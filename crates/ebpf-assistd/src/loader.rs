//! eBPF program loading using aya.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Context, Result};
use aya::programs::Program;
use aya::Bpf;
use capctl::caps::Cap;
use tracing::{debug, info, warn};

use ebpf_assist_common::{PolicyAction, ProgramId, ProgramInfo, ProgramType};

use crate::caps::with_caps;

/// Counter for generating unique program IDs.
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// A loaded eBPF program with its metadata.
pub struct LoadedProgram {
    pub info: ProgramInfo,
    pub bpf: Bpf,
}

/// Result of loading a program, may include a policy warning.
pub struct LoadResult {
    pub info: ProgramInfo,
    /// Warning message if policy action was Warn.
    pub warning: Option<String>,
}

/// Manages loaded eBPF programs.
pub struct Loader {
    programs: HashMap<ProgramId, LoadedProgram>,
}

impl Loader {
    pub fn new() -> Self {
        Self {
            programs: HashMap::new(),
        }
    }

    /// Load an eBPF program from a file.
    ///
    /// Checks the program type against the default policy:
    /// - Allow: Load proceeds normally
    /// - Warn: Load proceeds but returns a warning
    /// - Deny: Load fails with a policy violation error
    pub fn load(&mut self, path: &Path, program_name: Option<&str>) -> Result<LoadResult> {
        info!("Loading eBPF program from: {}", path.display());

        // Load with capabilities
        let bpf = with_caps(&[Cap::BPF, Cap::PERFMON], || {
            Bpf::load_file(path).context("Failed to load eBPF program")
        })?;

        // Find the program and detect type
        let (name, prog_type) = self.detect_program(&bpf, program_name)?;

        // Check policy for this program type
        let policy = prog_type.default_policy();
        let reason = prog_type.policy_reason();

        let warning = match policy {
            PolicyAction::Allow => {
                debug!("Policy: Allow {:?} - {}", prog_type, reason);
                None
            }
            PolicyAction::Warn => {
                warn!("Policy: Warn {:?} - {}", prog_type, reason);
                Some(format!(
                    "Warning: {:?} program loaded. {}",
                    prog_type, reason
                ))
            }
            PolicyAction::Deny => {
                anyhow::bail!(
                    "Policy violation: {:?} programs are not allowed. {}",
                    prog_type,
                    reason
                );
            }
        };

        let id = ProgramId(NEXT_ID.fetch_add(1, Ordering::SeqCst));

        let info = ProgramInfo {
            id,
            name: name.clone(),
            program_type: prog_type,
            path: path.to_path_buf(),
            attached: false,
            attach_point: None,
        };

        debug!("Loaded program: {:?}", info);

        self.programs.insert(
            id,
            LoadedProgram {
                info: info.clone(),
                bpf,
            },
        );

        Ok(LoadResult { info, warning })
    }

    /// Detect the program name and type from the loaded eBPF object.
    fn detect_program(&self, bpf: &Bpf, requested_name: Option<&str>) -> Result<(String, ProgramType)> {
        // Get all program names
        let program_names: Vec<_> = bpf.programs().map(|(name, _)| name.to_string()).collect();

        if program_names.is_empty() {
            anyhow::bail!("No programs found in eBPF object file");
        }

        // Select program by name or use the first one
        let name = if let Some(requested) = requested_name {
            if program_names.contains(&requested.to_string()) {
                requested.to_string()
            } else {
                anyhow::bail!(
                    "Program '{}' not found. Available: {:?}",
                    requested,
                    program_names
                );
            }
        } else if program_names.len() == 1 {
            program_names[0].clone()
        } else {
            anyhow::bail!(
                "Multiple programs found, please specify one: {:?}",
                program_names
            );
        };

        // Detect program type
        let prog = bpf.program(&name).unwrap();
        let prog_type = Self::detect_type(prog);

        Ok((name, prog_type))
    }

    /// Detect the program type from an aya Program.
    fn detect_type(prog: &Program) -> ProgramType {
        match prog {
            Program::KProbe(_) => ProgramType::KProbe,
            Program::UProbe(_) => ProgramType::UProbe,
            Program::TracePoint(_) => ProgramType::TracePoint,
            Program::RawTracePoint(_) => ProgramType::RawTracePoint,
            Program::Xdp(_) => ProgramType::Xdp,
            Program::SchedClassifier(_) => ProgramType::SchedClassifier,
            Program::CgroupSkb(_) => ProgramType::CgroupSkb,
            Program::SocketFilter(_) => ProgramType::SocketFilter,
            Program::PerfEvent(_) => ProgramType::PerfEvent,
            _ => ProgramType::Unknown,
        }
    }

    /// Attach a loaded program to its target.
    pub fn attach(&mut self, id: ProgramId, target: &str) -> Result<()> {
        // First check if the program exists and is not already attached
        {
            let loaded = self.programs.get(&id).context("Program not found")?;
            if loaded.info.attached {
                anyhow::bail!("Program already attached to {:?}", loaded.info.attach_point);
            }
            info!("Attaching program {} to {}", loaded.info.name, target);
        }

        // Get mutable reference and do the attach with elevated caps
        let loaded = self.programs.get_mut(&id).unwrap();
        let prog_name = loaded.info.name.clone();

        with_caps(&[Cap::BPF, Cap::PERFMON, Cap::NET_ADMIN], || {
            let prog = loaded
                .bpf
                .program_mut(&prog_name)
                .context("Program not found in eBPF object")?;

            match prog {
                Program::KProbe(kprobe) => {
                    kprobe.load()?;
                    kprobe.attach(target, 0)?;
                }
                Program::TracePoint(tp) => {
                    tp.load()?;
                    // target format: "category:name" e.g., "syscalls:sys_enter_openat"
                    let parts: Vec<&str> = target.split(':').collect();
                    if parts.len() != 2 {
                        anyhow::bail!("TracePoint target must be 'category:name'");
                    }
                    tp.attach(parts[0], parts[1])?;
                }
                Program::Xdp(xdp) => {
                    xdp.load()?;
                    // target is interface name
                    xdp.attach(target, aya::programs::XdpFlags::default())?;
                }
                _ => {
                    anyhow::bail!("Attach not implemented for this program type yet");
                }
            }
            Ok(())
        })?;

        loaded.info.attached = true;
        loaded.info.attach_point = Some(target.to_string());

        Ok(())
    }

    /// Detach a program from its target.
    pub fn detach(&mut self, id: ProgramId) -> Result<()> {
        let loaded = self
            .programs
            .get_mut(&id)
            .context("Program not found")?;

        if !loaded.info.attached {
            anyhow::bail!("Program is not attached");
        }

        info!("Detaching program {}", loaded.info.name);

        // Note: aya handles detach automatically when the program is dropped
        // For now, just mark as detached
        loaded.info.attached = false;
        loaded.info.attach_point = None;

        Ok(())
    }

    /// Unload a program.
    pub fn unload(&mut self, id: ProgramId) -> Result<()> {
        let loaded = self
            .programs
            .remove(&id)
            .context("Program not found")?;

        info!("Unloading program: {}", loaded.info.name);

        // Program is dropped here, which cleans up resources
        Ok(())
    }

    /// List all loaded programs.
    pub fn list(&self) -> Vec<ProgramInfo> {
        self.programs.values().map(|p| p.info.clone()).collect()
    }

    /// Get the number of loaded programs.
    pub fn count(&self) -> usize {
        self.programs.len()
    }
}

impl Default for Loader {
    fn default() -> Self {
        Self::new()
    }
}
