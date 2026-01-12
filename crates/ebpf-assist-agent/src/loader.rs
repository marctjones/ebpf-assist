//! eBPF program loader for the guest agent.

use aya::programs::Program;
use aya::Bpf as Ebpf;
use ebpf_assist_common::{MapInfo, MapType, ProgramId, ProgramInfo, ProgramType};
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;
use tracing::info;

/// Errors from the loader.
#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("Failed to load eBPF object: {0}")]
    Load(String),

    #[error("Program not found: {0}")]
    ProgramNotFound(String),

    #[error("Failed to attach program: {0}")]
    Attach(String),

    #[error("Unsupported program type: {0}")]
    UnsupportedType(String),

    #[error("Map not found: {0}")]
    MapNotFound(String),

    #[error("Map operation failed: {0}")]
    MapError(String),
}

/// A loaded eBPF program.
pub struct LoadedProgram {
    /// Program ID.
    pub id: ProgramId,
    /// Program info.
    pub info: ProgramInfo,
    /// The eBPF object containing the program.
    pub ebpf: Ebpf,
    /// Whether the program is attached.
    pub attached: bool,
    /// Attach target (if attached).
    pub attach_point: Option<String>,
}

/// Program loader managing all loaded programs.
pub struct ProgramLoader {
    /// Loaded programs by ID.
    programs: HashMap<ProgramId, LoadedProgram>,
    /// Next program ID.
    next_id: u32,
}

impl ProgramLoader {
    /// Create a new loader.
    pub fn new() -> Self {
        Self {
            programs: HashMap::new(),
            next_id: 1,
        }
    }

    /// Load a program from bytes.
    pub fn load(&mut self, bytes: &[u8], name: String) -> Result<(ProgramId, ProgramInfo), LoaderError> {
        // Load the eBPF object
        let ebpf = Ebpf::load(bytes).map_err(|e| LoaderError::Load(e.to_string()))?;

        // Find the program and determine its type
        let (_prog_name, prog_type) = self.detect_program(&ebpf)?;

        let id = ProgramId(self.next_id);
        self.next_id += 1;

        let info = ProgramInfo {
            id,
            name: name.clone(),
            program_type: prog_type,
            path: PathBuf::from("<memory>"),
            attached: false,
            attach_point: None,
        };

        info!(
            id = id.0,
            name = %name,
            prog_type = ?prog_type,
            "Loaded program"
        );

        let loaded = LoadedProgram {
            id,
            info: info.clone(),
            ebpf,
            attached: false,
            attach_point: None,
        };

        self.programs.insert(id, loaded);

        Ok((id, info))
    }

    /// Detect the program type from the eBPF object.
    fn detect_program(&self, ebpf: &Ebpf) -> Result<(String, ProgramType), LoaderError> {
        // Try to find a program and determine its type
        for (name, prog) in ebpf.programs() {
            let prog_type = match prog {
                Program::KProbe(_) => ProgramType::KProbe,
                Program::UProbe(_) => ProgramType::UProbe,
                Program::TracePoint(_) => ProgramType::TracePoint,
                Program::Xdp(_) => ProgramType::Xdp,
                Program::SchedClassifier(_) => ProgramType::SchedClassifier,
                Program::CgroupSkb(_) => ProgramType::CgroupSkb,
                Program::SocketFilter(_) => ProgramType::SocketFilter,
                Program::RawTracePoint(_) => ProgramType::RawTracePoint,
                Program::Lsm(_) => ProgramType::Lsm,
                Program::PerfEvent(_) => ProgramType::PerfEvent,
                _ => continue, // Skip unknown types
            };
            return Ok((name.to_string(), prog_type));
        }

        Err(LoaderError::ProgramNotFound(
            "No supported program found in object".to_string(),
        ))
    }

    /// Attach a program.
    pub fn attach(&mut self, id: ProgramId, target: &str) -> Result<(), LoaderError> {
        let loaded = self
            .programs
            .get_mut(&id)
            .ok_or_else(|| LoaderError::ProgramNotFound(format!("ID {}", id.0)))?;

        if loaded.attached {
            return Ok(()); // Already attached
        }

        // Find and attach the program
        for (_name, prog) in loaded.ebpf.programs_mut() {
            match prog {
                Program::KProbe(kprobe) => {
                    kprobe.load().map_err(|e| LoaderError::Attach(e.to_string()))?;
                    kprobe
                        .attach(target, 0)
                        .map_err(|e| LoaderError::Attach(e.to_string()))?;
                    info!(id = id.0, target = target, "Attached kprobe");
                    loaded.attached = true;
                    loaded.attach_point = Some(target.to_string());
                    loaded.info.attached = true;
                    loaded.info.attach_point = Some(target.to_string());
                    return Ok(());
                }
                Program::UProbe(uprobe) => {
                    uprobe.load().map_err(|e| LoaderError::Attach(e.to_string()))?;
                    // Parse target as "path:symbol" or just "path:offset"
                    let parts: Vec<&str> = target.splitn(2, ':').collect();
                    if parts.len() != 2 {
                        return Err(LoaderError::Attach(
                            "UProbe target must be 'path:symbol' or 'path:offset'".to_string(),
                        ));
                    }
                    uprobe
                        .attach(Some(parts[1]), 0, parts[0], None)
                        .map_err(|e| LoaderError::Attach(e.to_string()))?;
                    info!(id = id.0, target = target, "Attached uprobe");
                    loaded.attached = true;
                    loaded.attach_point = Some(target.to_string());
                    loaded.info.attached = true;
                    loaded.info.attach_point = Some(target.to_string());
                    return Ok(());
                }
                Program::TracePoint(tp) => {
                    tp.load().map_err(|e| LoaderError::Attach(e.to_string()))?;
                    // Parse target as "category/name"
                    let parts: Vec<&str> = target.splitn(2, '/').collect();
                    if parts.len() != 2 {
                        return Err(LoaderError::Attach(
                            "Tracepoint target must be 'category/name'".to_string(),
                        ));
                    }
                    tp.attach(parts[0], parts[1])
                        .map_err(|e| LoaderError::Attach(e.to_string()))?;
                    info!(id = id.0, target = target, "Attached tracepoint");
                    loaded.attached = true;
                    loaded.attach_point = Some(target.to_string());
                    loaded.info.attached = true;
                    loaded.info.attach_point = Some(target.to_string());
                    return Ok(());
                }
                _ => continue,
            }
        }

        Err(LoaderError::Attach("No attachable program found".to_string()))
    }

    /// Detach a program.
    pub fn detach(&mut self, id: ProgramId) -> Result<(), LoaderError> {
        let loaded = self
            .programs
            .get_mut(&id)
            .ok_or_else(|| LoaderError::ProgramNotFound(format!("ID {}", id.0)))?;

        // Programs are automatically detached when dropped, so we just mark as detached
        // The actual detach happens when we reload or remove the program
        loaded.attached = false;
        loaded.attach_point = None;
        loaded.info.attached = false;
        loaded.info.attach_point = None;

        info!(id = id.0, "Marked program as detached");
        Ok(())
    }

    /// Unload a program.
    pub fn unload(&mut self, id: ProgramId) -> Result<(), LoaderError> {
        self.programs
            .remove(&id)
            .ok_or_else(|| LoaderError::ProgramNotFound(format!("ID {}", id.0)))?;

        info!(id = id.0, "Unloaded program");
        Ok(())
    }

    /// Unload all programs.
    pub fn unload_all(&mut self) -> usize {
        let count = self.programs.len();
        self.programs.clear();
        info!(count = count, "Unloaded all programs");
        count
    }

    /// List all programs.
    pub fn list(&self) -> Vec<ProgramInfo> {
        self.programs.values().map(|p| p.info.clone()).collect()
    }

    /// Get program count.
    pub fn count(&self) -> usize {
        self.programs.len()
    }

    /// List maps for a program.
    pub fn list_maps(&self, id: ProgramId) -> Result<Vec<MapInfo>, LoaderError> {
        let loaded = self
            .programs
            .get(&id)
            .ok_or_else(|| LoaderError::ProgramNotFound(format!("ID {}", id.0)))?;

        let mut maps = Vec::new();
        for (name, map) in loaded.ebpf.maps() {
            // Detect map type from the aya Map enum
            let map_type = Self::detect_map_type(map);
            let (key_size, value_size, max_entries) = Self::get_map_sizes(map);

            maps.push(MapInfo {
                name: name.to_string(),
                map_type,
                key_size,
                value_size,
                max_entries,
            });
        }

        Ok(maps)
    }

    /// Detect map type from aya Map.
    fn detect_map_type(map: &aya::maps::Map) -> MapType {
        use aya::maps::Map;
        match map {
            Map::HashMap(_) => MapType::Hash,
            Map::Array(_) => MapType::Array,
            Map::PerCpuHashMap(_) => MapType::PerCpuHash,
            Map::PerCpuArray(_) => MapType::PerCpuArray,
            Map::PerfEventArray(_) => MapType::PerfEventArray,
            Map::RingBuf(_) => MapType::RingBuf,
            Map::LruHashMap(_) => MapType::LruHash,
            Map::Stack(_) => MapType::Stack,
            Map::Queue(_) => MapType::Queue,
            _ => MapType::Unknown,
        }
    }

    /// Get map sizes from aya Map.
    fn get_map_sizes(map: &aya::maps::Map) -> (u32, u32, u32) {
        use aya::maps::Map;

        // Extract MapData from the Map enum - use macro-like pattern to handle all variants
        macro_rules! extract_map_data {
            ($map:expr, $($variant:ident),+ $(,)?) => {
                match $map {
                    $(Map::$variant(m) => Some(m),)+
                    _ => None,
                }
            };
        }

        let map_data = extract_map_data!(
            map,
            HashMap,
            LpmTrie,
            Array,
            BloomFilter,
            PerCpuArray,
            PerCpuHashMap,
            PerCpuLruHashMap,
            PerfEventArray,
            RingBuf,
            SockHash,
            SockMap,
            ProgramArray,
            Stack,
            Queue,
            LruHashMap,
            StackTraceMap,
            CpuMap,
            DevMap,
            DevMapHash,
            XskMap,
            Unsupported
        );

        // Get info from MapData
        if let Some(map_data) = map_data {
            if let Ok(info) = map_data.info() {
                return (info.key_size(), info.value_size(), info.max_entries());
            }
        }
        (0, 0, 0)
    }
}

impl Default for ProgramLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loader_new() {
        let loader = ProgramLoader::new();
        assert_eq!(loader.count(), 0);
        assert!(loader.list().is_empty());
    }
}
