//! eBPF program loading using aya.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Context, Result};
use aya::programs::Program;
use aya::Bpf;
use capctl::caps::Cap;
use tracing::{debug, info, warn};

use ebpf_assist_common::{
    MapEntry, MapInfo, MapType, PolicyAction, ProgramId, ProgramInfo, ProgramType,
};

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
    fn detect_program(
        &self,
        bpf: &Bpf,
        requested_name: Option<&str>,
    ) -> Result<(String, ProgramType)> {
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
        let loaded = self.programs.get_mut(&id).context("Program not found")?;

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
        let loaded = self.programs.remove(&id).context("Program not found")?;

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

    /// List maps for a loaded program.
    pub fn list_maps(&self, id: ProgramId) -> Result<Vec<MapInfo>> {
        let loaded = self.programs.get(&id).context("Program not found")?;

        let mut maps = Vec::new();
        for (name, map) in loaded.bpf.maps() {
            let (key_size, value_size, max_entries) = Self::get_map_sizes(map);
            let map_info = MapInfo {
                name: name.to_string(),
                map_type: Self::detect_map_type(map),
                key_size,
                value_size,
                max_entries,
            };
            maps.push(map_info);
        }

        Ok(maps)
    }

    /// Get map size information from the Map enum.
    fn get_map_sizes(map: &aya::maps::Map) -> (u32, u32, u32) {
        use aya::maps::Map;
        // Extract MapData from the Map enum to get info
        let map_data = match map {
            Map::Array(m) => m,
            Map::HashMap(m) => m,
            Map::PerCpuArray(m) => m,
            Map::PerCpuHashMap(m) => m,
            Map::PerfEventArray(m) => m,
            Map::RingBuf(m) => m,
            Map::LruHashMap(m) => m,
            Map::Stack(m) => m,
            Map::Queue(m) => m,
            Map::BloomFilter(m) => m,
            Map::LpmTrie(m) => m,
            Map::PerCpuLruHashMap(m) => m,
            Map::ProgramArray(m) => m,
            Map::SockHash(m) => m,
            Map::SockMap(m) => m,
            Map::StackTraceMap(m) => m,
            Map::CpuMap(m) => m,
            Map::DevMap(m) => m,
            Map::DevMapHash(m) => m,
            Map::XskMap(m) => m,
            Map::Unsupported(m) => m,
        };

        // Get info from MapData
        if let Ok(info) = map_data.info() {
            (info.key_size(), info.value_size(), info.max_entries())
        } else {
            (0, 0, 0)
        }
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

    /// Read map entries.
    pub fn read_map(
        &self,
        id: ProgramId,
        map_name: &str,
        key: Option<&str>,
    ) -> Result<Vec<MapEntry>> {
        let loaded = self.programs.get(&id).context("Program not found")?;

        let map = loaded.bpf.map(map_name).context("Map not found")?;

        let map_type = Self::detect_map_type(map);
        let (key_size, value_size, _max_entries) = Self::get_map_sizes(map);

        match map_type {
            MapType::Array => self.read_array_map(map, key, value_size as usize),
            MapType::Hash => self.read_hash_map(map, key, key_size as usize, value_size as usize),
            _ => anyhow::bail!("Map type {:?} not yet supported for reading", map_type),
        }
    }

    fn read_array_map(
        &self,
        map: &aya::maps::Map,
        key: Option<&str>,
        _value_size: usize,
    ) -> Result<Vec<MapEntry>> {
        use aya::maps::Array;

        // Try to interpret as Array<MapData, u64>
        let array: Array<_, u64> = Array::try_from(map)?;
        let mut entries = Vec::new();

        if let Some(key_str) = key {
            // Read specific index
            let idx: u32 = key_str
                .parse()
                .context("Key must be numeric index for array maps")?;
            let value = array.get(&idx, 0)?;
            entries.push(MapEntry {
                key: idx.to_string(),
                value: format!("{:016x}", value),
                value_u64: Some(value),
                value_str: None,
            });
        } else {
            // Dump all entries (limit to 100)
            let max = std::cmp::min(array.len(), 100);
            for idx in 0..max {
                if let Ok(value) = array.get(&idx, 0) {
                    entries.push(MapEntry {
                        key: idx.to_string(),
                        value: format!("{:016x}", value),
                        value_u64: Some(value),
                        value_str: None,
                    });
                }
            }
        }

        Ok(entries)
    }

    fn read_hash_map(
        &self,
        map: &aya::maps::Map,
        key: Option<&str>,
        _key_size: usize,
        _value_size: usize,
    ) -> Result<Vec<MapEntry>> {
        use aya::maps::HashMap;

        // For simplicity, assume u32 keys and u64 values (common case)
        // A more complete implementation would handle arbitrary sizes
        let hash: HashMap<_, u32, u64> = HashMap::try_from(map)?;
        let mut entries = Vec::new();

        if let Some(key_str) = key {
            // Read specific key
            let k: u32 = Self::parse_key(key_str)?;
            let value = hash.get(&k, 0)?;
            entries.push(MapEntry {
                key: format!("{:08x}", k),
                value: format!("{:016x}", value),
                value_u64: Some(value),
                value_str: None,
            });
        } else {
            // Dump all entries (limit to 100)
            let mut count = 0;
            for item in hash.iter() {
                if count >= 100 {
                    break;
                }
                if let Ok((k, v)) = item {
                    entries.push(MapEntry {
                        key: format!("{:08x}", k),
                        value: format!("{:016x}", v),
                        value_u64: Some(v),
                        value_str: None,
                    });
                    count += 1;
                }
            }
        }

        Ok(entries)
    }

    /// Parse a key string (hex or decimal).
    fn parse_key(key_str: &str) -> Result<u32> {
        if key_str.starts_with("0x") || key_str.starts_with("0X") {
            u32::from_str_radix(&key_str[2..], 16).context("Invalid hex key")
        } else {
            key_str.parse().context("Invalid key")
        }
    }

    /// Write to a map.
    pub fn write_map(
        &mut self,
        id: ProgramId,
        map_name: &str,
        key: &str,
        value: &str,
    ) -> Result<()> {
        let loaded = self.programs.get_mut(&id).context("Program not found")?;

        let map = loaded.bpf.map_mut(map_name).context("Map not found")?;
        let map_type = Self::detect_map_type(map);

        match map_type {
            MapType::Array => {
                use aya::maps::Array;
                let mut array: Array<_, u64> = Array::try_from(map)?;
                let idx: u32 = key
                    .parse()
                    .context("Key must be numeric index for array maps")?;
                let val: u64 = Self::parse_value(value)?;
                array.set(idx, val, 0)?;
                info!("Wrote to array map {}: [{}] = {}", map_name, idx, val);
            }
            MapType::Hash => {
                use aya::maps::HashMap;
                let mut hash: HashMap<_, u32, u64> = HashMap::try_from(map)?;
                let k: u32 = Self::parse_key(key)?;
                let v: u64 = Self::parse_value(value)?;
                hash.insert(k, v, 0)?;
                info!("Wrote to hash map {}: {} = {}", map_name, k, v);
            }
            _ => anyhow::bail!("Map type {:?} not yet supported for writing", map_type),
        }

        Ok(())
    }

    /// Parse a value string (hex or decimal).
    fn parse_value(value_str: &str) -> Result<u64> {
        if value_str.starts_with("0x") || value_str.starts_with("0X") {
            u64::from_str_radix(&value_str[2..], 16).context("Invalid hex value")
        } else {
            value_str.parse().context("Invalid value")
        }
    }

    /// Delete a map entry.
    pub fn delete_map_entry(&mut self, id: ProgramId, map_name: &str, key: &str) -> Result<()> {
        let loaded = self.programs.get_mut(&id).context("Program not found")?;

        let map = loaded.bpf.map_mut(map_name).context("Map not found")?;
        let map_type = Self::detect_map_type(map);

        match map_type {
            MapType::Hash => {
                use aya::maps::HashMap;
                let mut hash: HashMap<_, u32, u64> = HashMap::try_from(map)?;
                let k: u32 = Self::parse_key(key)?;
                hash.remove(&k)?;
                info!("Deleted from hash map {}: key {}", map_name, k);
            }
            MapType::Array => {
                anyhow::bail!("Cannot delete entries from array maps (use write with 0)");
            }
            _ => anyhow::bail!("Map type {:?} not yet supported for deletion", map_type),
        }

        Ok(())
    }
}

impl Default for Loader {
    fn default() -> Self {
        Self::new()
    }
}
