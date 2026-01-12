//! Common types shared between ebpf-assist daemon and CLI.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Unique identifier for a loaded eBPF program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProgramId(pub u32);

/// Types of eBPF programs we support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramType {
    KProbe,
    KRetProbe,
    UProbe,
    URetProbe,
    TracePoint,
    RawTracePoint,
    Xdp,
    SchedClassifier,
    CgroupSkb,
    SocketFilter,
    PerfEvent,
    Lsm,
    StructOps,
    Unknown,
}

/// Policy action for a program type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Allow without any notification.
    Allow,
    /// Allow but warn the user.
    Warn,
    /// Deny the operation.
    Deny,
}

impl ProgramType {
    /// Get the default policy action for this program type.
    ///
    /// Policy rationale:
    /// - Allow: Read-only observability (kprobe, tracepoint, perf_event, etc.)
    /// - Warn: Can modify network traffic (xdp, tc, socket_filter)
    /// - Deny: Security-critical (lsm, struct_ops, cgroup)
    pub fn default_policy(&self) -> PolicyAction {
        match self {
            // Low risk: Read-only observability - core use case
            ProgramType::KProbe
            | ProgramType::KRetProbe
            | ProgramType::UProbe
            | ProgramType::URetProbe
            | ProgramType::TracePoint
            | ProgramType::RawTracePoint
            | ProgramType::PerfEvent => PolicyAction::Allow,

            // Medium risk: Can modify network traffic but common for monitoring
            ProgramType::Xdp | ProgramType::SchedClassifier | ProgramType::SocketFilter => {
                PolicyAction::Warn
            }

            // Higher risk: Security-critical, can bypass protections
            ProgramType::Lsm | ProgramType::StructOps | ProgramType::CgroupSkb => {
                PolicyAction::Deny
            }

            // Unknown types are denied by default for safety
            ProgramType::Unknown => PolicyAction::Deny,
        }
    }

    /// Human-readable description of why this policy exists.
    pub fn policy_reason(&self) -> &'static str {
        match self {
            ProgramType::KProbe | ProgramType::KRetProbe => {
                "Kernel function tracing (read-only observability)"
            }
            ProgramType::UProbe | ProgramType::URetProbe => {
                "Userspace function tracing (read-only observability)"
            }
            ProgramType::TracePoint | ProgramType::RawTracePoint => {
                "Static kernel tracepoints (read-only observability)"
            }
            ProgramType::PerfEvent => "Performance monitoring (read-only observability)",
            ProgramType::Xdp => "XDP can drop or modify network packets",
            ProgramType::SchedClassifier => "TC classifier can modify network traffic",
            ProgramType::SocketFilter => "Socket filter can inspect/filter network data",
            ProgramType::CgroupSkb => "Cgroup programs can control container networking",
            ProgramType::Lsm => "LSM programs can bypass security policies",
            ProgramType::StructOps => "struct_ops can replace kernel code paths",
            ProgramType::Unknown => "Unknown program type - denied for safety",
        }
    }
}

/// Information about a loaded eBPF program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramInfo {
    pub id: ProgramId,
    pub name: String,
    pub program_type: ProgramType,
    pub path: PathBuf,
    pub attached: bool,
    pub attach_point: Option<String>,
}

/// Types of BPF maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MapType {
    Hash,
    Array,
    PerCpuHash,
    PerCpuArray,
    PerfEventArray,
    RingBuf,
    HashMap,
    LruHash,
    LpmTrie,
    Stack,
    Queue,
    Unknown,
}

/// Information about a BPF map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapInfo {
    /// Map name from the eBPF object.
    pub name: String,
    /// Type of the map.
    pub map_type: MapType,
    /// Size of keys in bytes.
    pub key_size: u32,
    /// Size of values in bytes.
    pub value_size: u32,
    /// Maximum number of entries.
    pub max_entries: u32,
}

/// A map entry (key-value pair).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapEntry {
    /// Key as hex string.
    pub key: String,
    /// Value as hex string.
    pub value: String,
    /// Optional: value interpreted as various types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_u64: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_str: Option<String>,
}

/// Request from CLI to daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Load an eBPF program from a file.
    Load {
        path: PathBuf,
        /// Optional: specific program name within the object file.
        program_name: Option<String>,
    },

    /// Unload a program by ID.
    Unload { id: ProgramId },

    /// Attach a loaded program to a hook.
    Attach {
        id: ProgramId,
        /// e.g., "sys_openat" for kprobe, "syscalls:sys_enter_openat" for tracepoint
        target: String,
    },

    /// Detach a program from its hook.
    Detach { id: ProgramId },

    /// List all loaded programs.
    List,

    /// Get daemon status.
    Status,

    /// Ping to check if daemon is alive.
    Ping,

    /// Request authorization (triggers GUI prompt if needed).
    Unlock,

    /// Clear authorization cache (require re-auth on next operation).
    Lock,

    /// Check authorization status without triggering prompt.
    AuthStatus,

    /// List maps for a loaded program.
    MapList { id: ProgramId },

    /// Read a map entry or dump all entries.
    MapRead {
        id: ProgramId,
        map_name: String,
        /// Optional key (hex string). If None, dump all entries.
        #[serde(skip_serializing_if = "Option::is_none")]
        key: Option<String>,
    },

    /// Write a map entry.
    MapWrite {
        id: ProgramId,
        map_name: String,
        /// Key as hex string.
        key: String,
        /// Value as hex string.
        value: String,
    },

    /// Delete a map entry.
    MapDelete {
        id: ProgramId,
        map_name: String,
        /// Key as hex string.
        key: String,
    },
}

/// Response from daemon to CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Program loaded successfully.
    Loaded {
        id: ProgramId,
        name: String,
        program_type: ProgramType,
        /// Warning message if policy action was Warn.
        #[serde(skip_serializing_if = "Option::is_none")]
        warning: Option<String>,
    },

    /// Program unloaded successfully.
    Unloaded { id: ProgramId },

    /// Program attached successfully.
    Attached { id: ProgramId, target: String },

    /// Program detached successfully.
    Detached { id: ProgramId },

    /// List of loaded programs.
    Programs { programs: Vec<ProgramInfo> },

    /// Daemon status.
    Status {
        version: String,
        uptime_secs: u64,
        programs_loaded: usize,
        capabilities: Vec<String>,
    },

    /// Pong response.
    Pong,

    /// Authorization successful.
    Unlocked,

    /// Authorization cleared.
    Locked,

    /// Authorization status.
    AuthStatusResult {
        /// Whether the user is currently authorized.
        authorized: bool,
        /// Seconds until authorization expires (0 if not authorized).
        expires_in_secs: u64,
    },

    /// Error response.
    Error { message: String, code: ErrorCode },

    /// List of maps for a program.
    Maps { maps: Vec<MapInfo> },

    /// Map entries read result.
    MapEntries {
        map_name: String,
        entries: Vec<MapEntry>,
    },

    /// Map write success.
    MapWritten { map_name: String, key: String },

    /// Map delete success.
    MapDeleted { map_name: String, key: String },
}

/// Error codes for structured error handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// File not found.
    NotFound,
    /// Permission denied (needs auth).
    PermissionDenied,
    /// Invalid eBPF program (verifier error).
    VerifierError,
    /// Program with this ID not found.
    ProgramNotFound,
    /// Already attached.
    AlreadyAttached,
    /// Not attached.
    NotAttached,
    /// Invalid request format.
    InvalidRequest,
    /// Internal daemon error.
    Internal,
    /// Capability error.
    CapabilityError,
    /// Authorization required (needs unlock).
    AuthRequired,
    /// Authorization denied by polkit.
    AuthDenied,
    /// Policy violation (program type not allowed).
    PolicyViolation,
    /// Map not found in program.
    MapNotFound,
    /// Invalid key format.
    InvalidKey,
    /// Invalid value format.
    InvalidValue,
}

/// Default socket path for the daemon.
pub const SOCKET_PATH: &str = "/run/ebpf-assist/ebpf-assist.sock";

/// Alternative socket path in user's runtime directory.
pub fn user_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("ebpf-assist.sock")
    } else {
        PathBuf::from("/tmp/ebpf-assist.sock")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== ProgramId Tests ====================

    #[test]
    fn test_program_id_equality() {
        let id1 = ProgramId(42);
        let id2 = ProgramId(42);
        let id3 = ProgramId(43);
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_program_id_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ProgramId(1));
        set.insert(ProgramId(2));
        set.insert(ProgramId(1)); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_program_id_serialization() {
        let id = ProgramId(123);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "123");
        let deserialized: ProgramId = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, id);
    }

    // ==================== ProgramType Tests ====================

    #[test]
    fn test_program_type_serialization() {
        let types = vec![
            (ProgramType::KProbe, "\"k_probe\""),
            (ProgramType::KRetProbe, "\"k_ret_probe\""),
            (ProgramType::UProbe, "\"u_probe\""),
            (ProgramType::URetProbe, "\"u_ret_probe\""),
            (ProgramType::TracePoint, "\"trace_point\""),
            (ProgramType::RawTracePoint, "\"raw_trace_point\""),
            (ProgramType::Xdp, "\"xdp\""),
            (ProgramType::SchedClassifier, "\"sched_classifier\""),
            (ProgramType::CgroupSkb, "\"cgroup_skb\""),
            (ProgramType::SocketFilter, "\"socket_filter\""),
            (ProgramType::PerfEvent, "\"perf_event\""),
            (ProgramType::Lsm, "\"lsm\""),
            (ProgramType::StructOps, "\"struct_ops\""),
            (ProgramType::Unknown, "\"unknown\""),
        ];
        for (prog_type, expected) in types {
            let json = serde_json::to_string(&prog_type).unwrap();
            assert_eq!(json, expected, "Failed for {:?}", prog_type);
            let deserialized: ProgramType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, prog_type);
        }
    }

    #[test]
    fn test_policy_defaults() {
        // Observability types should be allowed
        assert_eq!(ProgramType::KProbe.default_policy(), PolicyAction::Allow);
        assert_eq!(ProgramType::KRetProbe.default_policy(), PolicyAction::Allow);
        assert_eq!(ProgramType::UProbe.default_policy(), PolicyAction::Allow);
        assert_eq!(ProgramType::URetProbe.default_policy(), PolicyAction::Allow);
        assert_eq!(
            ProgramType::TracePoint.default_policy(),
            PolicyAction::Allow
        );
        assert_eq!(
            ProgramType::RawTracePoint.default_policy(),
            PolicyAction::Allow
        );
        assert_eq!(ProgramType::PerfEvent.default_policy(), PolicyAction::Allow);

        // Network types should warn
        assert_eq!(ProgramType::Xdp.default_policy(), PolicyAction::Warn);
        assert_eq!(
            ProgramType::SchedClassifier.default_policy(),
            PolicyAction::Warn
        );
        assert_eq!(
            ProgramType::SocketFilter.default_policy(),
            PolicyAction::Warn
        );

        // Security-critical types should be denied
        assert_eq!(ProgramType::Lsm.default_policy(), PolicyAction::Deny);
        assert_eq!(ProgramType::StructOps.default_policy(), PolicyAction::Deny);
        assert_eq!(ProgramType::CgroupSkb.default_policy(), PolicyAction::Deny);
        assert_eq!(ProgramType::Unknown.default_policy(), PolicyAction::Deny);
    }

    #[test]
    fn test_policy_reason_not_empty() {
        let types = [
            ProgramType::KProbe,
            ProgramType::KRetProbe,
            ProgramType::UProbe,
            ProgramType::URetProbe,
            ProgramType::TracePoint,
            ProgramType::RawTracePoint,
            ProgramType::Xdp,
            ProgramType::SchedClassifier,
            ProgramType::CgroupSkb,
            ProgramType::SocketFilter,
            ProgramType::PerfEvent,
            ProgramType::Lsm,
            ProgramType::StructOps,
            ProgramType::Unknown,
        ];
        for prog_type in types {
            let reason = prog_type.policy_reason();
            assert!(!reason.is_empty(), "Empty reason for {:?}", prog_type);
            assert!(
                reason.len() > 10,
                "Too short reason for {:?}: {}",
                prog_type,
                reason
            );
        }
    }

    // ==================== PolicyAction Tests ====================

    #[test]
    fn test_policy_action_serialization() {
        assert_eq!(
            serde_json::to_string(&PolicyAction::Allow).unwrap(),
            "\"allow\""
        );
        assert_eq!(
            serde_json::to_string(&PolicyAction::Warn).unwrap(),
            "\"warn\""
        );
        assert_eq!(
            serde_json::to_string(&PolicyAction::Deny).unwrap(),
            "\"deny\""
        );
    }

    // ==================== MapType Tests ====================

    #[test]
    fn test_map_type_serialization() {
        let types = vec![
            (MapType::Hash, "\"hash\""),
            (MapType::Array, "\"array\""),
            (MapType::PerCpuHash, "\"per_cpu_hash\""),
            (MapType::PerCpuArray, "\"per_cpu_array\""),
            (MapType::PerfEventArray, "\"perf_event_array\""),
            (MapType::RingBuf, "\"ring_buf\""),
            (MapType::HashMap, "\"hash_map\""),
            (MapType::LruHash, "\"lru_hash\""),
            (MapType::LpmTrie, "\"lpm_trie\""),
            (MapType::Stack, "\"stack\""),
            (MapType::Queue, "\"queue\""),
            (MapType::Unknown, "\"unknown\""),
        ];
        for (map_type, expected) in types {
            let json = serde_json::to_string(&map_type).unwrap();
            assert_eq!(json, expected, "Failed for {:?}", map_type);
            let deserialized: MapType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, map_type);
        }
    }

    // ==================== MapInfo Tests ====================

    #[test]
    fn test_map_info_serialization() {
        let info = MapInfo {
            name: "my_map".to_string(),
            map_type: MapType::Hash,
            key_size: 4,
            value_size: 8,
            max_entries: 1024,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"name\":\"my_map\""));
        assert!(json.contains("\"map_type\":\"hash\""));
        assert!(json.contains("\"key_size\":4"));
        assert!(json.contains("\"value_size\":8"));
        assert!(json.contains("\"max_entries\":1024"));

        let deserialized: MapInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "my_map");
        assert_eq!(deserialized.map_type, MapType::Hash);
    }

    // ==================== MapEntry Tests ====================

    #[test]
    fn test_map_entry_minimal() {
        let entry = MapEntry {
            key: "0x01020304".to_string(),
            value: "0xdeadbeef".to_string(),
            value_u64: None,
            value_str: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"key\":\"0x01020304\""));
        assert!(json.contains("\"value\":\"0xdeadbeef\""));
        // Optional fields should be omitted when None
        assert!(!json.contains("value_u64"));
        assert!(!json.contains("value_str"));
    }

    #[test]
    fn test_map_entry_with_optionals() {
        let entry = MapEntry {
            key: "0x01".to_string(),
            value: "0x2a".to_string(),
            value_u64: Some(42),
            value_str: Some("*".to_string()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"value_u64\":42"));
        assert!(json.contains("\"value_str\":\"*\""));
    }

    // ==================== ProgramInfo Tests ====================

    #[test]
    fn test_program_info_serialization() {
        let info = ProgramInfo {
            id: ProgramId(42),
            name: "my_kprobe".to_string(),
            program_type: ProgramType::KProbe,
            path: PathBuf::from("/tmp/probe.o"),
            attached: true,
            attach_point: Some("sys_openat".to_string()),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"id\":42"));
        assert!(json.contains("\"name\":\"my_kprobe\""));
        assert!(json.contains("\"program_type\":\"k_probe\""));
        assert!(json.contains("\"attached\":true"));
        assert!(json.contains("\"attach_point\":\"sys_openat\""));

        let deserialized: ProgramInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, ProgramId(42));
        assert_eq!(deserialized.attached, true);
    }

    #[test]
    fn test_program_info_not_attached() {
        let info = ProgramInfo {
            id: ProgramId(1),
            name: "test".to_string(),
            program_type: ProgramType::TracePoint,
            path: PathBuf::from("/test.o"),
            attached: false,
            attach_point: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"attached\":false"));
    }

    // ==================== Request Tests ====================

    #[test]
    fn test_request_serialization() {
        let req = Request::Load {
            path: PathBuf::from("/tmp/probe.o"),
            program_name: Some("my_probe".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"load\""));
        assert!(json.contains("/tmp/probe.o"));
    }

    #[test]
    fn test_request_load_no_name() {
        let req = Request::Load {
            path: PathBuf::from("/tmp/probe.o"),
            program_name: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"load\""));
    }

    #[test]
    fn test_request_unload() {
        let req = Request::Unload { id: ProgramId(5) };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"unload\""));
        assert!(json.contains("\"id\":5"));
    }

    #[test]
    fn test_request_attach() {
        let req = Request::Attach {
            id: ProgramId(1),
            target: "sys_openat".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"attach\""));
        assert!(json.contains("\"target\":\"sys_openat\""));
    }

    #[test]
    fn test_request_detach() {
        let req = Request::Detach { id: ProgramId(1) };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"detach\""));
    }

    #[test]
    fn test_request_list() {
        let req = Request::List;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"list\""));
    }

    #[test]
    fn test_request_status() {
        let req = Request::Status;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"status\""));
    }

    #[test]
    fn test_request_ping() {
        let req = Request::Ping;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"ping\""));
    }

    #[test]
    fn test_request_unlock_lock() {
        let unlock = Request::Unlock;
        let lock = Request::Lock;
        assert!(serde_json::to_string(&unlock)
            .unwrap()
            .contains("\"type\":\"unlock\""));
        assert!(serde_json::to_string(&lock)
            .unwrap()
            .contains("\"type\":\"lock\""));
    }

    #[test]
    fn test_request_auth_status() {
        let req = Request::AuthStatus;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"auth_status\""));
    }

    #[test]
    fn test_request_map_list() {
        let req = Request::MapList { id: ProgramId(5) };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"map_list\""));
        assert!(json.contains("\"id\":5"));
    }

    #[test]
    fn test_request_map_read() {
        let req = Request::MapRead {
            id: ProgramId(1),
            map_name: "counters".to_string(),
            key: Some("0x01020304".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"map_read\""));
        assert!(json.contains("\"map_name\":\"counters\""));
        assert!(json.contains("\"key\":\"0x01020304\""));
    }

    #[test]
    fn test_request_map_read_no_key() {
        let req = Request::MapRead {
            id: ProgramId(1),
            map_name: "counters".to_string(),
            key: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        // key should be omitted when None
        assert!(!json.contains("\"key\""));
    }

    #[test]
    fn test_request_map_write() {
        let req = Request::MapWrite {
            id: ProgramId(1),
            map_name: "config".to_string(),
            key: "0x00".to_string(),
            value: "0xff".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"map_write\""));
        assert!(json.contains("\"key\":\"0x00\""));
        assert!(json.contains("\"value\":\"0xff\""));
    }

    #[test]
    fn test_request_map_delete() {
        let req = Request::MapDelete {
            id: ProgramId(1),
            map_name: "cache".to_string(),
            key: "0xdead".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"map_delete\""));
    }

    // ==================== Response Tests ====================

    #[test]
    fn test_response_serialization() {
        let resp = Response::Loaded {
            id: ProgramId(1),
            name: "test".to_string(),
            program_type: ProgramType::KProbe,
            warning: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"loaded\""));
        // warning should be omitted when None
        assert!(!json.contains("warning"));
    }

    #[test]
    fn test_response_with_warning() {
        let resp = Response::Loaded {
            id: ProgramId(1),
            name: "test".to_string(),
            program_type: ProgramType::Xdp,
            warning: Some("XDP can modify packets".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"warning\":\"XDP can modify packets\""));
    }

    #[test]
    fn test_response_unloaded() {
        let resp = Response::Unloaded { id: ProgramId(42) };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"unloaded\""));
        assert!(json.contains("\"id\":42"));
    }

    #[test]
    fn test_response_attached() {
        let resp = Response::Attached {
            id: ProgramId(1),
            target: "sys_openat".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"attached\""));
        assert!(json.contains("\"target\":\"sys_openat\""));
    }

    #[test]
    fn test_response_detached() {
        let resp = Response::Detached { id: ProgramId(1) };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"detached\""));
    }

    #[test]
    fn test_response_programs() {
        let resp = Response::Programs {
            programs: vec![
                ProgramInfo {
                    id: ProgramId(1),
                    name: "probe1".to_string(),
                    program_type: ProgramType::KProbe,
                    path: PathBuf::from("/a.o"),
                    attached: true,
                    attach_point: Some("sys_open".to_string()),
                },
                ProgramInfo {
                    id: ProgramId(2),
                    name: "probe2".to_string(),
                    program_type: ProgramType::TracePoint,
                    path: PathBuf::from("/b.o"),
                    attached: false,
                    attach_point: None,
                },
            ],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"programs\""));
        assert!(json.contains("probe1"));
        assert!(json.contains("probe2"));
    }

    #[test]
    fn test_response_status() {
        let resp = Response::Status {
            version: "0.1.0".to_string(),
            uptime_secs: 3600,
            programs_loaded: 5,
            capabilities: vec!["CAP_BPF".to_string(), "CAP_SYS_ADMIN".to_string()],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"status\""));
        assert!(json.contains("\"version\":\"0.1.0\""));
        assert!(json.contains("\"uptime_secs\":3600"));
        assert!(json.contains("\"programs_loaded\":5"));
        assert!(json.contains("CAP_BPF"));
    }

    #[test]
    fn test_response_pong() {
        let resp = Response::Pong;
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"pong\""));
    }

    #[test]
    fn test_response_auth() {
        let unlocked = Response::Unlocked;
        let locked = Response::Locked;
        assert!(serde_json::to_string(&unlocked)
            .unwrap()
            .contains("\"type\":\"unlocked\""));
        assert!(serde_json::to_string(&locked)
            .unwrap()
            .contains("\"type\":\"locked\""));
    }

    #[test]
    fn test_response_auth_status_result() {
        let resp = Response::AuthStatusResult {
            authorized: true,
            expires_in_secs: 300,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"auth_status_result\""));
        assert!(json.contains("\"authorized\":true"));
        assert!(json.contains("\"expires_in_secs\":300"));
    }

    #[test]
    fn test_response_error() {
        let resp = Response::Error {
            message: "Something went wrong".to_string(),
            code: ErrorCode::Internal,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"error\""));
        assert!(json.contains("\"message\":\"Something went wrong\""));
        assert!(json.contains("\"code\":\"internal\""));
    }

    #[test]
    fn test_response_maps() {
        let resp = Response::Maps {
            maps: vec![MapInfo {
                name: "events".to_string(),
                map_type: MapType::PerfEventArray,
                key_size: 4,
                value_size: 4,
                max_entries: 256,
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"maps\""));
        assert!(json.contains("\"name\":\"events\""));
    }

    #[test]
    fn test_response_map_entries() {
        let resp = Response::MapEntries {
            map_name: "counters".to_string(),
            entries: vec![MapEntry {
                key: "0x00".to_string(),
                value: "0x2a".to_string(),
                value_u64: Some(42),
                value_str: None,
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"map_entries\""));
        assert!(json.contains("\"map_name\":\"counters\""));
    }

    #[test]
    fn test_response_map_written() {
        let resp = Response::MapWritten {
            map_name: "config".to_string(),
            key: "0x01".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"map_written\""));
    }

    #[test]
    fn test_response_map_deleted() {
        let resp = Response::MapDeleted {
            map_name: "cache".to_string(),
            key: "0xff".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"map_deleted\""));
    }

    // ==================== ErrorCode Tests ====================

    #[test]
    fn test_error_code_serialization() {
        let codes = vec![
            (ErrorCode::NotFound, "\"not_found\""),
            (ErrorCode::PermissionDenied, "\"permission_denied\""),
            (ErrorCode::VerifierError, "\"verifier_error\""),
            (ErrorCode::ProgramNotFound, "\"program_not_found\""),
            (ErrorCode::AlreadyAttached, "\"already_attached\""),
            (ErrorCode::NotAttached, "\"not_attached\""),
            (ErrorCode::InvalidRequest, "\"invalid_request\""),
            (ErrorCode::Internal, "\"internal\""),
            (ErrorCode::CapabilityError, "\"capability_error\""),
            (ErrorCode::AuthRequired, "\"auth_required\""),
            (ErrorCode::AuthDenied, "\"auth_denied\""),
            (ErrorCode::PolicyViolation, "\"policy_violation\""),
            (ErrorCode::MapNotFound, "\"map_not_found\""),
            (ErrorCode::InvalidKey, "\"invalid_key\""),
            (ErrorCode::InvalidValue, "\"invalid_value\""),
        ];
        for (code, expected) in codes {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, expected, "Failed for {:?}", code);
            let deserialized: ErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, code);
        }
    }

    // ==================== Socket Path Tests ====================

    #[test]
    fn test_socket_path_constant() {
        assert_eq!(SOCKET_PATH, "/run/ebpf-assist/ebpf-assist.sock");
    }

    #[test]
    fn test_user_socket_path() {
        let path = user_socket_path();
        // Should end with ebpf-assist.sock regardless of XDG_RUNTIME_DIR
        assert!(path.to_string_lossy().ends_with("ebpf-assist.sock"));
    }

    #[test]
    fn test_user_socket_path_with_xdg() {
        // Save and modify env var
        let original = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");

        let path = user_socket_path();
        assert_eq!(path, PathBuf::from("/run/user/1000/ebpf-assist.sock"));

        // Restore
        if let Some(val) = original {
            std::env::set_var("XDG_RUNTIME_DIR", val);
        }
    }

    // ==================== Deserialization Tests ====================

    #[test]
    fn test_request_round_trip() {
        let requests = vec![
            Request::Load {
                path: PathBuf::from("/test.o"),
                program_name: Some("test".to_string()),
            },
            Request::Unload { id: ProgramId(1) },
            Request::Attach {
                id: ProgramId(1),
                target: "test".to_string(),
            },
            Request::Detach { id: ProgramId(1) },
            Request::List,
            Request::Status,
            Request::Ping,
            Request::Unlock,
            Request::Lock,
            Request::AuthStatus,
            Request::MapList { id: ProgramId(1) },
            Request::MapRead {
                id: ProgramId(1),
                map_name: "m".to_string(),
                key: None,
            },
            Request::MapWrite {
                id: ProgramId(1),
                map_name: "m".to_string(),
                key: "k".to_string(),
                value: "v".to_string(),
            },
            Request::MapDelete {
                id: ProgramId(1),
                map_name: "m".to_string(),
                key: "k".to_string(),
            },
        ];
        for req in requests {
            let json = serde_json::to_string(&req).unwrap();
            let deserialized: Request = serde_json::from_str(&json).unwrap();
            // Re-serialize and compare JSON (since Request doesn't impl PartialEq)
            let json2 = serde_json::to_string(&deserialized).unwrap();
            assert_eq!(json, json2, "Round-trip failed for request");
        }
    }

    #[test]
    fn test_response_round_trip() {
        let responses = vec![
            Response::Loaded {
                id: ProgramId(1),
                name: "t".to_string(),
                program_type: ProgramType::KProbe,
                warning: None,
            },
            Response::Unloaded { id: ProgramId(1) },
            Response::Attached {
                id: ProgramId(1),
                target: "t".to_string(),
            },
            Response::Detached { id: ProgramId(1) },
            Response::Programs { programs: vec![] },
            Response::Status {
                version: "0.1.0".to_string(),
                uptime_secs: 0,
                programs_loaded: 0,
                capabilities: vec![],
            },
            Response::Pong,
            Response::Unlocked,
            Response::Locked,
            Response::AuthStatusResult {
                authorized: false,
                expires_in_secs: 0,
            },
            Response::Error {
                message: "err".to_string(),
                code: ErrorCode::Internal,
            },
            Response::Maps { maps: vec![] },
            Response::MapEntries {
                map_name: "m".to_string(),
                entries: vec![],
            },
            Response::MapWritten {
                map_name: "m".to_string(),
                key: "k".to_string(),
            },
            Response::MapDeleted {
                map_name: "m".to_string(),
                key: "k".to_string(),
            },
        ];
        for resp in responses {
            let json = serde_json::to_string(&resp).unwrap();
            let deserialized: Response = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&deserialized).unwrap();
            assert_eq!(json, json2, "Round-trip failed for response");
        }
    }
}
