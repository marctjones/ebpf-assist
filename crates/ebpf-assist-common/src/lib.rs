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
            ProgramType::Xdp
            | ProgramType::SchedClassifier
            | ProgramType::SocketFilter => PolicyAction::Warn,

            // Higher risk: Security-critical, can bypass protections
            ProgramType::Lsm
            | ProgramType::StructOps
            | ProgramType::CgroupSkb => PolicyAction::Deny,

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
    Unload {
        id: ProgramId,
    },

    /// Attach a loaded program to a hook.
    Attach {
        id: ProgramId,
        /// e.g., "sys_openat" for kprobe, "syscalls:sys_enter_openat" for tracepoint
        target: String,
    },

    /// Detach a program from its hook.
    Detach {
        id: ProgramId,
    },

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
    MapList {
        id: ProgramId,
    },

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
    Unloaded {
        id: ProgramId,
    },

    /// Program attached successfully.
    Attached {
        id: ProgramId,
        target: String,
    },

    /// Program detached successfully.
    Detached {
        id: ProgramId,
    },

    /// List of loaded programs.
    Programs {
        programs: Vec<ProgramInfo>,
    },

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
    Error {
        message: String,
        code: ErrorCode,
    },

    /// List of maps for a program.
    Maps {
        maps: Vec<MapInfo>,
    },

    /// Map entries read result.
    MapEntries {
        map_name: String,
        entries: Vec<MapEntry>,
    },

    /// Map write success.
    MapWritten {
        map_name: String,
        key: String,
    },

    /// Map delete success.
    MapDeleted {
        map_name: String,
        key: String,
    },
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

    #[test]
    fn test_request_serialization() {
        let req = Request::Load {
            path: PathBuf::from("/tmp/probe.o"),
            program_name: Some("my_probe".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("load"));
        assert!(json.contains("/tmp/probe.o"));
    }

    #[test]
    fn test_response_serialization() {
        let resp = Response::Loaded {
            id: ProgramId(1),
            name: "test".to_string(),
            program_type: ProgramType::KProbe,
            warning: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("loaded"));
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
        assert!(json.contains("warning"));
        assert!(json.contains("XDP can modify packets"));
    }

    #[test]
    fn test_policy_defaults() {
        // Observability types should be allowed
        assert_eq!(ProgramType::KProbe.default_policy(), PolicyAction::Allow);
        assert_eq!(ProgramType::TracePoint.default_policy(), PolicyAction::Allow);
        assert_eq!(ProgramType::PerfEvent.default_policy(), PolicyAction::Allow);

        // Network types should warn
        assert_eq!(ProgramType::Xdp.default_policy(), PolicyAction::Warn);
        assert_eq!(ProgramType::SchedClassifier.default_policy(), PolicyAction::Warn);

        // Security-critical types should be denied
        assert_eq!(ProgramType::Lsm.default_policy(), PolicyAction::Deny);
        assert_eq!(ProgramType::StructOps.default_policy(), PolicyAction::Deny);
        assert_eq!(ProgramType::Unknown.default_policy(), PolicyAction::Deny);
    }
}
