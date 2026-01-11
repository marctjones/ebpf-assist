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
    Unknown,
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
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("loaded"));
    }
}
