//! Protocol types for host-guest communication over vsock.
//!
//! This is a copy of the protocol module from ebpf-assist-vm to avoid
//! pulling in host-side dependencies when building the agent.

use ebpf_assist_common::{MapEntry, MapInfo, ProgramId, ProgramInfo};
use serde::{Deserialize, Serialize};

/// Commands sent from host to guest agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum GuestCommand {
    /// Load an eBPF program (bytes transferred inline).
    Load {
        /// Raw program bytes (.o file contents).
        program_bytes: Vec<u8>,
        /// Program name.
        name: String,
    },

    /// Unload a program.
    Unload { id: ProgramId },

    /// Attach program to a target.
    Attach { id: ProgramId, target: String },

    /// Detach program from target.
    Detach { id: ProgramId },

    /// List all loaded programs.
    List,

    /// Get agent status.
    Status,

    /// Trigger activity for testing.
    Trigger {
        category: String,
        operation: String,
        args: Vec<String>,
    },

    /// Read trace output.
    ReadTrace { lines: u32, timeout_ms: u32 },

    /// List maps for a program.
    MapList { program_id: ProgramId },

    /// Read from a map.
    MapRead {
        program_id: ProgramId,
        map_name: String,
        key: Option<Vec<u8>>,
    },

    /// Write to a map.
    MapWrite {
        program_id: ProgramId,
        map_name: String,
        key: Vec<u8>,
        value: Vec<u8>,
    },

    /// Delete from a map.
    MapDelete {
        program_id: ProgramId,
        map_name: String,
        key: Vec<u8>,
    },

    /// Unload all programs (for VM reset).
    UnloadAll,

    /// Reset agent state.
    Reset,

    /// Shutdown the VM gracefully.
    Shutdown,

    /// Health check ping.
    Ping,
}

/// Responses from guest agent to host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum GuestResponse {
    /// Program loaded successfully.
    Loaded { id: ProgramId, info: ProgramInfo },

    /// Program unloaded.
    Unloaded,

    /// All programs unloaded.
    UnloadedAll { count: usize },

    /// Program attached.
    Attached,

    /// Program detached.
    Detached,

    /// List of programs.
    Programs(Vec<ProgramInfo>),

    /// Agent status.
    Status {
        uptime_secs: u64,
        programs_loaded: usize,
    },

    /// Trigger completed.
    Triggered { output: String },

    /// Trace output lines.
    TraceOutput { lines: Vec<String> },

    /// Map list.
    MapList { maps: Vec<MapInfo> },

    /// Map entries.
    MapEntries { entries: Vec<MapEntry> },

    /// Map write successful.
    MapWritten,

    /// Map delete successful.
    MapDeleted,

    /// Reset complete.
    ResetComplete,

    /// Pong response to ping.
    Pong,

    /// VM is shutting down.
    ShuttingDown,

    /// Error response.
    Error { code: i32, message: String },
}

impl GuestResponse {
    /// Create an error response.
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            code: -1,
            message: message.into(),
        }
    }

    /// Create an error response with code.
    pub fn error_with_code(code: i32, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
        }
    }

    /// Check if response is an error.
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }
}

/// Wire protocol: length-prefixed JSON.
///
/// Format: [4 bytes: length (u32 LE)][N bytes: JSON payload]
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16 MB
