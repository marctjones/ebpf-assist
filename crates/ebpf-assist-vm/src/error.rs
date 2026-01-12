//! Error types for MicroVM operations.

use thiserror::Error;

/// Result type for VM operations.
pub type VmResult<T> = Result<T, VmError>;

/// Errors that can occur during VM operations.
#[derive(Debug, Error)]
pub enum VmError {
    /// KVM is not available on this system.
    #[error("KVM not available: {0}. Ensure /dev/kvm exists and is accessible.")]
    KvmNotAvailable(String),

    /// Firecracker binary not found.
    #[error("Firecracker not found. Install it or set FIRECRACKER_PATH.")]
    FirecrackerNotFound,

    /// Kernel image not found.
    #[error("Kernel image not found at {0}. Run 'ebpf-assist vm init' to set up.")]
    KernelNotFound(String),

    /// Root filesystem not found.
    #[error("Rootfs not found at {0}. Run 'ebpf-assist vm init' to set up.")]
    RootfsNotFound(String),

    /// VM failed to boot.
    #[error("VM failed to boot: {0}")]
    BootFailed(String),

    /// VM not found.
    #[error("VM {0} not found")]
    VmNotFound(String),

    /// VM is not running.
    #[error("VM {0} is not running")]
    VmNotRunning(String),

    /// Failed to connect to VM agent.
    #[error("Failed to connect to VM agent: {0}")]
    AgentConnectionFailed(String),

    /// Agent not responding.
    #[error("VM agent not responding (timeout)")]
    AgentTimeout,

    /// VM crashed.
    #[error("VM crashed: {0}")]
    VmCrashed(String),

    /// Firecracker API error.
    #[error("Firecracker API error: {0}")]
    FirecrackerApi(String),

    /// vsock communication error.
    #[error("vsock error: {0}")]
    Vsock(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Pool exhausted.
    #[error("VM pool exhausted (max {0} VMs)")]
    PoolExhausted(usize),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),
}
