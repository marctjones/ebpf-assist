//! MicroVM management for ebpf-assist.
//!
//! This crate provides Firecracker-based MicroVM isolation for safe eBPF
//! experimentation. Programs can be loaded and run in an isolated kernel
//! that can crash without affecting the host.

mod config;
mod error;
mod firecracker;
mod manager;
mod protocol;
mod vsock_client;

pub use config::{PoolConfig, VmConfig};
pub use error::{VmError, VmResult};
pub use firecracker::CrashInfo;
pub use manager::{MicroVm, MicroVmManager, VmId, VmState};
pub use protocol::{GuestCommand, GuestResponse};
pub use vsock_client::GuestClient;
