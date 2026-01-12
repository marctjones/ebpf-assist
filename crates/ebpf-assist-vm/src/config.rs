//! Configuration types for MicroVM management.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Configuration for a single MicroVM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// Number of vCPUs (default: 1).
    pub vcpu_count: u8,

    /// Memory size in MB (default: 128).
    pub mem_size_mb: u32,

    /// Path to kernel image.
    pub kernel_path: PathBuf,

    /// Path to root filesystem.
    pub rootfs_path: PathBuf,

    /// Path to Firecracker binary.
    pub firecracker_path: PathBuf,

    /// Kernel boot arguments.
    pub boot_args: String,

    /// vsock port for agent communication.
    pub vsock_port: u32,
}

impl Default for VmConfig {
    fn default() -> Self {
        let data_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("ebpf-assist");

        Self {
            vcpu_count: 1,
            mem_size_mb: 128,
            kernel_path: data_dir.join("vmlinux"),
            rootfs_path: data_dir.join("rootfs.ext4"),
            firecracker_path: find_firecracker().unwrap_or_else(|| PathBuf::from("firecracker")),
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off".to_string(),
            vsock_port: 5000,
        }
    }
}

impl VmConfig {
    /// Create config with custom paths.
    pub fn with_paths(kernel: PathBuf, rootfs: PathBuf, firecracker: PathBuf) -> Self {
        Self {
            kernel_path: kernel,
            rootfs_path: rootfs,
            firecracker_path: firecracker,
            ..Default::default()
        }
    }

    /// Set memory size.
    pub fn with_memory(mut self, mb: u32) -> Self {
        self.mem_size_mb = mb;
        self
    }

    /// Set vCPU count.
    pub fn with_vcpus(mut self, count: u8) -> Self {
        self.vcpu_count = count;
        self
    }
}

/// Configuration for VM pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Minimum number of warm VMs to maintain.
    pub min_warm: usize,

    /// Maximum number of warm VMs.
    pub max_warm: usize,

    /// Maximum total VMs (warm + active).
    pub max_total: usize,

    /// How long before recycling an idle VM.
    pub idle_timeout: Duration,

    /// VM configuration template.
    pub vm_config: VmConfig,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_warm: 0,
            max_warm: 2,
            max_total: 5,
            idle_timeout: Duration::from_secs(300),
            vm_config: VmConfig::default(),
        }
    }
}

impl PoolConfig {
    /// Create pool config with custom VM config.
    pub fn with_vm_config(mut self, config: VmConfig) -> Self {
        self.vm_config = config;
        self
    }

    /// Set pool sizes.
    pub fn with_sizes(mut self, min_warm: usize, max_warm: usize, max_total: usize) -> Self {
        self.min_warm = min_warm;
        self.max_warm = max_warm;
        self.max_total = max_total;
        self
    }
}

/// Find Firecracker binary in common locations.
fn find_firecracker() -> Option<PathBuf> {
    // Check environment variable first
    if let Ok(path) = std::env::var("FIRECRACKER_PATH") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }

    // Check ebpf-assist data directory (where setup script installs it)
    if let Some(data_dir) = dirs::data_local_dir() {
        let ebpf_assist_fc = data_dir.join("ebpf-assist").join("firecracker");
        if ebpf_assist_fc.exists() {
            return Some(ebpf_assist_fc);
        }
    }

    // Check common locations
    let locations = [
        "/usr/local/bin/firecracker",
        "/usr/bin/firecracker",
    ];

    for loc in &locations {
        let p = PathBuf::from(loc);
        if p.exists() {
            return Some(p);
        }
    }

    // Check user's local bin
    if let Some(home) = dirs::home_dir() {
        let local_bin = home.join(".local/bin/firecracker");
        if local_bin.exists() {
            return Some(local_bin);
        }
    }

    // Check PATH
    which::which("firecracker").ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_vm_config() {
        let config = VmConfig::default();
        assert_eq!(config.vcpu_count, 1);
        assert_eq!(config.mem_size_mb, 128);
        assert_eq!(config.vsock_port, 5000);
    }

    #[test]
    fn test_vm_config_builder() {
        let config = VmConfig::default().with_memory(256).with_vcpus(2);
        assert_eq!(config.mem_size_mb, 256);
        assert_eq!(config.vcpu_count, 2);
    }

    #[test]
    fn test_default_pool_config() {
        let config = PoolConfig::default();
        assert_eq!(config.min_warm, 0);
        assert_eq!(config.max_warm, 2);
        assert_eq!(config.max_total, 5);
    }

    #[test]
    fn test_pool_config_builder() {
        let config = PoolConfig::default().with_sizes(1, 3, 10);
        assert_eq!(config.min_warm, 1);
        assert_eq!(config.max_warm, 3);
        assert_eq!(config.max_total, 10);
    }
}
