//! Firecracker API client for VM management.

use crate::error::{VmError, VmResult};
use crate::config::VmConfig;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use tokio::net::UnixStream;
use tracing::{debug, info, warn};

/// Crash information captured when a VM dies unexpectedly.
#[derive(Debug, Clone, PartialEq)]
pub struct CrashInfo {
    /// Exit code of the process.
    pub exit_code: Option<i32>,
    /// Captured stderr output.
    pub stderr: String,
    /// Captured stdout output.
    pub stdout: String,
    /// Possible cause of the crash.
    pub likely_cause: String,
}

impl CrashInfo {
    /// Analyze the crash and provide likely cause.
    pub fn analyze(exit_code: Option<i32>, stdout: &str, stderr: &str) -> Self {
        let likely_cause = if stderr.contains("KVM_RUN failed") {
            "KVM execution error - check that KVM is enabled and accessible".to_string()
        } else if stderr.contains("Permission denied") {
            "Permission error - check KVM device permissions".to_string()
        } else if stderr.contains("SIGKILL") || exit_code == Some(137) {
            "VM was killed (possibly OOM killer or external signal)".to_string()
        } else if stderr.contains("panic") || stderr.contains("kernel panic") {
            "Kernel panic - the eBPF program may have caused a kernel crash".to_string()
        } else if stderr.contains("BPF") || stderr.contains("bpf") {
            "BPF-related error - the eBPF program likely caused an issue".to_string()
        } else if stdout.contains("Segmentation fault") || stderr.contains("Segmentation fault") {
            "Segmentation fault in guest agent or eBPF program".to_string()
        } else if exit_code.is_some() {
            format!("Process exited with code {:?}", exit_code)
        } else {
            "Unknown cause - check stdout/stderr for details".to_string()
        };

        Self {
            exit_code,
            stderr: stderr.to_string(),
            stdout: stdout.to_string(),
            likely_cause,
        }
    }
}

/// Firecracker instance managing a single MicroVM.
pub struct FirecrackerInstance {
    /// Child process handle.
    process: Child,
    /// Path to the API socket.
    socket_path: PathBuf,
    /// vsock path for guest communication.
    vsock_path: PathBuf,
    /// VM configuration.
    config: VmConfig,
}

impl FirecrackerInstance {
    /// Start a new Firecracker instance.
    pub async fn start(config: VmConfig, vm_id: &str) -> VmResult<Self> {
        // Validate paths exist
        if !config.firecracker_path.exists() {
            return Err(VmError::FirecrackerNotFound);
        }
        if !config.kernel_path.exists() {
            return Err(VmError::KernelNotFound(
                config.kernel_path.display().to_string(),
            ));
        }
        if !config.rootfs_path.exists() {
            return Err(VmError::RootfsNotFound(
                config.rootfs_path.display().to_string(),
            ));
        }

        // Create runtime directory
        let runtime_dir = PathBuf::from(format!("/tmp/ebpf-assist-vm/{}", vm_id));
        tokio::fs::create_dir_all(&runtime_dir).await?;

        let socket_path = runtime_dir.join("firecracker.sock");
        let vsock_path = runtime_dir.join("vsock.sock");

        // Remove stale sockets
        let _ = tokio::fs::remove_file(&socket_path).await;
        let _ = tokio::fs::remove_file(&vsock_path).await;

        info!(
            vm_id = vm_id,
            socket = %socket_path.display(),
            "Starting Firecracker instance"
        );

        // Start Firecracker process
        let process = Command::new(&config.firecracker_path)
            .arg("--api-sock")
            .arg(&socket_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let instance = Self {
            process,
            socket_path,
            vsock_path,
            config,
        };

        // Wait for socket to be available
        instance.wait_for_socket().await?;

        Ok(instance)
    }

    /// Wait for the API socket to become available.
    async fn wait_for_socket(&self) -> VmResult<()> {
        for _ in 0..50 {
            if self.socket_path.exists() {
                // Try to connect
                if UnixStream::connect(&self.socket_path).await.is_ok() {
                    return Ok(());
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        Err(VmError::BootFailed(
            "Firecracker socket not available after 5s".to_string(),
        ))
    }

    /// Configure and boot the VM.
    pub async fn boot(&self) -> VmResult<()> {
        // Set boot source
        self.put_boot_source().await?;

        // Set root drive
        self.put_root_drive().await?;

        // Configure machine
        self.put_machine_config().await?;

        // Configure vsock
        self.put_vsock().await?;

        // Start the VM
        self.put_actions("InstanceStart").await?;

        info!("VM booted successfully");
        Ok(())
    }

    /// Make an API request to Firecracker.
    async fn api_request<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
    ) -> VmResult<String> {
        let stream = UnixStream::connect(&self.socket_path).await?;
        let io = hyper_util::rt::TokioIo::new(stream);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await
            .map_err(|e| VmError::FirecrackerApi(e.to_string()))?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                warn!("Connection error: {}", e);
            }
        });

        let body_bytes = match body {
            Some(b) => serde_json::to_vec(b)?,
            None => Vec::new(),
        };

        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|e| VmError::FirecrackerApi(e.to_string()))?;

        let response = sender.send_request(req).await
            .map_err(|e| VmError::FirecrackerApi(e.to_string()))?;

        let status = response.status();
        let body = response.into_body().collect().await
            .map_err(|e| VmError::FirecrackerApi(e.to_string()))?
            .to_bytes();

        let body_str = String::from_utf8_lossy(&body).to_string();

        if !status.is_success() {
            return Err(VmError::FirecrackerApi(format!(
                "HTTP {}: {}",
                status, body_str
            )));
        }

        debug!(path = path, status = %status, "API request successful");
        Ok(body_str)
    }

    /// Configure boot source.
    async fn put_boot_source(&self) -> VmResult<()> {
        #[derive(Serialize)]
        struct BootSource {
            kernel_image_path: String,
            boot_args: String,
        }

        let boot_source = BootSource {
            kernel_image_path: self.config.kernel_path.display().to_string(),
            boot_args: self.config.boot_args.clone(),
        };

        self.api_request(Method::PUT, "/boot-source", Some(&boot_source))
            .await?;
        Ok(())
    }

    /// Configure root drive.
    async fn put_root_drive(&self) -> VmResult<()> {
        #[derive(Serialize)]
        struct Drive {
            drive_id: String,
            path_on_host: String,
            is_root_device: bool,
            is_read_only: bool,
        }

        let drive = Drive {
            drive_id: "rootfs".to_string(),
            path_on_host: self.config.rootfs_path.display().to_string(),
            is_root_device: true,
            is_read_only: false,
        };

        self.api_request(Method::PUT, "/drives/rootfs", Some(&drive))
            .await?;
        Ok(())
    }

    /// Configure machine resources.
    async fn put_machine_config(&self) -> VmResult<()> {
        #[derive(Serialize)]
        struct MachineConfig {
            vcpu_count: u8,
            mem_size_mib: u32,
        }

        let config = MachineConfig {
            vcpu_count: self.config.vcpu_count,
            mem_size_mib: self.config.mem_size_mb,
        };

        self.api_request(Method::PUT, "/machine-config", Some(&config))
            .await?;
        Ok(())
    }

    /// Configure vsock device.
    async fn put_vsock(&self) -> VmResult<()> {
        #[derive(Serialize)]
        struct Vsock {
            guest_cid: u32,
            uds_path: String,
        }

        let vsock = Vsock {
            guest_cid: 3, // Standard guest CID
            uds_path: self.vsock_path.display().to_string(),
        };

        self.api_request(Method::PUT, "/vsock", Some(&vsock))
            .await?;
        Ok(())
    }

    /// Execute an action.
    async fn put_actions(&self, action_type: &str) -> VmResult<()> {
        #[derive(Serialize)]
        struct Action {
            action_type: String,
        }

        let action = Action {
            action_type: action_type.to_string(),
        };

        self.api_request(Method::PUT, "/actions", Some(&action))
            .await?;
        Ok(())
    }

    /// Get the vsock path for connecting to the guest.
    pub fn vsock_path(&self) -> &Path {
        &self.vsock_path
    }

    /// Check if the process is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.process.try_wait(), Ok(None))
    }

    /// Check if the process has crashed and return crash info.
    pub fn check_crash(&mut self) -> Option<CrashInfo> {
        match self.process.try_wait() {
            Ok(Some(status)) => {
                // Process has exited
                let exit_code = status.code();

                // Try to read stderr/stdout
                let stdout = self.process.stdout.take()
                    .and_then(|mut s| {
                        use std::io::Read;
                        let mut buf = String::new();
                        s.read_to_string(&mut buf).ok()?;
                        Some(buf)
                    })
                    .unwrap_or_default();

                let stderr = self.process.stderr.take()
                    .and_then(|mut s| {
                        use std::io::Read;
                        let mut buf = String::new();
                        s.read_to_string(&mut buf).ok()?;
                        Some(buf)
                    })
                    .unwrap_or_default();

                Some(CrashInfo::analyze(exit_code, &stdout, &stderr))
            }
            Ok(None) => None, // Still running
            Err(e) => {
                // Error checking status - assume crashed
                Some(CrashInfo {
                    exit_code: None,
                    stdout: String::new(),
                    stderr: format!("Failed to check process status: {}", e),
                    likely_cause: "Process status check failed".to_string(),
                })
            }
        }
    }

    /// Wait for the process to exit and return crash info.
    pub async fn wait_for_exit(&mut self) -> CrashInfo {
        // Wait for process with timeout
        let timeout = tokio::time::Duration::from_secs(10);
        let start = std::time::Instant::now();

        loop {
            if let Some(info) = self.check_crash() {
                return info;
            }

            if start.elapsed() > timeout {
                // Force kill and collect info
                let _ = self.process.kill();
                return CrashInfo {
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    likely_cause: "Process did not exit within timeout, was killed".to_string(),
                };
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    /// Shutdown the VM gracefully.
    pub async fn shutdown(&mut self) -> VmResult<()> {
        // Try graceful shutdown first
        let _ = self.put_actions("SendCtrlAltDel").await;

        // Wait a bit for graceful shutdown
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Force kill if still running
        if self.is_running() {
            warn!("VM did not shutdown gracefully, forcing");
            let _ = self.process.kill();
        }

        // Clean up sockets
        let _ = tokio::fs::remove_file(&self.socket_path).await;
        let _ = tokio::fs::remove_file(&self.vsock_path).await;

        Ok(())
    }
}

impl Drop for FirecrackerInstance {
    fn drop(&mut self) {
        // Best effort kill on drop
        let _ = self.process.kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_source_serialization() {
        #[derive(Serialize)]
        struct BootSource {
            kernel_image_path: String,
            boot_args: String,
        }

        let boot_source = BootSource {
            kernel_image_path: "/path/to/vmlinux".to_string(),
            boot_args: "console=ttyS0".to_string(),
        };

        let json = serde_json::to_string(&boot_source).unwrap();
        assert!(json.contains("kernel_image_path"));
        assert!(json.contains("boot_args"));
    }
}
