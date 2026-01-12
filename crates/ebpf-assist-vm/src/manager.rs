//! MicroVM manager for VM lifecycle and pool management.

use crate::config::{PoolConfig, VmConfig};
use crate::error::{VmError, VmResult};
use crate::firecracker::FirecrackerInstance;
use crate::vsock_client::GuestClient;
use crate::protocol::{GuestCommand, GuestResponse};
use ebpf_assist_common::{ProgramId, ProgramInfo};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Unique identifier for a VM.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VmId(String);

impl VmId {
    /// Create a new random VM ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Get the ID as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for VmId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for VmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for VmId {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl VmId {
    /// Create a VmId from a string (convenience method).
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// State of a MicroVM.
#[derive(Debug, Clone, PartialEq)]
pub enum VmState {
    /// VM is starting up.
    Starting,
    /// VM is running and ready.
    Running,
    /// VM is stopping.
    Stopping,
    /// VM has stopped.
    Stopped,
    /// VM has crashed with diagnostic information.
    Crashed(Option<crate::firecracker::CrashInfo>),
}

/// A single MicroVM instance.
pub struct MicroVm {
    /// Unique identifier.
    pub id: VmId,
    /// Current state.
    pub state: VmState,
    /// Firecracker instance.
    firecracker: FirecrackerInstance,
    /// Guest client for communication.
    client: Option<GuestClient>,
    /// Programs loaded in this VM.
    programs: HashMap<ProgramId, ProgramInfo>,
}

impl MicroVm {
    /// Create and boot a new MicroVM.
    pub async fn create(config: VmConfig) -> VmResult<Self> {
        let id = VmId::new();
        info!(vm_id = %id, "Creating new MicroVM");

        // Start Firecracker
        let firecracker = FirecrackerInstance::start(config, id.as_str()).await?;

        let mut vm = Self {
            id,
            state: VmState::Starting,
            firecracker,
            client: None,
            programs: HashMap::new(),
        };

        // Boot the VM
        vm.firecracker.boot().await?;

        // Connect to guest agent
        vm.connect().await?;

        vm.state = VmState::Running;
        info!(vm_id = %vm.id, "MicroVM is running");

        Ok(vm)
    }

    /// Connect to the guest agent.
    async fn connect(&mut self) -> VmResult<()> {
        let vsock_path = self.firecracker.vsock_path();

        // Retry connection with backoff
        for attempt in 1..=10 {
            debug!(vm_id = %self.id, attempt = attempt, "Connecting to guest agent");

            match GuestClient::connect(vsock_path).await {
                Ok(client) => {
                    // Verify connection with ping
                    let mut client = client;
                    match client.send_command(GuestCommand::Ping).await {
                        Ok(GuestResponse::Pong) => {
                            self.client = Some(client);
                            info!(vm_id = %self.id, "Connected to guest agent");
                            return Ok(());
                        }
                        Ok(other) => {
                            warn!(vm_id = %self.id, response = ?other, "Unexpected ping response");
                        }
                        Err(e) => {
                            warn!(vm_id = %self.id, error = %e, "Ping failed");
                        }
                    }
                }
                Err(e) => {
                    debug!(vm_id = %self.id, error = %e, "Connection attempt failed");
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }

        Err(VmError::AgentConnectionFailed(
            "Failed to connect after 10 attempts".to_string(),
        ))
    }

    /// Get the guest client.
    fn client(&mut self) -> VmResult<&mut GuestClient> {
        self.client
            .as_mut()
            .ok_or_else(|| VmError::AgentConnectionFailed("Not connected".to_string()))
    }

    /// Load an eBPF program into the VM.
    pub async fn load_program(&mut self, bytes: Vec<u8>, name: String) -> VmResult<(ProgramId, ProgramInfo)> {
        let client = self.client()?;

        let response = client
            .send_command(GuestCommand::Load {
                program_bytes: bytes,
                name,
            })
            .await?;

        match response {
            GuestResponse::Loaded { id, info } => {
                self.programs.insert(id, info.clone());
                Ok((id, info))
            }
            GuestResponse::Error { message, .. } => {
                Err(VmError::BootFailed(message))
            }
            other => Err(VmError::BootFailed(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Unload a program from the VM.
    pub async fn unload_program(&mut self, id: ProgramId) -> VmResult<()> {
        let client = self.client()?;

        let response = client
            .send_command(GuestCommand::Unload { id })
            .await?;

        match response {
            GuestResponse::Unloaded => {
                self.programs.remove(&id);
                Ok(())
            }
            GuestResponse::Error { message, .. } => {
                Err(VmError::BootFailed(message))
            }
            other => Err(VmError::BootFailed(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Attach a program to a target.
    pub async fn attach_program(&mut self, id: ProgramId, target: String) -> VmResult<()> {
        let client = self.client()?;

        let response = client
            .send_command(GuestCommand::Attach { id, target })
            .await?;

        match response {
            GuestResponse::Attached => Ok(()),
            GuestResponse::Error { message, .. } => {
                Err(VmError::BootFailed(message))
            }
            other => Err(VmError::BootFailed(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Detach a program.
    pub async fn detach_program(&mut self, id: ProgramId) -> VmResult<()> {
        let client = self.client()?;

        let response = client
            .send_command(GuestCommand::Detach { id })
            .await?;

        match response {
            GuestResponse::Detached => Ok(()),
            GuestResponse::Error { message, .. } => {
                Err(VmError::BootFailed(message))
            }
            other => Err(VmError::BootFailed(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// List programs in the VM.
    pub async fn list_programs(&mut self) -> VmResult<Vec<ProgramInfo>> {
        let client = self.client()?;

        let response = client.send_command(GuestCommand::List).await?;

        match response {
            GuestResponse::Programs(programs) => Ok(programs),
            GuestResponse::Error { message, .. } => {
                Err(VmError::BootFailed(message))
            }
            other => Err(VmError::BootFailed(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Read trace output.
    pub async fn read_trace(&mut self, lines: u32, timeout_ms: u32) -> VmResult<Vec<String>> {
        let client = self.client()?;

        let response = client
            .send_command(GuestCommand::ReadTrace { lines, timeout_ms })
            .await?;

        match response {
            GuestResponse::TraceOutput { lines } => Ok(lines),
            GuestResponse::Error { message, .. } => {
                Err(VmError::BootFailed(message))
            }
            other => Err(VmError::BootFailed(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Trigger activity for testing.
    pub async fn trigger(
        &mut self,
        category: String,
        operation: String,
        args: Vec<String>,
    ) -> VmResult<String> {
        let client = self.client()?;

        let response = client
            .send_command(GuestCommand::Trigger {
                category,
                operation,
                args,
            })
            .await?;

        match response {
            GuestResponse::Triggered { output } => Ok(output),
            GuestResponse::Error { message, .. } => {
                Err(VmError::BootFailed(message))
            }
            other => Err(VmError::BootFailed(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Reset the VM state (unload all programs).
    pub async fn reset(&mut self) -> VmResult<()> {
        let client = self.client()?;

        let response = client.send_command(GuestCommand::Reset).await?;

        match response {
            GuestResponse::ResetComplete => {
                self.programs.clear();
                Ok(())
            }
            GuestResponse::Error { message, .. } => {
                Err(VmError::BootFailed(message))
            }
            other => Err(VmError::BootFailed(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /// Shutdown the VM.
    pub async fn shutdown(mut self) -> VmResult<()> {
        self.state = VmState::Stopping;

        // Send shutdown command to agent
        if let Some(ref mut client) = self.client {
            let _ = client.send_command(GuestCommand::Shutdown).await;
        }

        // Shutdown Firecracker
        self.firecracker.shutdown().await?;

        self.state = VmState::Stopped;
        info!(vm_id = %self.id, "MicroVM shutdown complete");
        Ok(())
    }

    /// Check if the VM has crashed and update state if so.
    /// Returns crash info if the VM crashed.
    pub fn check_health(&mut self) -> Option<crate::firecracker::CrashInfo> {
        if let Some(crash_info) = self.firecracker.check_crash() {
            warn!(
                vm_id = %self.id,
                likely_cause = %crash_info.likely_cause,
                "VM crashed"
            );
            self.state = VmState::Crashed(Some(crash_info.clone()));
            Some(crash_info)
        } else {
            None
        }
    }

    /// Check if the VM is healthy (running and responsive).
    pub async fn is_healthy(&mut self) -> bool {
        // First check if the process is running
        if self.check_health().is_some() {
            return false;
        }

        // Try to ping the guest agent
        if let Some(ref mut client) = self.client {
            match client.send_command(GuestCommand::Ping).await {
                Ok(GuestResponse::Pong) => true,
                _ => {
                    warn!(vm_id = %self.id, "Guest agent not responding");
                    false
                }
            }
        } else {
            false
        }
    }

    /// Get crash info if the VM has crashed.
    pub fn crash_info(&self) -> Option<&crate::firecracker::CrashInfo> {
        match &self.state {
            VmState::Crashed(info) => info.as_ref(),
            _ => None,
        }
    }
}

/// Manager for multiple MicroVMs with optional pooling.
pub struct MicroVmManager {
    /// Pool configuration.
    config: PoolConfig,
    /// Active VMs.
    active_vms: Arc<Mutex<HashMap<VmId, MicroVm>>>,
    /// Warm (pre-booted) VMs ready for use.
    warm_pool: Arc<Mutex<Vec<MicroVm>>>,
}

impl MicroVmManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            active_vms: Arc::new(Mutex::new(HashMap::new())),
            warm_pool: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a manager with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(PoolConfig::default())
    }

    /// Acquire a VM (from warm pool or create new).
    pub async fn acquire(&self) -> VmResult<VmId> {
        // Try to get from warm pool first
        {
            let mut pool = self.warm_pool.lock().await;
            if let Some(vm) = pool.pop() {
                let id = vm.id.clone();
                let mut active = self.active_vms.lock().await;
                active.insert(id.clone(), vm);
                info!(vm_id = %id, "Acquired VM from warm pool");
                return Ok(id);
            }
        }

        // Check if we can create a new VM
        {
            let active = self.active_vms.lock().await;
            let pool = self.warm_pool.lock().await;
            let total = active.len() + pool.len();
            if total >= self.config.max_total {
                return Err(VmError::PoolExhausted(self.config.max_total));
            }
        }

        // Create a new VM
        let vm = MicroVm::create(self.config.vm_config.clone()).await?;
        let id = vm.id.clone();

        let mut active = self.active_vms.lock().await;
        active.insert(id.clone(), vm);

        info!(vm_id = %id, "Created new VM");
        Ok(id)
    }

    /// Release a VM (return to pool or destroy).
    pub async fn release(&self, id: &VmId) -> VmResult<()> {
        let vm = {
            let mut active = self.active_vms.lock().await;
            active.remove(id).ok_or_else(|| VmError::VmNotFound(id.to_string()))?
        };

        // Check if we can return to warm pool
        let can_warm = {
            let pool = self.warm_pool.lock().await;
            pool.len() < self.config.max_warm
        };

        if can_warm {
            // Reset and return to pool
            let mut vm = vm;
            if let Err(e) = vm.reset().await {
                warn!(vm_id = %id, error = %e, "Failed to reset VM, destroying instead");
                let _ = vm.shutdown().await;
            } else {
                let mut pool = self.warm_pool.lock().await;
                pool.push(vm);
                info!(vm_id = %id, "Returned VM to warm pool");
            }
        } else {
            // Destroy the VM
            let _ = vm.shutdown().await;
            info!(vm_id = %id, "Destroyed VM (warm pool full)");
        }

        Ok(())
    }

    /// Get access to a VM by ID.
    pub async fn with_vm<F, R>(&self, id: &VmId, f: F) -> VmResult<R>
    where
        F: FnOnce(&mut MicroVm) -> R,
    {
        let mut active = self.active_vms.lock().await;
        let vm = active
            .get_mut(id)
            .ok_or_else(|| VmError::VmNotFound(id.to_string()))?;
        Ok(f(vm))
    }

    /// Get access to a VM for async operations.
    pub async fn with_vm_async<F, Fut, R>(&self, id: &VmId, f: F) -> VmResult<R>
    where
        F: FnOnce(&mut MicroVm) -> Fut,
        Fut: std::future::Future<Output = VmResult<R>>,
    {
        let mut active = self.active_vms.lock().await;
        let vm = active
            .get_mut(id)
            .ok_or_else(|| VmError::VmNotFound(id.to_string()))?;
        f(vm).await
    }

    /// Load a program into a VM (convenience method).
    pub async fn load_program(
        &self,
        id: &VmId,
        bytes: Vec<u8>,
        name: String,
    ) -> VmResult<(ebpf_assist_common::ProgramId, ebpf_assist_common::ProgramInfo)> {
        let mut active = self.active_vms.lock().await;
        let vm = active
            .get_mut(id)
            .ok_or_else(|| VmError::VmNotFound(id.to_string()))?;
        vm.load_program(bytes, name).await
    }

    /// List all active VM IDs.
    pub async fn list_active(&self) -> Vec<VmId> {
        let active = self.active_vms.lock().await;
        active.keys().cloned().collect()
    }

    /// Get pool statistics.
    pub async fn stats(&self) -> PoolStats {
        let active = self.active_vms.lock().await;
        let pool = self.warm_pool.lock().await;
        PoolStats {
            active_vms: active.len(),
            warm_vms: pool.len(),
            max_total: self.config.max_total,
        }
    }

    /// Pre-warm the pool with VMs.
    pub async fn warm_up(&self, count: usize) -> VmResult<()> {
        let to_create = {
            let pool = self.warm_pool.lock().await;
            count.saturating_sub(pool.len())
        };

        for _ in 0..to_create {
            let vm = MicroVm::create(self.config.vm_config.clone()).await?;
            let mut pool = self.warm_pool.lock().await;
            pool.push(vm);
        }

        info!(count = to_create, "Warmed up VM pool");
        Ok(())
    }

    /// Shutdown all VMs.
    pub async fn shutdown_all(&self) -> VmResult<()> {
        // Shutdown active VMs
        let active_vms: Vec<_> = {
            let mut active = self.active_vms.lock().await;
            active.drain().map(|(_, vm)| vm).collect()
        };

        for vm in active_vms {
            let _ = vm.shutdown().await;
        }

        // Shutdown warm pool VMs
        let warm_vms: Vec<_> = {
            let mut pool = self.warm_pool.lock().await;
            pool.drain(..).collect()
        };

        for vm in warm_vms {
            let _ = vm.shutdown().await;
        }

        info!("All VMs shutdown");
        Ok(())
    }
}

/// Pool statistics.
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Number of active (in-use) VMs.
    pub active_vms: usize,
    /// Number of warm (ready) VMs.
    pub warm_vms: usize,
    /// Maximum total VMs.
    pub max_total: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_id_generation() {
        let id1 = VmId::new();
        let id2 = VmId::new();
        assert_ne!(id1, id2);
        assert!(!id1.as_str().is_empty());
    }

    #[test]
    fn test_vm_state() {
        let state = VmState::Running;
        assert_eq!(state, VmState::Running);
    }

    #[test]
    fn test_pool_stats() {
        let stats = PoolStats {
            active_vms: 2,
            warm_vms: 1,
            max_total: 5,
        };
        assert_eq!(stats.active_vms, 2);
        assert_eq!(stats.warm_vms, 1);
    }
}
