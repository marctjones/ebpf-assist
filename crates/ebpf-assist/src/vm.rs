//! VM management commands for MicroVM isolation.

use anyhow::{bail, Context, Result};
use serde_json::json;

use ebpf_assist_vm::{MicroVmManager, PoolConfig, VmState};

/// Initialize MicroVM environment (download assets, check KVM).
pub async fn init(json_output: bool) -> Result<()> {
    // Check KVM access by actually trying to open it
    // This correctly handles ACLs and other permission mechanisms
    let kvm_available = std::path::Path::new("/dev/kvm").exists();
    let kvm_writable = if kvm_available {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok()
    } else {
        false
    };

    // Check for required files
    let data_dir = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ebpf-assist");

    let firecracker_path = data_dir.join("firecracker");
    let kernel_path = data_dir.join("vmlinux");
    let rootfs_path = data_dir.join("rootfs.ext4");

    let firecracker_exists = firecracker_path.is_file();
    let kernel_exists = kernel_path.is_file();
    let rootfs_exists = rootfs_path.is_file();

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "kvm_available": kvm_available,
                "kvm_writable": kvm_writable,
                "data_dir": data_dir.display().to_string(),
                "assets": {
                    "firecracker": {
                        "path": firecracker_path.display().to_string(),
                        "exists": firecracker_exists
                    },
                    "kernel": {
                        "path": kernel_path.display().to_string(),
                        "exists": kernel_exists
                    },
                    "rootfs": {
                        "path": rootfs_path.display().to_string(),
                        "exists": rootfs_exists
                    }
                },
                "ready": kvm_available && kvm_writable && firecracker_exists && kernel_exists && rootfs_exists
            }))?
        );
    } else {
        println!("MicroVM Environment Status");
        println!("{}", "=".repeat(50));
        println!();

        // KVM status
        let kvm_status = if kvm_available && kvm_writable {
            "✓ Available and accessible"
        } else if kvm_available {
            "⚠ Available but not accessible (check permissions)"
        } else {
            "✗ Not available (KVM not enabled)"
        };
        println!("KVM:         {}", kvm_status);
        println!();

        // Asset status
        println!("Assets in {}:", data_dir.display());
        println!(
            "  Firecracker: {}",
            if firecracker_exists {
                "✓ Present"
            } else {
                "✗ Missing"
            }
        );
        println!(
            "  Kernel:      {}",
            if kernel_exists {
                "✓ Present"
            } else {
                "✗ Missing"
            }
        );
        println!(
            "  Rootfs:      {}",
            if rootfs_exists {
                "✓ Present"
            } else {
                "✗ Missing"
            }
        );
        println!();

        if !firecracker_exists || !kernel_exists || !rootfs_exists {
            println!("Setup required. Run:");
            println!("  ./scripts/vm/setup-vm.sh");
            println!();
            println!("This will download Firecracker and a compatible kernel,");
            println!("and build the rootfs with the guest agent.");
        } else if !kvm_available || !kvm_writable {
            println!("KVM access required. Options:");
            println!("  1. Enable KVM: modprobe kvm && modprobe kvm_intel (or kvm_amd)");
            println!("  2. Add your user to kvm group: sudo usermod -aG kvm $USER");
            println!("  3. Or run with sudo for isolated operations");
        } else {
            println!("✓ MicroVM environment ready!");
            println!();
            println!("Usage:");
            println!("  ebpf-assist load --isolate <program.o>  # Load in isolated VM");
            println!("  ebpf-assist vm list                     # List running VMs");
            println!("  ebpf-assist vm stop <vm-id>             # Stop a VM");
        }
    }

    Ok(())
}

/// List running MicroVMs.
pub async fn list(json_output: bool) -> Result<()> {
    let config = PoolConfig::default();
    let manager = MicroVmManager::new(config);
    let vms = manager.list_active().await;

    if json_output {
        let vm_list: Vec<_> = vms
            .iter()
            .map(|id| {
                json!({
                    "id": id.to_string(),
                    "state": "Running"
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "vms": vm_list
            }))?
        );
    } else if vms.is_empty() {
        println!("No MicroVMs running");
        println!();
        println!("Start one with: ebpf-assist load --isolate <program.o>");
    } else {
        println!("{:<36} {:<15}", "VM ID", "STATE");
        println!("{}", "-".repeat(55));
        for id in vms {
            println!("{:<36} {:<15}", id, "Running");
        }
    }

    Ok(())
}

/// Stop a MicroVM.
pub async fn stop(vm_id: &str, json_output: bool) -> Result<()> {
    let config = PoolConfig::default();
    let manager = MicroVmManager::new(config);

    // Create VmId from string
    let id: ebpf_assist_vm::VmId = vm_id.parse().unwrap();

    manager.release(&id).await.with_context(|| {
        format!("Failed to stop VM {}", vm_id)
    })?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "success": true,
                "vm_id": vm_id
            }))?
        );
    } else {
        println!("Stopped VM {}", vm_id);
    }

    Ok(())
}

/// Show detailed status of a MicroVM.
pub async fn status(vm_id: &str, json_output: bool) -> Result<()> {
    let config = PoolConfig::default();
    let manager = MicroVmManager::new(config);

    let id: ebpf_assist_vm::VmId = vm_id.parse().unwrap();

    // Get state via with_vm
    let state = manager.with_vm(&id, |vm| vm.state.clone()).await.with_context(|| {
        format!("VM {} not found", vm_id)
    })?;

    if json_output {
        let state_json = match &state {
            VmState::Crashed(Some(info)) => json!({
                "state": "Crashed",
                "exit_code": info.exit_code,
                "likely_cause": info.likely_cause,
                "stderr": info.stderr,
                "stdout": info.stdout
            }),
            VmState::Crashed(None) => json!({
                "state": "Crashed",
                "likely_cause": "Unknown"
            }),
            _ => json!({
                "state": format!("{:?}", state)
            }),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "vm_id": vm_id,
                "status": state_json
            }))?
        );
    } else {
        println!("VM: {}", vm_id);
        match state {
            VmState::Starting => println!("State: Starting"),
            VmState::Running => println!("State: Running"),
            VmState::Stopping => println!("State: Stopping"),
            VmState::Stopped => println!("State: Stopped"),
            VmState::Crashed(info) => {
                println!("State: Crashed");
                if let Some(crash_info) = info {
                    println!();
                    println!("Crash Information:");
                    println!("  Likely cause: {}", crash_info.likely_cause);
                    if let Some(code) = crash_info.exit_code {
                        println!("  Exit code:    {}", code);
                    }
                    if !crash_info.stderr.is_empty() {
                        println!();
                        println!("Stderr (last 500 chars):");
                        let stderr = &crash_info.stderr;
                        let truncated = if stderr.len() > 500 {
                            &stderr[stderr.len() - 500..]
                        } else {
                            stderr
                        };
                        for line in truncated.lines() {
                            println!("  {}", line);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Pool status and configuration.
pub async fn pool_status(json_output: bool) -> Result<()> {
    let config = PoolConfig::default();
    let manager = MicroVmManager::new(config.clone());
    let stats = manager.stats().await;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "max_warm": config.max_warm,
                "max_total": config.max_total,
                "active_vms": stats.active_vms,
                "warm_vms": stats.warm_vms
            }))?
        );
    } else {
        println!("VM Pool Status");
        println!("{}", "=".repeat(30));
        println!("Configuration:");
        println!("  Max warm VMs: {}", config.max_warm);
        println!("  Max total VMs: {}", config.max_total);
        println!();
        println!("Current state:");
        println!("  Active VMs: {}", stats.active_vms);
        println!("  Warm VMs:   {}", stats.warm_vms);
    }

    Ok(())
}

/// Load a program in an isolated MicroVM.
pub async fn load_isolated(
    path: &std::path::Path,
    program_name: Option<&str>,
    json_output: bool,
) -> Result<()> {
    // Check if VM environment is ready
    let data_dir = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ebpf-assist");

    let firecracker_path = data_dir.join("firecracker");
    let kernel_path = data_dir.join("vmlinux");
    let rootfs_path = data_dir.join("rootfs.ext4");

    if !firecracker_path.is_file() || !kernel_path.is_file() || !rootfs_path.is_file() {
        bail!(
            "MicroVM environment not set up.\n\n\
             Run: ./scripts/vm/setup-vm.sh\n\n\
             Or use 'ebpf-assist vm init' to check status."
        );
    }

    if !std::path::Path::new("/dev/kvm").exists() {
        bail!(
            "KVM not available. MicroVM isolation requires KVM.\n\n\
             Options:\n\
             1. Enable KVM: modprobe kvm && modprobe kvm_intel\n\
             2. Use non-isolated mode: ebpf-assist load {} (without --isolate)",
            path.display()
        );
    }

    // Read the program bytes
    let program_bytes = std::fs::read(path).with_context(|| {
        format!("Failed to read program file: {}", path.display())
    })?;

    let program_name_str = program_name
        .map(String::from)
        .unwrap_or_else(|| {
            path.file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "program".to_string())
        });

    // Create VM manager and acquire a VM
    let config = PoolConfig::default();
    let manager = MicroVmManager::new(config);

    if !json_output {
        println!("Acquiring MicroVM...");
    }

    let vm_id = manager.acquire().await.context("Failed to acquire MicroVM")?;

    if !json_output {
        println!("VM acquired: {}", vm_id);
        println!("Sending program to guest agent...");
    }

    // Load program using the manager's convenience method
    let (prog_id, info) = manager
        .load_program(&vm_id, program_bytes, program_name_str.clone())
        .await
        .context("Failed to load program in VM")?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "success": true,
                "isolated": true,
                "vm_id": vm_id.to_string(),
                "program_id": prog_id.0,
                "name": info.name,
                "type": format!("{:?}", info.program_type)
            }))?
        );
    } else {
        println!();
        println!("Loaded program in isolated MicroVM:");
        println!("  VM ID:   {}", vm_id);
        println!("  Prog ID: {}", prog_id.0);
        println!("  Name:    {}", info.name);
        println!("  Type:    {:?}", info.program_type);
        println!();
        println!("The program is running in a separate kernel.");
        println!("Any crashes will not affect your host system.");
        println!();
        println!("Next: ebpf-assist attach {} <target>", prog_id.0);
        println!("Stop VM: ebpf-assist vm stop {}", vm_id);
    }

    Ok(())
}
