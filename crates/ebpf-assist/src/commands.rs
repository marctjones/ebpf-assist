//! CLI command implementations.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::json;

use ebpf_assist_common::{ErrorCode, ProgramId, Request, Response};

use crate::client::Client;

/// Improved error messages for common failures.
fn improve_error(code: ErrorCode, message: &str) -> String {
    let mut improved = format!("[{:?}] {}", code, message);

    match code {
        ErrorCode::NotFound => {
            if message.contains("program") {
                improved
                    .push_str("\n\n💡 Suggestion: Use 'ebpf-assist list' to see loaded programs.");
            } else if message.contains("not found") {
                improved.push_str("\n\n💡 File not found. Did you compile the program?");
                improved.push_str("\n   Run: ebpf-assist compile <source.c>");
            }
        }
        ErrorCode::ProgramNotFound => {
            improved.push_str("\n\n💡 Suggestion: Use 'ebpf-assist list' to see loaded programs.");
        }
        ErrorCode::AuthRequired => {
            improved.push_str("\n\n💡 Run 'ebpf-assist unlock' to authenticate.");
            improved.push_str("\n   This will prompt for your password (cached for 15 minutes).");
        }
        ErrorCode::AuthDenied => {
            improved.push_str("\n\n💡 Authentication was denied. Make sure you have permission to manage eBPF programs.");
        }
        ErrorCode::VerifierError => {
            improved.push_str("\n\n💡 BPF verifier rejected the program. Common issues:");
            improved.push_str("\n   - Unbounded loops (use bounded loops with #pragma unroll)");
            improved.push_str("\n   - Null pointer dereference (add null checks)");
            improved.push_str("\n   - Out-of-bounds access (check array bounds)");
            improved.push_str("\n   - Uninitialized variables (initialize before use)");
        }
        ErrorCode::PermissionDenied => {
            if message.contains("kprobe") || message.contains("function") {
                improved.push_str("\n\n💡 Kprobe attach failed. Common issues:");
                improved.push_str("\n   - Function doesn't exist: check /proc/kallsyms");
                improved.push_str("\n   - Try with __x64_sys_ prefix for syscalls");
                improved.push_str("\n   - Example: 'do_sys_openat2' or '__x64_sys_openat'");
            } else if message.contains("tracepoint") {
                improved.push_str("\n\n💡 Tracepoint attach failed. Format: category:name");
                improved.push_str("\n   Available: ls /sys/kernel/debug/tracing/events/");
                improved.push_str("\n   Example: 'syscalls:sys_enter_openat'");
            } else if message.contains("xdp") || message.contains("interface") {
                improved.push_str("\n\n💡 XDP attach failed. Make sure:");
                improved.push_str("\n   - Interface exists: ip link show");
                improved.push_str("\n   - Interface supports XDP: not all do");
            }
        }
        ErrorCode::AlreadyAttached => {
            improved.push_str(
                "\n\n💡 Program is already attached. Detach first with: ebpf-assist detach <id>",
            );
        }
        ErrorCode::NotAttached => {
            improved.push_str("\n\n💡 Program is not attached. Attach first with: ebpf-assist attach <id> <target>");
        }
        ErrorCode::PolicyViolation => {
            improved.push_str("\n\n💡 This program type is blocked by security policy.");
            improved.push_str(
                "\n   Allowed types: kprobe, kretprobe, uprobe, uretprobe, tracepoint, perf_event",
            );
            improved.push_str("\n   Warn types: xdp, tc, socket_filter");
            improved.push_str("\n   Blocked: lsm, struct_ops, cgroup");
        }
        _ => {}
    }

    improved
}

/// Load an eBPF program.
pub async fn load(path: &Path, program_name: Option<&str>, json_output: bool) -> Result<()> {
    let path = path.canonicalize().with_context(|| {
        format!(
            "File not found: {}\n\n💡 Did you compile the program?\n   Run: ebpf-assist compile <source.c>",
            path.display()
        )
    })?;

    let mut client = Client::connect().await.with_context(|| {
        "Failed to connect to daemon.\n\n💡 Is ebpf-assistd running?\n   Start with: ebpf-assistd\n   Or: systemctl start ebpf-assistd@$USER"
    })?;

    let response = client
        .request(Request::Load {
            path: path.clone(),
            program_name: program_name.map(String::from),
        })
        .await?;

    match response {
        Response::Loaded {
            id,
            name,
            program_type,
            warning,
        } => {
            if json_output {
                let mut result = json!({
                    "success": true,
                    "id": id.0,
                    "name": name,
                    "type": format!("{:?}", program_type)
                });
                if let Some(ref w) = warning {
                    result["warning"] = serde_json::Value::String(w.clone());
                }
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                // Show warning first if present
                if let Some(ref w) = warning {
                    eprintln!("\n⚠️  {}\n", w);
                }
                println!("Loaded program:");
                println!("  ID:   {}", id.0);
                println!("  Name: {}", name);
                println!("  Type: {:?}", program_type);
                println!("\nNext: ebpf-assist attach {} <target>", id.0);
            }
            Ok(())
        }
        Response::Error { message, code } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": false,
                        "error": message,
                        "code": format!("{:?}", code)
                    }))?
                );
                std::process::exit(1);
            } else {
                bail!("{}", improve_error(code, &message));
            }
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Unload a program.
pub async fn unload(id: u32, json_output: bool) -> Result<()> {
    let mut client = Client::connect()
        .await
        .with_context(|| "Failed to connect to daemon. Is ebpf-assistd running?")?;

    let response = client
        .request(Request::Unload { id: ProgramId(id) })
        .await?;

    match response {
        Response::Unloaded { id } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": true,
                        "id": id.0
                    }))?
                );
            } else {
                println!("Unloaded program {}", id.0);
            }
            Ok(())
        }
        Response::Error { message, code } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": false,
                        "error": message,
                        "code": format!("{:?}", code)
                    }))?
                );
                std::process::exit(1);
            } else {
                bail!("{}", improve_error(code, &message));
            }
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Attach a program to a target.
pub async fn attach(id: u32, target: &str, json_output: bool) -> Result<()> {
    let mut client = Client::connect()
        .await
        .with_context(|| "Failed to connect to daemon. Is ebpf-assistd running?")?;

    let response = client
        .request(Request::Attach {
            id: ProgramId(id),
            target: target.to_string(),
        })
        .await?;

    match response {
        Response::Attached { id, target } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": true,
                        "id": id.0,
                        "target": target
                    }))?
                );
            } else {
                println!("Attached program {} to {}", id.0, target);
                println!("\nNext steps:");
                println!("  1. Trigger activity: ebpf-assist trigger syscall openat /tmp/test");
                println!("  2. Read output: ebpf-assist output trace");
            }
            Ok(())
        }
        Response::Error { message, code } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": false,
                        "error": message,
                        "code": format!("{:?}", code)
                    }))?
                );
                std::process::exit(1);
            } else {
                bail!("{}", improve_error(code, &message));
            }
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Detach a program.
pub async fn detach(id: u32, json_output: bool) -> Result<()> {
    let mut client = Client::connect()
        .await
        .with_context(|| "Failed to connect to daemon. Is ebpf-assistd running?")?;

    let response = client
        .request(Request::Detach { id: ProgramId(id) })
        .await?;

    match response {
        Response::Detached { id } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": true,
                        "id": id.0
                    }))?
                );
            } else {
                println!("Detached program {}", id.0);
            }
            Ok(())
        }
        Response::Error { message, code } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": false,
                        "error": message,
                        "code": format!("{:?}", code)
                    }))?
                );
                std::process::exit(1);
            } else {
                bail!("{}", improve_error(code, &message));
            }
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// List all loaded programs.
pub async fn list(json_output: bool) -> Result<()> {
    let mut client = Client::connect()
        .await
        .with_context(|| "Failed to connect to daemon. Is ebpf-assistd running?")?;

    let response = client.request(Request::List).await?;

    match response {
        Response::Programs { programs } => {
            if json_output {
                let progs: Vec<_> = programs
                    .iter()
                    .map(|p| {
                        json!({
                            "id": p.id.0,
                            "name": p.name,
                            "type": format!("{:?}", p.program_type),
                            "attached": p.attached,
                            "target": p.attach_point
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "programs": progs
                    }))?
                );
            } else if programs.is_empty() {
                println!("No programs loaded");
                println!("\n💡 Load a program with: ebpf-assist load <program.o>");
            } else {
                println!(
                    "{:<6} {:<20} {:<15} {:<10} {}",
                    "ID", "NAME", "TYPE", "ATTACHED", "TARGET"
                );
                println!("{}", "-".repeat(70));
                for prog in programs {
                    let attached = if prog.attached { "yes" } else { "no" };
                    let target = prog.attach_point.as_deref().unwrap_or("-");
                    println!(
                        "{:<6} {:<20} {:<15} {:<10} {}",
                        prog.id.0,
                        prog.name,
                        format!("{:?}", prog.program_type),
                        attached,
                        target
                    );
                }
            }
            Ok(())
        }
        Response::Error { message, code } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": false,
                        "error": message,
                        "code": format!("{:?}", code)
                    }))?
                );
                std::process::exit(1);
            } else {
                bail!("{}", improve_error(code, &message));
            }
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Show daemon status.
pub async fn status(json_output: bool) -> Result<()> {
    let mut client = Client::connect()
        .await
        .with_context(|| "Failed to connect to daemon. Is ebpf-assistd running?")?;

    let response = client.request(Request::Status).await?;

    match response {
        Response::Status {
            version,
            uptime_secs,
            programs_loaded,
            capabilities,
        } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "version": version,
                        "uptime_secs": uptime_secs,
                        "programs_loaded": programs_loaded,
                        "capabilities": capabilities
                    }))?
                );
            } else {
                println!("ebpf-assistd status:");
                println!("  Version:         {}", version);
                println!("  Uptime:          {}s", uptime_secs);
                println!("  Programs loaded: {}", programs_loaded);
                println!(
                    "  Capabilities:    {}",
                    if capabilities.is_empty() {
                        "none".to_string()
                    } else {
                        capabilities.join(", ")
                    }
                );
            }
            Ok(())
        }
        Response::Error { message, code } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": false,
                        "error": message,
                        "code": format!("{:?}", code)
                    }))?
                );
                std::process::exit(1);
            } else {
                bail!("{}", improve_error(code, &message));
            }
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Check if daemon is running.
pub async fn ping(json_output: bool) -> Result<()> {
    let mut client = Client::connect()
        .await
        .with_context(|| "Failed to connect to daemon. Is ebpf-assistd running?")?;

    let response = client.request(Request::Ping).await?;

    match response {
        Response::Pong => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "running": true
                    }))?
                );
            } else {
                println!("Daemon is running");
            }
            Ok(())
        }
        Response::Error { message, code } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "running": false,
                        "error": message,
                        "code": format!("{:?}", code)
                    }))?
                );
                std::process::exit(1);
            } else {
                bail!("{}", improve_error(code, &message));
            }
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Request authorization (triggers GUI prompt).
pub async fn unlock(json_output: bool) -> Result<()> {
    let mut client = Client::connect()
        .await
        .with_context(|| "Failed to connect to daemon. Is ebpf-assistd running?")?;

    if !json_output {
        println!("Requesting authorization...");
    }

    let response = client.request(Request::Unlock).await?;

    match response {
        Response::Unlocked => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": true,
                        "authorized": true,
                        "cache_duration_secs": 900
                    }))?
                );
            } else {
                println!("Authorization granted (cached for 15 minutes)");
            }
            Ok(())
        }
        Response::Error { message, code } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": false,
                        "authorized": false,
                        "error": message,
                        "code": format!("{:?}", code)
                    }))?
                );
                std::process::exit(1);
            } else {
                bail!("{}", improve_error(code, &message));
            }
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Clear authorization cache.
pub async fn lock(json_output: bool) -> Result<()> {
    let mut client = Client::connect()
        .await
        .with_context(|| "Failed to connect to daemon. Is ebpf-assistd running?")?;

    let response = client.request(Request::Lock).await?;

    match response {
        Response::Locked => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": true,
                        "authorized": false
                    }))?
                );
            } else {
                println!("Authorization cache cleared");
            }
            Ok(())
        }
        Response::Error { message, code } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": false,
                        "error": message,
                        "code": format!("{:?}", code)
                    }))?
                );
                std::process::exit(1);
            } else {
                bail!("{}", improve_error(code, &message));
            }
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Check authorization status.
pub async fn auth_status(json_output: bool) -> Result<()> {
    let mut client = Client::connect()
        .await
        .with_context(|| "Failed to connect to daemon. Is ebpf-assistd running?")?;

    let response = client.request(Request::AuthStatus).await?;

    match response {
        Response::AuthStatusResult {
            authorized,
            expires_in_secs,
        } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "authorized": authorized,
                        "expires_in_secs": expires_in_secs
                    }))?
                );
            } else if authorized {
                println!("Authorized (expires in {} seconds)", expires_in_secs);
            } else {
                println!("Not authorized");
                println!("\n💡 Run 'ebpf-assist unlock' to authenticate.");
            }
            Ok(())
        }
        Response::Error { message, code } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": false,
                        "error": message,
                        "code": format!("{:?}", code)
                    }))?
                );
                std::process::exit(1);
            } else {
                bail!("{}", improve_error(code, &message));
            }
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// List maps for a loaded program.
pub async fn map_list(id: u32, json_output: bool) -> Result<()> {
    let mut client = Client::connect()
        .await
        .with_context(|| "Failed to connect to daemon. Is ebpf-assistd running?")?;

    let response = client
        .request(Request::MapList { id: ProgramId(id) })
        .await?;

    match response {
        Response::Maps { maps } => {
            if json_output {
                let map_info: Vec<_> = maps
                    .iter()
                    .map(|m| {
                        json!({
                            "name": m.name,
                            "type": format!("{:?}", m.map_type),
                            "key_size": m.key_size,
                            "value_size": m.value_size,
                            "max_entries": m.max_entries
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "program_id": id,
                        "maps": map_info
                    }))?
                );
            } else if maps.is_empty() {
                println!("No maps in program {}", id);
            } else {
                println!("Maps for program {}:", id);
                println!(
                    "{:<20} {:<15} {:<10} {:<10} {}",
                    "NAME", "TYPE", "KEY", "VALUE", "MAX ENTRIES"
                );
                println!("{}", "-".repeat(70));
                for m in maps {
                    println!(
                        "{:<20} {:<15} {:<10} {:<10} {}",
                        m.name,
                        format!("{:?}", m.map_type),
                        m.key_size,
                        m.value_size,
                        m.max_entries
                    );
                }
            }
            Ok(())
        }
        Response::Error { message, code } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": false,
                        "error": message,
                        "code": format!("{:?}", code)
                    }))?
                );
                std::process::exit(1);
            } else {
                bail!("{}", improve_error(code, &message));
            }
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Read map entries.
pub async fn map_read(id: u32, map_name: &str, key: Option<&str>, json_output: bool) -> Result<()> {
    let mut client = Client::connect()
        .await
        .with_context(|| "Failed to connect to daemon. Is ebpf-assistd running?")?;

    let response = client
        .request(Request::MapRead {
            id: ProgramId(id),
            map_name: map_name.to_string(),
            key: key.map(String::from),
        })
        .await?;

    match response {
        Response::MapEntries { map_name, entries } => {
            if json_output {
                let entry_info: Vec<_> = entries
                    .iter()
                    .map(|e| {
                        let mut obj = json!({
                            "key": e.key,
                            "value": e.value
                        });
                        if let Some(v) = e.value_u64 {
                            obj["value_u64"] = json!(v);
                        }
                        if let Some(ref s) = e.value_str {
                            obj["value_str"] = json!(s);
                        }
                        obj
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "map_name": map_name,
                        "entries": entry_info
                    }))?
                );
            } else if entries.is_empty() {
                println!("Map '{}' is empty", map_name);
            } else {
                println!("Map '{}' ({} entries):", map_name, entries.len());
                println!("{:<20} {:<20} {}", "KEY", "VALUE (hex)", "VALUE (dec)");
                println!("{}", "-".repeat(60));
                for e in entries {
                    let dec = e.value_u64.map(|v| v.to_string()).unwrap_or_default();
                    println!("{:<20} {:<20} {}", e.key, e.value, dec);
                }
            }
            Ok(())
        }
        Response::Error { message, code } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": false,
                        "error": message,
                        "code": format!("{:?}", code)
                    }))?
                );
                std::process::exit(1);
            } else {
                bail!("{}", improve_error(code, &message));
            }
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Write to a map.
pub async fn map_write(
    id: u32,
    map_name: &str,
    key: &str,
    value: &str,
    json_output: bool,
) -> Result<()> {
    let mut client = Client::connect()
        .await
        .with_context(|| "Failed to connect to daemon. Is ebpf-assistd running?")?;

    let response = client
        .request(Request::MapWrite {
            id: ProgramId(id),
            map_name: map_name.to_string(),
            key: key.to_string(),
            value: value.to_string(),
        })
        .await?;

    match response {
        Response::MapWritten { map_name, key } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": true,
                        "map_name": map_name,
                        "key": key
                    }))?
                );
            } else {
                println!("Wrote to map '{}' key '{}'", map_name, key);
            }
            Ok(())
        }
        Response::Error { message, code } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": false,
                        "error": message,
                        "code": format!("{:?}", code)
                    }))?
                );
                std::process::exit(1);
            } else {
                bail!("{}", improve_error(code, &message));
            }
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Delete a map entry.
pub async fn map_delete(id: u32, map_name: &str, key: &str, json_output: bool) -> Result<()> {
    let mut client = Client::connect()
        .await
        .with_context(|| "Failed to connect to daemon. Is ebpf-assistd running?")?;

    let response = client
        .request(Request::MapDelete {
            id: ProgramId(id),
            map_name: map_name.to_string(),
            key: key.to_string(),
        })
        .await?;

    match response {
        Response::MapDeleted { map_name, key } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": true,
                        "map_name": map_name,
                        "key": key
                    }))?
                );
            } else {
                println!("Deleted from map '{}' key '{}'", map_name, key);
            }
            Ok(())
        }
        Response::Error { message, code } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "success": false,
                        "error": message,
                        "code": format!("{:?}", code)
                    }))?
                );
                std::process::exit(1);
            } else {
                bail!("{}", improve_error(code, &message));
            }
        }
        _ => bail!("Unexpected response from daemon"),
    }
}
