//! CLI command implementations.

use std::path::Path;

use anyhow::{bail, Result};

use ebpf_assist_common::{ProgramId, Request, Response};

use crate::client::Client;

/// Load an eBPF program.
pub async fn load(path: &Path, program_name: Option<&str>) -> Result<()> {
    let path = path.canonicalize()?;
    let mut client = Client::connect().await?;

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
        } => {
            println!("Loaded program:");
            println!("  ID:   {}", id.0);
            println!("  Name: {}", name);
            println!("  Type: {:?}", program_type);
            Ok(())
        }
        Response::Error { message, code } => {
            bail!("[{:?}] {}", code, message);
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Unload a program.
pub async fn unload(id: u32) -> Result<()> {
    let mut client = Client::connect().await?;

    let response = client
        .request(Request::Unload {
            id: ProgramId(id),
        })
        .await?;

    match response {
        Response::Unloaded { id } => {
            println!("Unloaded program {}", id.0);
            Ok(())
        }
        Response::Error { message, code } => {
            bail!("[{:?}] {}", code, message);
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Attach a program to a target.
pub async fn attach(id: u32, target: &str) -> Result<()> {
    let mut client = Client::connect().await?;

    let response = client
        .request(Request::Attach {
            id: ProgramId(id),
            target: target.to_string(),
        })
        .await?;

    match response {
        Response::Attached { id, target } => {
            println!("Attached program {} to {}", id.0, target);
            Ok(())
        }
        Response::Error { message, code } => {
            bail!("[{:?}] {}", code, message);
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Detach a program.
pub async fn detach(id: u32) -> Result<()> {
    let mut client = Client::connect().await?;

    let response = client
        .request(Request::Detach {
            id: ProgramId(id),
        })
        .await?;

    match response {
        Response::Detached { id } => {
            println!("Detached program {}", id.0);
            Ok(())
        }
        Response::Error { message, code } => {
            bail!("[{:?}] {}", code, message);
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// List all loaded programs.
pub async fn list() -> Result<()> {
    let mut client = Client::connect().await?;

    let response = client.request(Request::List).await?;

    match response {
        Response::Programs { programs } => {
            if programs.is_empty() {
                println!("No programs loaded");
            } else {
                println!("{:<6} {:<20} {:<15} {:<10} {}", "ID", "NAME", "TYPE", "ATTACHED", "TARGET");
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
            bail!("[{:?}] {}", code, message);
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Show daemon status.
pub async fn status() -> Result<()> {
    let mut client = Client::connect().await?;

    let response = client.request(Request::Status).await?;

    match response {
        Response::Status {
            version,
            uptime_secs,
            programs_loaded,
            capabilities,
        } => {
            println!("ebpf-assistd status:");
            println!("  Version:         {}", version);
            println!("  Uptime:          {}s", uptime_secs);
            println!("  Programs loaded: {}", programs_loaded);
            println!("  Capabilities:    {}", capabilities.join(", "));
            Ok(())
        }
        Response::Error { message, code } => {
            bail!("[{:?}] {}", code, message);
        }
        _ => bail!("Unexpected response from daemon"),
    }
}

/// Check if daemon is running.
pub async fn ping() -> Result<()> {
    let mut client = Client::connect().await?;

    let response = client.request(Request::Ping).await?;

    match response {
        Response::Pong => {
            println!("Daemon is running");
            Ok(())
        }
        Response::Error { message, code } => {
            bail!("[{:?}] {}", code, message);
        }
        _ => bail!("Unexpected response from daemon"),
    }
}
