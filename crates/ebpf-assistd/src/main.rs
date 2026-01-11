//! ebpf-assistd - Daemon for loading eBPF programs with minimal privileges.

mod caps;
mod handler;
mod loader;
mod server;

use anyhow::Result;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use ebpf_assist_common::user_socket_path;

#[tokio::main]
async fn main() -> Result<()> {
    // Set up logging
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    info!("ebpf-assistd starting...");

    // Determine socket path
    let socket_path = user_socket_path();
    info!("Using socket: {}", socket_path.display());

    // Create parent directory if needed
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Remove stale socket if it exists
    if socket_path.exists() {
        tokio::fs::remove_file(&socket_path).await?;
    }

    // Start the server
    server::run(socket_path).await
}
