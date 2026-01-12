//! Guest agent for ebpf-assist MicroVM.
//!
//! This agent runs inside a Firecracker VM and handles eBPF operations
//! requested by the host over vsock. It provides kernel isolation for
//! safe experimentation with eBPF programs.

mod handler;
mod loader;
mod protocol;
mod trigger;

use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use tracing::{error, info, warn};

use handler::CommandHandler;
use protocol::{GuestCommand, GuestResponse, MAX_MESSAGE_SIZE};

/// Default vsock port for the agent.
const VSOCK_PORT: u32 = 5000;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("ebpf-assist guest agent starting");

    // Create handler
    let start_time = Instant::now();
    let handler = Arc::new(Mutex::new(CommandHandler::new(start_time)));

    // Bind to vsock
    let addr = VsockAddr::new(VMADDR_CID_ANY, VSOCK_PORT);
    let mut listener = VsockListener::bind(addr)?;
    info!(port = VSOCK_PORT, "Listening on vsock");

    // Accept connections
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!(cid = addr.cid(), port = addr.port(), "New connection");
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, handler).await {
                        error!(error = %e, "Connection handler error");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "Accept error");
            }
        }
    }
}

/// Handle a single vsock connection.
async fn handle_connection(
    mut stream: VsockStream,
    handler: Arc<Mutex<CommandHandler>>,
) -> Result<()> {
    loop {
        // Read message length (4 bytes, little-endian)
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                info!("Connection closed");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }

        let msg_len = u32::from_le_bytes(len_buf) as usize;

        if msg_len > MAX_MESSAGE_SIZE {
            warn!(size = msg_len, max = MAX_MESSAGE_SIZE, "Message too large");
            let response = GuestResponse::error("Message too large");
            send_response(&mut stream, &response).await?;
            continue;
        }

        // Read message payload
        let mut payload = vec![0u8; msg_len];
        stream.read_exact(&mut payload).await?;

        // Parse command
        let command: GuestCommand = match serde_json::from_slice(&payload) {
            Ok(cmd) => cmd,
            Err(e) => {
                warn!(error = %e, "Failed to parse command");
                let response = GuestResponse::error(format!("Invalid command: {}", e));
                send_response(&mut stream, &response).await?;
                continue;
            }
        };

        // Check for shutdown
        let is_shutdown = matches!(command, GuestCommand::Shutdown);

        // Handle command
        let response = {
            let mut h = handler.lock().await;
            h.handle(command).await
        };

        // Send response
        send_response(&mut stream, &response).await?;

        // Exit if shutdown requested
        if is_shutdown {
            info!("Shutdown requested, exiting");
            std::process::exit(0);
        }
    }
}

/// Send a response over the stream.
async fn send_response(stream: &mut VsockStream, response: &GuestResponse) -> Result<()> {
    let payload = serde_json::to_vec(response)?;

    // Send length prefix
    let len_bytes = (payload.len() as u32).to_le_bytes();
    stream.write_all(&len_bytes).await?;

    // Send payload
    stream.write_all(&payload).await?;
    stream.flush().await?;

    Ok(())
}
