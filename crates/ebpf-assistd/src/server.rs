//! Unix socket server for the daemon.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use ebpf_assist_common::{Request, Response};

use crate::handler::{handle_request, State};

/// Run the daemon server.
pub async fn run(socket_path: impl AsRef<Path>) -> Result<()> {
    let socket_path = socket_path.as_ref();

    let listener = UnixListener::bind(socket_path).context("Failed to bind to socket")?;

    // Make socket accessible
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    }

    info!("Listening on {}", socket_path.display());

    let state = Arc::new(Mutex::new(State::new()));

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, state).await {
                        error!("Error handling client: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

/// Handle a single client connection.
async fn handle_client(stream: UnixStream, state: Arc<Mutex<State>>) -> Result<()> {
    debug!("New client connected");

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            debug!("Client disconnected");
            break;
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        debug!("Received: {}", line);

        // Parse request
        let response = match serde_json::from_str::<Request>(line) {
            Ok(request) => handle_request(Arc::clone(&state), request).await,
            Err(e) => {
                warn!("Invalid request: {}", e);
                Response::Error {
                    message: format!("Invalid request: {}", e),
                    code: ebpf_assist_common::ErrorCode::InvalidRequest,
                }
            }
        };

        // Send response
        let response_json = serde_json::to_string(&response)?;
        debug!("Sending: {}", response_json);
        writer.write_all(response_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}
