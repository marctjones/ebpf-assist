//! Client for communicating with ebpf-assistd.

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::debug;

use ebpf_assist_common::{user_socket_path, Request, Response};

/// Client for the daemon.
pub struct Client {
    stream: BufReader<UnixStream>,
}

impl Client {
    /// Connect to the daemon.
    pub async fn connect() -> Result<Self> {
        let socket_path = user_socket_path();
        debug!("Connecting to {}", socket_path.display());

        let stream = UnixStream::connect(&socket_path).await.with_context(|| {
            format!(
                "Failed to connect to daemon at {}. Is ebpf-assistd running?",
                socket_path.display()
            )
        })?;

        Ok(Self {
            stream: BufReader::new(stream),
        })
    }

    /// Send a request and receive a response.
    pub async fn request(&mut self, request: Request) -> Result<Response> {
        let request_json = serde_json::to_string(&request)?;
        debug!("Sending: {}", request_json);

        self.stream
            .get_mut()
            .write_all(request_json.as_bytes())
            .await?;
        self.stream.get_mut().write_all(b"\n").await?;
        self.stream.get_mut().flush().await?;

        let mut response_line = String::new();
        self.stream.read_line(&mut response_line).await?;

        debug!("Received: {}", response_line.trim());

        let response: Response =
            serde_json::from_str(&response_line).context("Failed to parse response from daemon")?;

        Ok(response)
    }
}
