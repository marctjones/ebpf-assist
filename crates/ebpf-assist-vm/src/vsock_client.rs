//! vsock client for communication with guest agent.

use crate::error::{VmError, VmResult};
use crate::protocol::{GuestCommand, GuestResponse, MAX_MESSAGE_SIZE};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::{debug, trace};

/// Client for communicating with the guest agent over vsock.
pub struct GuestClient {
    /// Unix socket connected to Firecracker's vsock.
    stream: UnixStream,
}

impl GuestClient {
    /// Connect to the guest agent via vsock UDS.
    pub async fn connect(vsock_path: &Path) -> VmResult<Self> {
        // Firecracker exposes vsock as a Unix socket
        // We connect and send the guest port as the first message
        let stream = UnixStream::connect(vsock_path).await?;

        let mut client = Self { stream };

        // Send "CONNECT <port>\n" to initiate vsock connection
        // Port 5000 is where our guest agent listens
        client.stream.write_all(b"CONNECT 5000\n").await?;

        // Read the "OK <local_port>\n" response
        let mut buf = [0u8; 64];
        let n = client.stream.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);

        if !response.starts_with("OK") {
            return Err(VmError::Vsock(format!(
                "Failed to connect to guest: {}",
                response.trim()
            )));
        }

        debug!("Connected to guest agent via vsock");
        Ok(client)
    }

    /// Send a command and receive a response.
    pub async fn send_command(&mut self, command: GuestCommand) -> VmResult<GuestResponse> {
        // Serialize command
        let payload = serde_json::to_vec(&command)?;

        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(VmError::Vsock(format!(
                "Message too large: {} bytes (max {})",
                payload.len(),
                MAX_MESSAGE_SIZE
            )));
        }

        trace!(
            command = ?command,
            size = payload.len(),
            "Sending command to guest"
        );

        // Send length prefix (4 bytes, little-endian)
        let len_bytes = (payload.len() as u32).to_le_bytes();
        self.stream.write_all(&len_bytes).await?;

        // Send payload
        self.stream.write_all(&payload).await?;
        self.stream.flush().await?;

        // Read response length
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let response_len = u32::from_le_bytes(len_buf) as usize;

        if response_len > MAX_MESSAGE_SIZE {
            return Err(VmError::Vsock(format!(
                "Response too large: {} bytes (max {})",
                response_len,
                MAX_MESSAGE_SIZE
            )));
        }

        // Read response payload
        let mut response_buf = vec![0u8; response_len];
        self.stream.read_exact(&mut response_buf).await?;

        // Deserialize response
        let response: GuestResponse = serde_json::from_slice(&response_buf)?;

        trace!(response = ?response, "Received response from guest");
        Ok(response)
    }

    /// Send a command with timeout.
    pub async fn send_command_timeout(
        &mut self,
        command: GuestCommand,
        timeout: std::time::Duration,
    ) -> VmResult<GuestResponse> {
        tokio::time::timeout(timeout, self.send_command(command))
            .await
            .map_err(|_| VmError::AgentTimeout)?
    }

    /// Ping the guest agent.
    pub async fn ping(&mut self) -> VmResult<()> {
        match self.send_command(GuestCommand::Ping).await? {
            GuestResponse::Pong => Ok(()),
            GuestResponse::Error { message, .. } => Err(VmError::Vsock(message)),
            other => Err(VmError::Vsock(format!("Unexpected response: {:?}", other))),
        }
    }

    /// Get agent status.
    pub async fn status(&mut self) -> VmResult<(u64, usize)> {
        match self.send_command(GuestCommand::Status).await? {
            GuestResponse::Status {
                uptime_secs,
                programs_loaded,
            } => Ok((uptime_secs, programs_loaded)),
            GuestResponse::Error { message, .. } => Err(VmError::Vsock(message)),
            other => Err(VmError::Vsock(format!("Unexpected response: {:?}", other))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_message_size() {
        assert_eq!(MAX_MESSAGE_SIZE, 16 * 1024 * 1024);
    }

    #[test]
    fn test_length_encoding() {
        let len: u32 = 1000;
        let bytes = len.to_le_bytes();
        let decoded = u32::from_le_bytes(bytes);
        assert_eq!(len, decoded);
    }
}
