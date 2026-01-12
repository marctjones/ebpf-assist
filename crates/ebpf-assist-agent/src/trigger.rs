//! Trigger executor for generating test activity.

use std::process::Command;
use thiserror::Error;
use tracing::{debug, info};

/// Errors from trigger execution.
#[derive(Debug, Error)]
pub enum TriggerError {
    #[error("Unknown category: {0}")]
    UnknownCategory(String),

    #[error("Unknown operation: {0}/{1}")]
    UnknownOperation(String, String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
}

/// Executor for trigger operations.
pub struct TriggerExecutor {
    // Could hold state if needed
}

impl TriggerExecutor {
    /// Create a new executor.
    pub fn new() -> Self {
        Self {}
    }

    /// Execute a trigger.
    pub async fn execute(
        &self,
        category: &str,
        operation: &str,
        args: &[String],
    ) -> Result<String, TriggerError> {
        info!(category = category, operation = operation, "Executing trigger");

        match category {
            "fs" => self.execute_fs(operation, args).await,
            "net" => self.execute_net(operation, args).await,
            "process" => self.execute_process(operation, args).await,
            "syscall" => self.execute_syscall(operation, args).await,
            _ => Err(TriggerError::UnknownCategory(category.to_string())),
        }
    }

    /// Execute filesystem triggers.
    async fn execute_fs(&self, operation: &str, args: &[String]) -> Result<String, TriggerError> {
        match operation {
            "open" => {
                let path = args.first().map(|s| s.as_str()).unwrap_or("/tmp/test");
                // Open and close a file
                let _ = std::fs::File::create(path);
                Ok(format!("Opened file: {}", path))
            }
            "read" => {
                let path = args.first().map(|s| s.as_str()).unwrap_or("/etc/hostname");
                let content = std::fs::read_to_string(path)
                    .map_err(|e| TriggerError::ExecutionFailed(e.to_string()))?;
                Ok(format!("Read {} bytes from {}", content.len(), path))
            }
            "write" => {
                let path = args.first().map(|s| s.as_str()).unwrap_or("/tmp/test");
                let data = args.get(1).map(|s| s.as_str()).unwrap_or("test data");
                std::fs::write(path, data)
                    .map_err(|e| TriggerError::ExecutionFailed(e.to_string()))?;
                Ok(format!("Wrote {} bytes to {}", data.len(), path))
            }
            "stat" => {
                let path = args.first().map(|s| s.as_str()).unwrap_or("/");
                let meta = std::fs::metadata(path)
                    .map_err(|e| TriggerError::ExecutionFailed(e.to_string()))?;
                Ok(format!("Stat {}: {} bytes", path, meta.len()))
            }
            _ => Err(TriggerError::UnknownOperation(
                "fs".to_string(),
                operation.to_string(),
            )),
        }
    }

    /// Execute network triggers.
    async fn execute_net(&self, operation: &str, args: &[String]) -> Result<String, TriggerError> {
        match operation {
            "connect" => {
                let addr = args.first().map(|s| s.as_str()).unwrap_or("127.0.0.1:80");
                // Try to connect (will likely fail but triggers syscall)
                let result = std::net::TcpStream::connect(addr);
                match result {
                    Ok(_) => Ok(format!("Connected to {}", addr)),
                    Err(e) => Ok(format!("Connection attempt to {} failed: {}", addr, e)),
                }
            }
            "dns" => {
                let host = args.first().map(|s| s.as_str()).unwrap_or("localhost");
                // Resolve hostname
                use std::net::ToSocketAddrs;
                let result = format!("{}:80", host).to_socket_addrs();
                match result {
                    Ok(addrs) => {
                        let addrs: Vec<_> = addrs.collect();
                        Ok(format!("Resolved {} to {:?}", host, addrs))
                    }
                    Err(e) => Ok(format!("DNS resolution for {} failed: {}", host, e)),
                }
            }
            "listen" => {
                let port: u16 = args.first().and_then(|s| s.parse().ok()).unwrap_or(0);
                let listener = std::net::TcpListener::bind(format!("127.0.0.1:{}", port))
                    .map_err(|e| TriggerError::ExecutionFailed(e.to_string()))?;
                let local_addr = listener.local_addr().unwrap();
                Ok(format!("Listening on {}", local_addr))
            }
            _ => Err(TriggerError::UnknownOperation(
                "net".to_string(),
                operation.to_string(),
            )),
        }
    }

    /// Execute process triggers.
    async fn execute_process(
        &self,
        operation: &str,
        args: &[String],
    ) -> Result<String, TriggerError> {
        match operation {
            "exec" => {
                let cmd = args.first().map(|s| s.as_str()).unwrap_or("true");
                let output = Command::new(cmd)
                    .args(&args[1..])
                    .output()
                    .map_err(|e| TriggerError::ExecutionFailed(e.to_string()))?;
                Ok(format!(
                    "Executed {}: exit code {}",
                    cmd,
                    output.status.code().unwrap_or(-1)
                ))
            }
            "fork" => {
                // Fork via a simple command
                let output = Command::new("true")
                    .output()
                    .map_err(|e| TriggerError::ExecutionFailed(e.to_string()))?;
                Ok("Forked child process".to_string())
            }
            "sleep" => {
                let ms: u64 = args.first().and_then(|s| s.parse().ok()).unwrap_or(100);
                std::thread::sleep(std::time::Duration::from_millis(ms));
                Ok(format!("Slept for {}ms", ms))
            }
            _ => Err(TriggerError::UnknownOperation(
                "process".to_string(),
                operation.to_string(),
            )),
        }
    }

    /// Execute syscall triggers.
    async fn execute_syscall(
        &self,
        operation: &str,
        args: &[String],
    ) -> Result<String, TriggerError> {
        match operation {
            "getpid" => {
                let pid = std::process::id();
                Ok(format!("PID: {}", pid))
            }
            "getuid" => {
                let uid = unsafe { libc::getuid() };
                Ok(format!("UID: {}", uid))
            }
            "time" => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                Ok(format!("Time: {}", now))
            }
            "uname" => {
                let output = Command::new("uname")
                    .arg("-a")
                    .output()
                    .map_err(|e| TriggerError::ExecutionFailed(e.to_string()))?;
                Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
            }
            _ => Err(TriggerError::UnknownOperation(
                "syscall".to_string(),
                operation.to_string(),
            )),
        }
    }
}

impl Default for TriggerExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fs_stat() {
        let executor = TriggerExecutor::new();
        let result = executor.execute("fs", "stat", &["/".to_string()]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_syscall_getpid() {
        let executor = TriggerExecutor::new();
        let result = executor.execute("syscall", "getpid", &[]).await;
        assert!(result.is_ok());
        assert!(result.unwrap().contains("PID:"));
    }

    #[tokio::test]
    async fn test_unknown_category() {
        let executor = TriggerExecutor::new();
        let result = executor.execute("unknown", "op", &[]).await;
        assert!(matches!(result, Err(TriggerError::UnknownCategory(_))));
    }
}
