//! Command handler for the guest agent.

use crate::loader::ProgramLoader;
use crate::protocol::{GuestCommand, GuestResponse};
use crate::trigger::TriggerExecutor;
use std::time::Instant;
use tracing::{info, warn};

/// Handler for guest commands.
pub struct CommandHandler {
    /// Program loader.
    loader: ProgramLoader,
    /// Trigger executor.
    trigger: TriggerExecutor,
    /// Start time for uptime calculation.
    start_time: Instant,
    /// Trace buffer.
    trace_buffer: Vec<String>,
}

impl CommandHandler {
    /// Create a new handler.
    pub fn new(start_time: Instant) -> Self {
        Self {
            loader: ProgramLoader::new(),
            trigger: TriggerExecutor::new(),
            start_time,
            trace_buffer: Vec::new(),
        }
    }

    /// Handle a command.
    pub async fn handle(&mut self, command: GuestCommand) -> GuestResponse {
        match command {
            GuestCommand::Ping => GuestResponse::Pong,

            GuestCommand::Status => GuestResponse::Status {
                uptime_secs: self.start_time.elapsed().as_secs(),
                programs_loaded: self.loader.count(),
            },

            GuestCommand::Load { program_bytes, name } => {
                match self.loader.load(&program_bytes, name) {
                    Ok((id, info)) => GuestResponse::Loaded { id, info },
                    Err(e) => GuestResponse::error(e.to_string()),
                }
            }

            GuestCommand::Unload { id } => match self.loader.unload(id) {
                Ok(()) => GuestResponse::Unloaded,
                Err(e) => GuestResponse::error(e.to_string()),
            },

            GuestCommand::Attach { id, target } => match self.loader.attach(id, &target) {
                Ok(()) => GuestResponse::Attached,
                Err(e) => GuestResponse::error(e.to_string()),
            },

            GuestCommand::Detach { id } => match self.loader.detach(id) {
                Ok(()) => GuestResponse::Detached,
                Err(e) => GuestResponse::error(e.to_string()),
            },

            GuestCommand::List => GuestResponse::Programs(self.loader.list()),

            GuestCommand::Trigger {
                category,
                operation,
                args,
            } => match self.trigger.execute(&category, &operation, &args).await {
                Ok(output) => GuestResponse::Triggered { output },
                Err(e) => GuestResponse::error(e.to_string()),
            },

            GuestCommand::ReadTrace { lines, timeout_ms } => {
                // Read from trace_pipe with timeout
                let output = self.read_trace_pipe(lines as usize, timeout_ms).await;
                GuestResponse::TraceOutput { lines: output }
            }

            GuestCommand::MapList { program_id } => match self.loader.list_maps(program_id) {
                Ok(maps) => GuestResponse::MapList { maps },
                Err(e) => GuestResponse::error(e.to_string()),
            },

            GuestCommand::MapRead {
                program_id,
                map_name,
                key,
            } => {
                // Map operations would need more complex implementation
                // For now, return empty entries
                GuestResponse::MapEntries { entries: vec![] }
            }

            GuestCommand::MapWrite {
                program_id,
                map_name,
                key,
                value,
            } => {
                // Map write would need implementation
                GuestResponse::MapWritten
            }

            GuestCommand::MapDelete {
                program_id,
                map_name,
                key,
            } => {
                // Map delete would need implementation
                GuestResponse::MapDeleted
            }

            GuestCommand::UnloadAll => {
                let count = self.loader.unload_all();
                GuestResponse::UnloadedAll { count }
            }

            GuestCommand::Reset => {
                self.loader.unload_all();
                self.trace_buffer.clear();
                GuestResponse::ResetComplete
            }

            GuestCommand::Shutdown => {
                info!("Shutdown requested");
                GuestResponse::ShuttingDown
            }
        }
    }

    /// Read from trace_pipe with timeout.
    async fn read_trace_pipe(&mut self, max_lines: usize, timeout_ms: u32) -> Vec<String> {
        use tokio::fs::File;
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::time::{timeout, Duration};

        let timeout_duration = Duration::from_millis(timeout_ms as u64);

        let result = timeout(timeout_duration, async {
            let mut lines = Vec::new();

            // Try to open trace_pipe
            let file = match File::open("/sys/kernel/debug/tracing/trace_pipe").await {
                Ok(f) => f,
                Err(e) => {
                    warn!(error = %e, "Failed to open trace_pipe");
                    return lines;
                }
            };

            let mut reader = BufReader::new(file);
            let mut line = String::new();

            while lines.len() < max_lines {
                line.clear();
                match tokio::time::timeout(
                    Duration::from_millis(100),
                    reader.read_line(&mut line),
                )
                .await
                {
                    Ok(Ok(0)) => break, // EOF
                    Ok(Ok(_)) => {
                        let trimmed = line.trim().to_string();
                        if !trimmed.is_empty() {
                            lines.push(trimmed);
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(error = %e, "Error reading trace_pipe");
                        break;
                    }
                    Err(_) => {
                        // Timeout on single line read, check if we have enough
                        if !lines.is_empty() {
                            break;
                        }
                    }
                }
            }

            lines
        })
        .await;

        result.unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_new() {
        let handler = CommandHandler::new(Instant::now());
        // Just verify it can be created
    }

    #[tokio::test]
    async fn test_ping() {
        let mut handler = CommandHandler::new(Instant::now());
        let response = handler.handle(GuestCommand::Ping).await;
        assert!(matches!(response, GuestResponse::Pong));
    }

    #[tokio::test]
    async fn test_status() {
        let mut handler = CommandHandler::new(Instant::now());
        let response = handler.handle(GuestCommand::Status).await;
        match response {
            GuestResponse::Status {
                uptime_secs,
                programs_loaded,
            } => {
                assert_eq!(programs_loaded, 0);
            }
            _ => panic!("Expected Status response"),
        }
    }

    #[tokio::test]
    async fn test_list_empty() {
        let mut handler = CommandHandler::new(Instant::now());
        let response = handler.handle(GuestCommand::List).await;
        match response {
            GuestResponse::Programs(programs) => {
                assert!(programs.is_empty());
            }
            _ => panic!("Expected Programs response"),
        }
    }
}
