//! MCP Server for ebpf-assist.
//!
//! Provides tools for AI assistants to manage eBPF programs.
//! Uses JSON-RPC 2.0 over stdio.

mod protocol;
mod tools;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, info};

use protocol::{JsonRpcRequest, JsonRpcResponse, McpMethod};

#[tokio::main]
async fn main() -> Result<()> {
    // Set up logging to stderr (stdout is for MCP protocol)
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("ebpf_assist_mcp=info".parse().unwrap()),
        )
        .init();

    info!("ebpf-assist-mcp starting...");

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            info!("EOF received, shutting down");
            break;
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        debug!("Received: {}", line);

        let response = match serde_json::from_str::<JsonRpcRequest>(line) {
            Ok(request) => handle_request(request).await,
            Err(e) => {
                error!("Failed to parse request: {}", e);
                JsonRpcResponse::error(
                    serde_json::Value::Null,
                    -32700,
                    format!("Parse error: {}", e),
                )
            }
        };

        let response_json = serde_json::to_string(&response)?;
        debug!("Sending: {}", response_json);

        stdout.write_all(response_json.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
    }

    Ok(())
}

async fn handle_request(request: JsonRpcRequest) -> JsonRpcResponse {
    let id = request.id.clone();

    match request.method.parse::<McpMethod>() {
        Ok(method) => {
            let result = match method {
                McpMethod::Initialize => tools::handle_initialize(request.params).await,
                McpMethod::ToolsList => tools::handle_tools_list().await,
                McpMethod::ToolsCall => tools::handle_tools_call(request.params).await,
                McpMethod::Ping => Ok(serde_json::json!({})),
            };

            match result {
                Ok(value) => JsonRpcResponse::success(id, value),
                Err(e) => JsonRpcResponse::error(id, -32000, e.to_string()),
            }
        }
        Err(_) => {
            // Unknown method - return error
            JsonRpcResponse::error(id, -32601, format!("Method not found: {}", request.method))
        }
    }
}
