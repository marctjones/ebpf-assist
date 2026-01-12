//! MCP tool implementations.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::{debug, info};

use ebpf_assist_common::{user_socket_path, ProgramId, Request, Response};

use crate::protocol::{ToolCallParams, ToolCallResult, ToolDefinition};

/// Find the ebpf-assist CLI binary.
/// First tries adjacent to the MCP binary, then falls back to PATH.
fn find_cli_binary() -> PathBuf {
    // Try to find it relative to the current executable
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(dir) = exe_path.parent() {
            let cli_path = dir.join("ebpf-assist");
            if cli_path.is_file() {
                return cli_path;
            }
        }
    }
    // Fall back to PATH lookup
    PathBuf::from("ebpf-assist")
}

/// Handle initialize request.
pub async fn handle_initialize(_params: serde_json::Value) -> Result<serde_json::Value> {
    info!("MCP initialize");
    Ok(serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "ebpf-assist",
            "version": env!("CARGO_PKG_VERSION")
        }
    }))
}

/// Handle tools/list request.
pub async fn handle_tools_list() -> Result<serde_json::Value> {
    let tools = vec![
        ToolDefinition {
            name: "ebpf_new".to_string(),
            description: "Create a new eBPF program from a template. Templates include kprobe (function entry), kretprobe (function return), tracepoint, xdp (packet processing), and raw_tracepoint.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "template": {
                        "type": "string",
                        "enum": ["kprobe", "kretprobe", "tracepoint", "xdp", "raw_tracepoint"],
                        "description": "Template type: kprobe, kretprobe, tracepoint, xdp, raw_tracepoint"
                    },
                    "name": {
                        "type": "string",
                        "description": "Program name (used for filename and function name)"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target for the template (e.g., 'do_sys_openat2' for kprobe, 'syscalls/sys_enter_openat' for tracepoint)"
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output directory (default: current directory)"
                    }
                },
                "required": ["template", "name"]
            }),
        },
        ToolDefinition {
            name: "ebpf_compile".to_string(),
            description: "Compile an eBPF C source file to an object file. Wraps clang with the correct flags for BPF target.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "source": {
                        "type": "string",
                        "description": "Path to the eBPF C source file"
                    },
                    "output": {
                        "type": "string",
                        "description": "Output path for object file (default: source.o)"
                    },
                    "opt_level": {
                        "type": "integer",
                        "description": "Optimization level 0-3 (default: 2)"
                    }
                },
                "required": ["source"]
            }),
        },
        ToolDefinition {
            name: "ebpf_load".to_string(),
            description: "Load an eBPF program from an object file. Returns the program ID for use with attach/detach.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the eBPF object file (.o)"
                    },
                    "program_name": {
                        "type": "string",
                        "description": "Name of the program within the object file (required if multiple programs exist)"
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "ebpf_unload".to_string(),
            description: "Unload a previously loaded eBPF program by its ID.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "integer",
                        "description": "Program ID returned from ebpf_load"
                    }
                },
                "required": ["id"]
            }),
        },
        ToolDefinition {
            name: "ebpf_attach".to_string(),
            description: "Attach a loaded eBPF program to a kernel hook (kprobe, tracepoint, XDP interface, etc.).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "integer",
                        "description": "Program ID returned from ebpf_load"
                    },
                    "target": {
                        "type": "string",
                        "description": "Attach target: function name for kprobe (e.g., 'do_sys_openat2'), 'category:name' for tracepoint (e.g., 'syscalls:sys_enter_openat'), or interface name for XDP (e.g., 'eth0')"
                    }
                },
                "required": ["id", "target"]
            }),
        },
        ToolDefinition {
            name: "ebpf_detach".to_string(),
            description: "Detach an eBPF program from its kernel hook.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "integer",
                        "description": "Program ID"
                    }
                },
                "required": ["id"]
            }),
        },
        ToolDefinition {
            name: "ebpf_list".to_string(),
            description: "List all loaded eBPF programs managed by ebpf-assist.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        },
        ToolDefinition {
            name: "ebpf_status".to_string(),
            description: "Get ebpf-assist daemon status including version, uptime, and capabilities.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        },
        ToolDefinition {
            name: "ebpf_unlock".to_string(),
            description: "Authenticate with polkit to enable eBPF operations. This triggers a GUI password prompt. Authorization is cached for 15 minutes.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        },
        ToolDefinition {
            name: "ebpf_trigger".to_string(),
            description: "Trigger kernel activity to test eBPF programs. Useful for generating syscalls, filesystem events, process events, or network activity that your eBPF program can intercept.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "enum": ["syscall", "fs", "proc", "net"],
                        "description": "Category of activity to trigger"
                    },
                    "operation": {
                        "type": "string",
                        "description": "Specific operation: syscall (openat, read, write, execve, connect), fs (create, delete, rename, chmod), proc (fork, exec, exit), net (tcp-connect, udp-send, ping, dns)"
                    },
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Arguments for the operation (e.g., file paths, addresses)"
                    }
                },
                "required": ["category", "operation"]
            }),
        },
        ToolDefinition {
            name: "ebpf_trace".to_string(),
            description: "Read output from bpf_printk (the trace_pipe). Use this to see what your eBPF program is logging. Requires root access to read trace_pipe.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "lines": {
                        "type": "integer",
                        "description": "Number of lines to read (default: 10)"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 5)"
                    }
                }
            }),
        },
    ];

    Ok(serde_json::json!({ "tools": tools }))
}

/// Handle tools/call request.
pub async fn handle_tools_call(params: serde_json::Value) -> Result<serde_json::Value> {
    let call: ToolCallParams = serde_json::from_value(params)
        .context("Invalid tool call parameters")?;

    debug!("Tool call: {} with args: {:?}", call.name, call.arguments);

    let result = match call.name.as_str() {
        "ebpf_new" => tool_new(call.arguments).await,
        "ebpf_compile" => tool_compile(call.arguments).await,
        "ebpf_load" => tool_load(call.arguments).await,
        "ebpf_unload" => tool_unload(call.arguments).await,
        "ebpf_attach" => tool_attach(call.arguments).await,
        "ebpf_detach" => tool_detach(call.arguments).await,
        "ebpf_list" => tool_list().await,
        "ebpf_status" => tool_status().await,
        "ebpf_unlock" => tool_unlock().await,
        "ebpf_trigger" => tool_trigger(call.arguments).await,
        "ebpf_trace" => tool_trace(call.arguments).await,
        _ => Ok(ToolCallResult::error(format!("Unknown tool: {}", call.name))),
    };

    match result {
        Ok(r) => Ok(serde_json::to_value(r)?),
        Err(e) => Ok(serde_json::to_value(ToolCallResult::error(e.to_string()))?),
    }
}

/// Send a request to the daemon and get the response.
async fn daemon_request(request: Request) -> Result<Response> {
    let socket_path = user_socket_path();
    let stream = UnixStream::connect(&socket_path)
        .await
        .with_context(|| format!(
            "Failed to connect to daemon at {}. Is ebpf-assistd running?",
            socket_path.display()
        ))?;

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let request_json = serde_json::to_string(&request)?;
    writer.write_all(request_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    let mut response_line = String::new();
    reader.read_line(&mut response_line).await?;

    let response: Response = serde_json::from_str(&response_line)
        .context("Failed to parse daemon response")?;

    Ok(response)
}

#[derive(Deserialize)]
struct NewArgs {
    template: String,
    name: String,
    target: Option<String>,
    output_dir: Option<String>,
}

async fn tool_new(args: serde_json::Value) -> Result<ToolCallResult> {
    let args: NewArgs = serde_json::from_value(args)?;

    let mut cmd_args = vec![
        "new".to_string(),
        args.template.clone(),
        args.name.clone(),
        "--json".to_string(),
    ];

    if let Some(target) = &args.target {
        cmd_args.push("--target".to_string());
        cmd_args.push(target.clone());
    }

    if let Some(output_dir) = &args.output_dir {
        cmd_args.push("--output-dir".to_string());
        cmd_args.push(output_dir.clone());
    }

    let output = tokio::process::Command::new(find_cli_binary())
        .args(&cmd_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to run ebpf-assist new")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        // Parse JSON output
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let path = json.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let template = json.get("template").and_then(|v| v.as_str()).unwrap_or("");
            Ok(ToolCallResult::text(format!(
                "Created eBPF program from {} template:\n  Path: {}\n\nNext steps:\n  1. Edit {} as needed\n  2. Compile: ebpf_compile(source=\"{}\")\n  3. Load: ebpf_load(path=\"{}.o\")",
                template, path, path, path, args.name
            )))
        } else {
            Ok(ToolCallResult::text(format!("{}{}", stdout, stderr)))
        }
    } else {
        Ok(ToolCallResult::error(format!("{}{}", stdout, stderr)))
    }
}

#[derive(Deserialize)]
struct CompileArgs {
    source: String,
    output: Option<String>,
    opt_level: Option<u8>,
}

async fn tool_compile(args: serde_json::Value) -> Result<ToolCallResult> {
    let args: CompileArgs = serde_json::from_value(args)?;

    let mut cmd_args = vec![
        "compile".to_string(),
        args.source.clone(),
        "--json".to_string(),
    ];

    if let Some(output) = &args.output {
        cmd_args.push("--output".to_string());
        cmd_args.push(output.clone());
    }

    if let Some(opt) = args.opt_level {
        cmd_args.push("--opt".to_string());
        cmd_args.push(opt.to_string());
    }

    let output = tokio::process::Command::new(find_cli_binary())
        .args(&cmd_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to run ebpf-assist compile")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let output_path = json.get("output").and_then(|v| v.as_str()).unwrap_or("");
            let warnings = json.get("warnings").and_then(|v| v.as_array()).map(|w| {
                w.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join("\n")
            }).unwrap_or_default();

            let mut msg = format!("Compiled successfully:\n  Output: {}", output_path);
            if !warnings.is_empty() {
                msg.push_str(&format!("\n\nWarnings:\n{}", warnings));
            }
            msg.push_str(&format!("\n\nNext: ebpf_load(path=\"{}\")", output_path));
            Ok(ToolCallResult::text(msg))
        } else {
            Ok(ToolCallResult::text(format!("{}{}", stdout, stderr)))
        }
    } else {
        // Parse error JSON
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let error = json.get("error").and_then(|v| v.as_str()).unwrap_or("Compilation failed");
            Ok(ToolCallResult::error(error.to_string()))
        } else {
            Ok(ToolCallResult::error(format!("{}{}", stdout, stderr)))
        }
    }
}

#[derive(Deserialize)]
struct LoadArgs {
    path: String,
    program_name: Option<String>,
}

async fn tool_load(args: serde_json::Value) -> Result<ToolCallResult> {
    let args: LoadArgs = serde_json::from_value(args)?;

    let path = PathBuf::from(&args.path).canonicalize()
        .with_context(|| format!("File not found: {}", args.path))?;

    let response = daemon_request(Request::Load {
        path,
        program_name: args.program_name,
    }).await?;

    match response {
        Response::Loaded { id, name, program_type } => {
            Ok(ToolCallResult::text(format!(
                "Loaded eBPF program:\n  ID: {}\n  Name: {}\n  Type: {:?}\n\nUse ebpf_attach with id={} to attach to a kernel hook.",
                id.0, name, program_type, id.0
            )))
        }
        Response::Error { message, code } => {
            Ok(ToolCallResult::error(format!("[{:?}] {}", code, message)))
        }
        _ => Ok(ToolCallResult::error("Unexpected response from daemon")),
    }
}

#[derive(Deserialize)]
struct IdArgs {
    id: u32,
}

async fn tool_unload(args: serde_json::Value) -> Result<ToolCallResult> {
    let args: IdArgs = serde_json::from_value(args)?;

    let response = daemon_request(Request::Unload {
        id: ProgramId(args.id),
    }).await?;

    match response {
        Response::Unloaded { id } => {
            Ok(ToolCallResult::text(format!("Unloaded program {}", id.0)))
        }
        Response::Error { message, code } => {
            Ok(ToolCallResult::error(format!("[{:?}] {}", code, message)))
        }
        _ => Ok(ToolCallResult::error("Unexpected response from daemon")),
    }
}

#[derive(Deserialize)]
struct AttachArgs {
    id: u32,
    target: String,
}

async fn tool_attach(args: serde_json::Value) -> Result<ToolCallResult> {
    let args: AttachArgs = serde_json::from_value(args)?;

    let response = daemon_request(Request::Attach {
        id: ProgramId(args.id),
        target: args.target.clone(),
    }).await?;

    match response {
        Response::Attached { id, target } => {
            Ok(ToolCallResult::text(format!(
                "Attached program {} to {}\n\nThe eBPF program is now active. Use ebpf_trigger to generate activity, or ebpf_trace to read bpf_printk output.",
                id.0, target
            )))
        }
        Response::Error { message, code } => {
            Ok(ToolCallResult::error(format!("[{:?}] {}", code, message)))
        }
        _ => Ok(ToolCallResult::error("Unexpected response from daemon")),
    }
}

async fn tool_detach(args: serde_json::Value) -> Result<ToolCallResult> {
    let args: IdArgs = serde_json::from_value(args)?;

    let response = daemon_request(Request::Detach {
        id: ProgramId(args.id),
    }).await?;

    match response {
        Response::Detached { id } => {
            Ok(ToolCallResult::text(format!("Detached program {}", id.0)))
        }
        Response::Error { message, code } => {
            Ok(ToolCallResult::error(format!("[{:?}] {}", code, message)))
        }
        _ => Ok(ToolCallResult::error("Unexpected response from daemon")),
    }
}

async fn tool_list() -> Result<ToolCallResult> {
    let response = daemon_request(Request::List).await?;

    match response {
        Response::Programs { programs } => {
            if programs.is_empty() {
                Ok(ToolCallResult::text("No eBPF programs loaded"))
            } else {
                let mut output = String::from("Loaded eBPF programs:\n\n");
                output.push_str(&format!("{:<6} {:<20} {:<15} {:<10} {}\n",
                    "ID", "NAME", "TYPE", "ATTACHED", "TARGET"));
                output.push_str(&"-".repeat(70));
                output.push('\n');

                for prog in programs {
                    let attached = if prog.attached { "yes" } else { "no" };
                    let target = prog.attach_point.as_deref().unwrap_or("-");
                    output.push_str(&format!(
                        "{:<6} {:<20} {:<15} {:<10} {}\n",
                        prog.id.0,
                        prog.name,
                        format!("{:?}", prog.program_type),
                        attached,
                        target
                    ));
                }
                Ok(ToolCallResult::text(output))
            }
        }
        Response::Error { message, code } => {
            Ok(ToolCallResult::error(format!("[{:?}] {}", code, message)))
        }
        _ => Ok(ToolCallResult::error("Unexpected response from daemon")),
    }
}

async fn tool_status() -> Result<ToolCallResult> {
    let response = daemon_request(Request::Status).await?;

    match response {
        Response::Status { version, uptime_secs, programs_loaded, capabilities } => {
            Ok(ToolCallResult::text(format!(
                "ebpf-assistd status:\n  Version: {}\n  Uptime: {}s\n  Programs loaded: {}\n  Capabilities: {}",
                version, uptime_secs, programs_loaded,
                if capabilities.is_empty() { "none".to_string() } else { capabilities.join(", ") }
            )))
        }
        Response::Error { message, code } => {
            Ok(ToolCallResult::error(format!("[{:?}] {}", code, message)))
        }
        _ => Ok(ToolCallResult::error("Unexpected response from daemon")),
    }
}

async fn tool_unlock() -> Result<ToolCallResult> {
    let response = daemon_request(Request::Unlock).await?;

    match response {
        Response::Unlocked => {
            Ok(ToolCallResult::text(
                "Authorization granted. You can now load and attach eBPF programs.\nAuthorization is cached for 15 minutes."
            ))
        }
        Response::Error { message, code } => {
            Ok(ToolCallResult::error(format!("[{:?}] {}", code, message)))
        }
        _ => Ok(ToolCallResult::error("Unexpected response from daemon")),
    }
}

#[derive(Deserialize)]
struct TriggerArgs {
    category: String,
    operation: String,
    #[serde(default)]
    args: Vec<String>,
}

async fn tool_trigger(args: serde_json::Value) -> Result<ToolCallResult> {
    let args: TriggerArgs = serde_json::from_value(args)?;

    // Build CLI command
    let mut cmd_args = vec![
        "trigger".to_string(),
        args.category.clone(),
        args.operation.clone(),
    ];
    cmd_args.extend(args.args.clone());

    // Run ebpf-assist trigger command
    let output = tokio::process::Command::new(find_cli_binary())
        .args(&cmd_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to run ebpf-assist trigger")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        Ok(ToolCallResult::text(format!(
            "Triggered {} {}\n\n{}{}",
            args.category, args.operation,
            stdout, stderr
        )))
    } else {
        Ok(ToolCallResult::error(format!(
            "Trigger failed:\n{}\n{}",
            stdout, stderr
        )))
    }
}

#[derive(Deserialize, Default)]
struct TraceArgs {
    #[serde(default = "default_lines")]
    lines: usize,
    #[serde(default = "default_timeout")]
    timeout: u64,
}

fn default_lines() -> usize { 10 }
fn default_timeout() -> u64 { 5 }

async fn tool_trace(args: serde_json::Value) -> Result<ToolCallResult> {
    let args: TraceArgs = serde_json::from_value(args).unwrap_or_default();

    // Run ebpf-assist output trace command
    let output = tokio::process::Command::new(find_cli_binary())
        .args([
            "output", "trace",
            "--lines", &args.lines.to_string(),
            "--timeout", &args.timeout.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to run ebpf-assist output trace")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() || !stdout.is_empty() {
        Ok(ToolCallResult::text(format!("{}{}", stdout, stderr)))
    } else {
        Ok(ToolCallResult::error(format!(
            "Failed to read trace_pipe. You may need root access.\n{}",
            stderr
        )))
    }
}
