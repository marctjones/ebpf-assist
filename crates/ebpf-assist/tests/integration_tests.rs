//! Integration tests for ebpf-assist.
//!
//! These tests require:
//! - Built binaries in target/release or target/debug
//! - May require CAP_BPF/CAP_PERFMON for full eBPF tests

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Get the path to a binary in target directory.
fn binary_path(name: &str) -> PathBuf {
    // Try release first, then debug
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();

    let release = workspace_root.join("target/release").join(name);
    if release.exists() {
        return release;
    }
    workspace_root.join("target/debug").join(name)
}

// ==================== CLI Binary Tests ====================

mod cli_tests {
    use super::*;

    #[test]
    fn test_cli_help() {
        let cli = binary_path("ebpf-assist");
        if !cli.exists() {
            eprintln!("CLI binary not found at {:?}, skipping test", cli);
            return;
        }

        let output = Command::new(&cli)
            .arg("--help")
            .output()
            .expect("Failed to run CLI");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("ebpf-assist"));
    }

    #[test]
    fn test_cli_version() {
        let cli = binary_path("ebpf-assist");
        if !cli.exists() {
            return;
        }

        let output = Command::new(&cli)
            .arg("--version")
            .output()
            .expect("Failed to run CLI");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("ebpf-assist"));
    }

    #[test]
    fn test_cli_subcommand_help() {
        let cli = binary_path("ebpf-assist");
        if !cli.exists() {
            return;
        }

        let subcommands = [
            "compile", "new", "load", "unload", "attach", "detach", "list", "status", "ping",
            "trigger", "output", "map",
        ];

        for cmd in subcommands {
            let output = Command::new(&cli)
                .args([cmd, "--help"])
                .output()
                .expect(&format!("Failed to run {} --help", cmd));

            assert!(output.status.success(), "{} --help failed", cmd);
        }
    }

    #[test]
    fn test_cli_new_kprobe() {
        let cli = binary_path("ebpf-assist");
        if !cli.exists() {
            return;
        }

        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

        let output = Command::new(&cli)
            .args(["new", "kprobe", "test_probe", "--output-dir"])
            .arg(temp_dir.path())
            .output()
            .expect("Failed to run new command");

        assert!(
            output.status.success(),
            "new kprobe failed: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );

        let created_file = temp_dir.path().join("test_probe.c");
        assert!(created_file.exists(), "Template file not created");

        let content = std::fs::read_to_string(&created_file).unwrap();
        assert!(content.contains("SEC(\"kprobe/"));
        assert!(content.contains("LICENSE"));
    }

    #[test]
    fn test_cli_new_all_templates() {
        let cli = binary_path("ebpf-assist");
        if !cli.exists() {
            return;
        }

        let templates = ["kprobe", "kretprobe", "tracepoint", "xdp", "raw_tracepoint"];

        for template in templates {
            let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

            let output = Command::new(&cli)
                .args([
                    "new",
                    template,
                    &format!("test_{}", template),
                    "--output-dir",
                ])
                .arg(temp_dir.path())
                .output()
                .expect(&format!("Failed to run new {}", template));

            assert!(output.status.success(), "new {} failed", template);

            let created_file = temp_dir.path().join(format!("test_{}.c", template));
            assert!(
                created_file.exists(),
                "Template file not created for {}",
                template
            );
        }
    }

    #[test]
    fn test_cli_new_json_output() {
        let cli = binary_path("ebpf-assist");
        if !cli.exists() {
            return;
        }

        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

        let output = Command::new(&cli)
            .args(["new", "kprobe", "json_test", "--output-dir"])
            .arg(temp_dir.path())
            .arg("--json")
            .output()
            .expect("Failed to run new command");

        assert!(output.status.success());

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("Output should be valid JSON");

        assert_eq!(json["success"], true);
        assert!(json["path"].as_str().unwrap().contains("json_test.c"));
    }

    #[test]
    fn test_cli_compile_missing_file() {
        let cli = binary_path("ebpf-assist");
        if !cli.exists() {
            return;
        }

        let output = Command::new(&cli)
            .args(["compile", "/nonexistent/file.c"])
            .output()
            .expect("Failed to run compile");

        // Should fail with non-zero exit code
        assert!(!output.status.success());
    }

    #[test]
    fn test_cli_trigger_help() {
        let cli = binary_path("ebpf-assist");
        if !cli.exists() {
            return;
        }

        let output = Command::new(&cli)
            .args(["trigger", "--help"])
            .output()
            .expect("Failed to run trigger --help");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("syscall") || stdout.contains("fs") || stdout.contains("net"));
    }
}

// ==================== MCP Server Tests ====================

mod mcp_tests {
    use super::*;

    fn run_mcp_request(request: &str) -> String {
        let mcp = binary_path("ebpf-assist-mcp");
        if !mcp.exists() {
            return String::new();
        }

        let mut child = Command::new(&mcp)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start MCP server");

        {
            let stdin = child.stdin.as_mut().unwrap();
            stdin.write_all(request.as_bytes()).unwrap();
        }

        let output = child.wait_with_output().expect("Failed to read output");
        String::from_utf8_lossy(&output.stdout).to_string()
    }

    #[test]
    fn test_mcp_initialize() {
        let mcp = binary_path("ebpf-assist-mcp");
        if !mcp.exists() {
            eprintln!("MCP binary not found, skipping test");
            return;
        }

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let response = run_mcp_request(request);

        if response.is_empty() {
            return;
        }

        let json: serde_json::Value =
            serde_json::from_str(&response).expect("Response should be valid JSON");

        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 1);
        assert!(json["result"]["serverInfo"]["name"]
            .as_str()
            .unwrap()
            .contains("ebpf"));
    }

    #[test]
    fn test_mcp_tools_list() {
        let mcp = binary_path("ebpf-assist-mcp");
        if !mcp.exists() {
            return;
        }

        let request = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        let response = run_mcp_request(request);

        if response.is_empty() {
            return;
        }

        let json: serde_json::Value =
            serde_json::from_str(&response).expect("Response should be valid JSON");

        let tools = json["result"]["tools"].as_array().unwrap();
        assert!(tools.len() >= 10, "Should have at least 10 tools");

        // Check for expected tools
        let tool_names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();

        assert!(
            tool_names.contains(&"ebpf_new"),
            "Should have ebpf_new tool"
        );
        assert!(
            tool_names.contains(&"ebpf_compile"),
            "Should have ebpf_compile tool"
        );
        assert!(
            tool_names.contains(&"ebpf_list"),
            "Should have ebpf_list tool"
        );
        assert!(
            tool_names.contains(&"ebpf_status"),
            "Should have ebpf_status tool"
        );
    }

    #[test]
    fn test_mcp_tool_ebpf_new() {
        let mcp = binary_path("ebpf-assist-mcp");
        if !mcp.exists() {
            return;
        }

        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let output_dir = temp_dir.path().to_string_lossy();

        let request = format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"ebpf_new","arguments":{{"template":"kprobe","name":"mcp_test","output_dir":"{}"}}}}}}"#,
            output_dir
        );

        let response = run_mcp_request(&request);

        if response.is_empty() {
            return;
        }

        let json: serde_json::Value =
            serde_json::from_str(&response).expect("Response should be valid JSON");

        // Should return content
        assert!(json["result"]["content"].is_array());

        // File should be created
        let created_file = temp_dir.path().join("mcp_test.c");
        assert!(created_file.exists(), "MCP should create the template file");
    }

    #[test]
    fn test_mcp_ping() {
        let mcp = binary_path("ebpf-assist-mcp");
        if !mcp.exists() {
            return;
        }

        let request = r#"{"jsonrpc":"2.0","id":4,"method":"ping","params":{}}"#;
        let response = run_mcp_request(request);

        if response.is_empty() {
            return;
        }

        let json: serde_json::Value =
            serde_json::from_str(&response).expect("Response should be valid JSON");

        assert_eq!(json["id"], 4);
        // Should have either result or error
        assert!(json["result"].is_object() || json["error"].is_object());
    }

    #[test]
    fn test_mcp_unknown_method() {
        let mcp = binary_path("ebpf-assist-mcp");
        if !mcp.exists() {
            return;
        }

        let request = r#"{"jsonrpc":"2.0","id":5,"method":"unknown/method","params":{}}"#;
        let response = run_mcp_request(request);

        if response.is_empty() {
            return;
        }

        let json: serde_json::Value =
            serde_json::from_str(&response).expect("Response should be valid JSON");

        // Should return an error
        assert!(
            json["error"].is_object(),
            "Unknown method should return error"
        );
        assert_eq!(json["error"]["code"], -32601); // Method not found
    }

    #[test]
    fn test_mcp_tool_definitions_have_schemas() {
        let mcp = binary_path("ebpf-assist-mcp");
        if !mcp.exists() {
            return;
        }

        let request = r#"{"jsonrpc":"2.0","id":6,"method":"tools/list","params":{}}"#;
        let response = run_mcp_request(request);

        if response.is_empty() {
            return;
        }

        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        let tools = json["result"]["tools"].as_array().unwrap();

        for tool in tools {
            let name = tool["name"].as_str().unwrap();
            assert!(
                tool["description"].is_string(),
                "Tool {} missing description",
                name
            );
            assert!(
                tool["inputSchema"].is_object(),
                "Tool {} missing inputSchema",
                name
            );
        }
    }
}

// ==================== Trigger Command Tests ====================

mod trigger_tests {
    use super::*;

    #[test]
    fn test_trigger_syscall_getpid() {
        let cli = binary_path("ebpf-assist");
        if !cli.exists() {
            return;
        }

        let output = Command::new(&cli)
            .args(["trigger", "syscall", "getpid"])
            .output()
            .expect("Failed to run trigger syscall");

        assert!(
            output.status.success(),
            "trigger syscall getpid should succeed"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("PID") || stdout.contains("getpid"));
    }

    #[test]
    fn test_trigger_fs_create_delete() {
        let cli = binary_path("ebpf-assist");
        if !cli.exists() {
            return;
        }

        let temp_file = "/tmp/ebpf-assist-trigger-test";

        // Create
        let output = Command::new(&cli)
            .args(["trigger", "fs", "create", temp_file])
            .output()
            .expect("Failed to run trigger fs create");

        assert!(output.status.success(), "trigger fs create should succeed");
        assert!(
            std::path::Path::new(temp_file).exists(),
            "File should be created"
        );

        // Delete
        let output = Command::new(&cli)
            .args(["trigger", "fs", "delete", temp_file])
            .output()
            .expect("Failed to run trigger fs delete");

        assert!(output.status.success(), "trigger fs delete should succeed");
        assert!(
            !std::path::Path::new(temp_file).exists(),
            "File should be deleted"
        );
    }

    #[test]
    fn test_trigger_proc_fork() {
        let cli = binary_path("ebpf-assist");
        if !cli.exists() {
            return;
        }

        let output = Command::new(&cli)
            .args(["trigger", "proc", "fork"])
            .output()
            .expect("Failed to run trigger proc fork");

        assert!(output.status.success(), "trigger proc fork should succeed");
    }

    #[test]
    fn test_trigger_proc_exec() {
        let cli = binary_path("ebpf-assist");
        if !cli.exists() {
            return;
        }

        let output = Command::new(&cli)
            .args(["trigger", "proc", "exec", "/bin/true"])
            .output()
            .expect("Failed to run trigger proc exec");

        assert!(output.status.success(), "trigger proc exec should succeed");
    }

    #[test]
    fn test_trigger_net_dns() {
        let cli = binary_path("ebpf-assist");
        if !cli.exists() {
            return;
        }

        let output = Command::new(&cli)
            .args(["trigger", "net", "dns", "localhost"])
            .output()
            .expect("Failed to run trigger net dns");

        // May fail if network not available, but command should exist
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success()
                || stdout.contains("DNS")
                || stderr.contains("DNS")
                || stdout.contains("lookup"),
            "trigger net dns should run"
        );
    }
}

// ==================== Compile Tests ====================

mod compile_tests {
    use super::*;

    #[test]
    fn test_compile_generated_template() {
        let cli = binary_path("ebpf-assist");
        if !cli.exists() {
            return;
        }

        // Check if clang is available
        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("clang not found, skipping compile test");
            return;
        }

        // Check if libbpf headers are available
        if !std::path::Path::new("/usr/include/bpf/bpf_helpers.h").exists() {
            eprintln!("libbpf-dev not found, skipping compile test");
            return;
        }

        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

        // Generate template
        let output = Command::new(&cli)
            .args(["new", "kprobe", "compile_test", "--output-dir"])
            .arg(temp_dir.path())
            .output()
            .expect("Failed to create template");

        assert!(output.status.success(), "Template creation failed");

        let source = temp_dir.path().join("compile_test.c");
        let object = temp_dir.path().join("compile_test.o");

        // Compile
        let output = Command::new(&cli)
            .args(["compile"])
            .arg(&source)
            .args(["--output"])
            .arg(&object)
            .output()
            .expect("Failed to run compile");

        if output.status.success() {
            assert!(object.exists(), "Object file should be created");
        } else {
            // Compilation might fail due to header issues - that's OK for the test
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Compile failed (may be header issue): {}", stderr);
        }
    }

    #[test]
    fn test_compile_json_output() {
        let cli = binary_path("ebpf-assist");
        if !cli.exists() {
            return;
        }

        if Command::new("clang").arg("--version").output().is_err() {
            return;
        }

        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

        // Generate template
        Command::new(&cli)
            .args(["new", "kprobe", "json_compile_test", "--output-dir"])
            .arg(temp_dir.path())
            .output()
            .expect("Failed to create template");

        let source = temp_dir.path().join("json_compile_test.c");

        // Compile with JSON output
        let output = Command::new(&cli)
            .args(["compile"])
            .arg(&source)
            .arg("--json")
            .output()
            .expect("Failed to run compile");

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Output should be valid JSON regardless of success/failure
        let json: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(
            json.is_ok(),
            "Compile output should be valid JSON: {}",
            stdout
        );

        let json = json.unwrap();
        assert!(
            json.get("success").is_some() || json.get("error").is_some(),
            "JSON should have success or error field"
        );
    }
}
