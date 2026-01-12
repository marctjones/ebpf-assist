//! Trigger kernel activity for testing eBPF programs.
//!
//! This module provides functions to generate specific kernel events
//! that eBPF programs can intercept, useful for testing and development.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::{OutputCommands, TriggerCommands};

/// Run a trigger command.
pub async fn run(cmd: TriggerCommands) -> Result<()> {
    match cmd {
        TriggerCommands::Syscall { name, args } => trigger_syscall(&name, &args),
        TriggerCommands::Fs { op, paths } => trigger_fs(&op, &paths),
        TriggerCommands::Proc { op, args } => trigger_proc(&op, &args),
        TriggerCommands::Net { op, target, data } => {
            trigger_net(&op, &target, data.as_deref()).await
        }
    }
}

/// Run an output command.
pub async fn output(cmd: OutputCommands) -> Result<()> {
    match cmd {
        OutputCommands::Trace { lines, timeout } => read_trace_pipe(lines, timeout),
    }
}

/// Trigger a specific syscall.
fn trigger_syscall(name: &str, args: &[String]) -> Result<()> {
    match name {
        "openat" | "open" => {
            let path = args
                .first()
                .map(|s| s.as_str())
                .unwrap_or("/tmp/ebpf-assist-test");
            println!("Triggering openat: {}", path);
            let _ = File::open(path);
            println!("  Done (file may or may not exist)");
            Ok(())
        }

        "read" => {
            let path = args.first().map(|s| s.as_str()).unwrap_or("/etc/hostname");
            println!("Triggering read: {}", path);
            let mut file = File::open(path).context("Failed to open file for reading")?;
            let mut buf = [0u8; 64];
            let _ = file.read(&mut buf);
            println!("  Done");
            Ok(())
        }

        "write" => {
            let path = args
                .first()
                .map(|s| s.as_str())
                .unwrap_or("/tmp/ebpf-assist-test-write");
            let data = args.get(1).map(|s| s.as_str()).unwrap_or("test data");
            println!("Triggering write: {} <- {:?}", path, data);
            let mut file = File::create(path).context("Failed to create file for writing")?;
            file.write_all(data.as_bytes())?;
            println!("  Done");
            Ok(())
        }

        "execve" | "exec" => {
            let cmd = args.first().map(|s| s.as_str()).unwrap_or("/bin/true");
            let cmd_args: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();
            println!("Triggering execve: {} {:?}", cmd, cmd_args);
            let status = Command::new(cmd)
                .args(&cmd_args)
                .status()
                .context("Failed to execute command")?;
            println!("  Done (exit code: {:?})", status.code());
            Ok(())
        }

        "connect" => {
            let target = args.first().map(|s| s.as_str()).unwrap_or("127.0.0.1:80");
            println!("Triggering connect: {}", target);
            match TcpStream::connect_timeout(
                &target.parse().context("Invalid address")?,
                Duration::from_secs(1),
            ) {
                Ok(_) => println!("  Connected successfully"),
                Err(e) => println!("  Connection failed (expected): {}", e),
            }
            Ok(())
        }

        "socket" => {
            println!("Triggering socket creation");
            let _ = UdpSocket::bind("0.0.0.0:0")?;
            println!("  Done");
            Ok(())
        }

        "getpid" => {
            println!("Triggering getpid");
            let pid = std::process::id();
            println!("  PID: {}", pid);
            Ok(())
        }

        "stat" => {
            let path = args.first().map(|s| s.as_str()).unwrap_or("/etc/passwd");
            println!("Triggering stat: {}", path);
            let metadata = fs::metadata(path).context("Failed to stat file")?;
            println!("  Size: {} bytes", metadata.len());
            Ok(())
        }

        _ => {
            bail!("Unknown syscall: {}. Supported: openat, read, write, execve, connect, socket, getpid, stat", name);
        }
    }
}

/// Trigger filesystem activity.
fn trigger_fs(op: &str, paths: &[String]) -> Result<()> {
    match op {
        "create" => {
            let path = paths
                .first()
                .map(|s| s.as_str())
                .unwrap_or("/tmp/ebpf-assist-test-create");
            println!("Creating file: {}", path);
            File::create(path)?;
            println!("  Done");
            Ok(())
        }

        "delete" | "remove" | "unlink" => {
            let path = paths.first().context("Path required for delete")?;
            println!("Deleting: {}", path);
            fs::remove_file(path).context("Failed to delete file")?;
            println!("  Done");
            Ok(())
        }

        "rename" | "mv" => {
            if paths.len() < 2 {
                bail!("rename requires two paths: source and destination");
            }
            println!("Renaming: {} -> {}", paths[0], paths[1]);
            fs::rename(&paths[0], &paths[1]).context("Failed to rename")?;
            println!("  Done");
            Ok(())
        }

        "chmod" => {
            if paths.len() < 2 {
                bail!("chmod requires path and mode (e.g., 755)");
            }
            let mode = u32::from_str_radix(&paths[1], 8).context("Invalid mode")?;
            println!("Chmod: {} to {:o}", paths[0], mode);
            fs::set_permissions(&paths[0], fs::Permissions::from_mode(mode))?;
            println!("  Done");
            Ok(())
        }

        "mkdir" => {
            let path = paths.first().context("Path required for mkdir")?;
            println!("Creating directory: {}", path);
            fs::create_dir_all(path)?;
            println!("  Done");
            Ok(())
        }

        "rmdir" => {
            let path = paths.first().context("Path required for rmdir")?;
            println!("Removing directory: {}", path);
            fs::remove_dir(path)?;
            println!("  Done");
            Ok(())
        }

        "read" => {
            let path = paths.first().map(|s| s.as_str()).unwrap_or("/etc/hostname");
            println!("Reading file: {}", path);
            let content = fs::read_to_string(path).context("Failed to read file")?;
            println!("  Content ({} bytes): {}", content.len(), content.trim());
            Ok(())
        }

        "write" => {
            let path = paths.first().context("Path required for write")?;
            let data = paths.get(1).map(|s| s.as_str()).unwrap_or("test data\n");
            println!("Writing to file: {}", path);
            fs::write(path, data)?;
            println!("  Done ({} bytes)", data.len());
            Ok(())
        }

        "append" => {
            let path = paths.first().context("Path required for append")?;
            let data = paths
                .get(1)
                .map(|s| s.as_str())
                .unwrap_or("appended data\n");
            println!("Appending to file: {}", path);
            let mut file = OpenOptions::new().append(true).create(true).open(path)?;
            file.write_all(data.as_bytes())?;
            println!("  Done ({} bytes)", data.len());
            Ok(())
        }

        _ => {
            bail!("Unknown fs operation: {}. Supported: create, delete, rename, chmod, mkdir, rmdir, read, write, append", op);
        }
    }
}

/// Trigger process activity.
fn trigger_proc(op: &str, args: &[String]) -> Result<()> {
    match op {
        "fork" => {
            println!("Triggering fork (via /bin/true)");
            // We can't directly fork in Rust safely, but execve does fork+exec
            Command::new("/bin/true").status()?;
            println!("  Done");
            Ok(())
        }

        "exec" => {
            let cmd = args.first().map(|s| s.as_str()).unwrap_or("/bin/ls");
            let cmd_args: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();
            println!("Executing: {} {:?}", cmd, cmd_args);
            let output = Command::new(cmd)
                .args(&cmd_args)
                .output()
                .context("Failed to execute")?;
            println!("  Exit code: {:?}", output.status.code());
            if !output.stdout.is_empty() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().take(5) {
                    println!("  stdout: {}", line);
                }
                if stdout.lines().count() > 5 {
                    println!("  ... ({} more lines)", stdout.lines().count() - 5);
                }
            }
            Ok(())
        }

        "exit" => {
            // We spawn a process that exits with a specific code
            let code = args.first().map(|s| s.as_str()).unwrap_or("0");
            println!("Spawning process that exits with code: {}", code);
            Command::new("/bin/sh")
                .args(["-c", &format!("exit {}", code)])
                .status()?;
            println!("  Done");
            Ok(())
        }

        "sleep" => {
            let secs: u64 = args.first().map(|s| s.parse().unwrap_or(1)).unwrap_or(1);
            println!("Spawning sleep process for {} seconds", secs);
            Command::new("/bin/sleep").arg(secs.to_string()).status()?;
            println!("  Done");
            Ok(())
        }

        _ => {
            bail!(
                "Unknown proc operation: {}. Supported: fork, exec, exit, sleep",
                op
            );
        }
    }
}

/// Trigger network activity.
async fn trigger_net(op: &str, target: &str, data: Option<&str>) -> Result<()> {
    match op {
        "tcp-connect" | "tcp" => {
            println!("TCP connect to: {}", target);
            match TcpStream::connect_timeout(
                &target.parse().context("Invalid address (use host:port)")?,
                Duration::from_secs(5),
            ) {
                Ok(mut stream) => {
                    println!("  Connected!");
                    if let Some(data) = data {
                        stream.write_all(data.as_bytes())?;
                        println!("  Sent {} bytes", data.len());
                    }
                }
                Err(e) => {
                    println!("  Connection failed: {}", e);
                }
            }
            Ok(())
        }

        "udp-send" | "udp" => {
            println!("UDP send to: {}", target);
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            let data = data.unwrap_or("test packet");
            socket.send_to(data.as_bytes(), target)?;
            println!("  Sent {} bytes", data.len());
            Ok(())
        }

        "ping" => {
            println!("Ping: {}", target);
            let status = Command::new("ping")
                .args(["-c", "1", "-W", "2", target])
                .status();
            match status {
                Ok(s) if s.success() => println!("  Host is reachable"),
                Ok(_) => println!("  Host unreachable"),
                Err(e) => println!("  Ping failed: {}", e),
            }
            Ok(())
        }

        "dns" | "resolve" => {
            println!("DNS lookup: {}", target);
            use std::net::ToSocketAddrs;
            let addr = format!("{}:80", target);
            match addr.to_socket_addrs() {
                Ok(addrs) => {
                    for a in addrs {
                        println!("  Resolved: {}", a.ip());
                    }
                }
                Err(e) => println!("  Lookup failed: {}", e),
            }
            Ok(())
        }

        "http-get" | "http" => {
            println!("HTTP GET: {}", target);
            // Simple HTTP without external dependencies
            let url = if target.starts_with("http://") {
                target.to_string()
            } else {
                format!("http://{}", target)
            };

            // Parse host:port from URL
            let host_port = url
                .strip_prefix("http://")
                .unwrap_or(target)
                .split('/')
                .next()
                .unwrap_or(target);

            let addr = if host_port.contains(':') {
                host_port.to_string()
            } else {
                format!("{}:80", host_port)
            };

            match TcpStream::connect_timeout(
                &addr.parse().context("Invalid address")?,
                Duration::from_secs(5),
            ) {
                Ok(mut stream) => {
                    let host = host_port.split(':').next().unwrap_or(host_port);
                    let request = format!(
                        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        host
                    );
                    stream.write_all(request.as_bytes())?;
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

                    let mut response = String::new();
                    let mut reader = BufReader::new(&stream);
                    // Read just the status line
                    reader.read_line(&mut response)?;
                    println!("  Response: {}", response.trim());
                }
                Err(e) => {
                    println!("  Connection failed: {}", e);
                }
            }
            Ok(())
        }

        _ => {
            bail!(
                "Unknown net operation: {}. Supported: tcp-connect, udp-send, ping, dns, http-get",
                op
            );
        }
    }
}

/// Read from /sys/kernel/debug/tracing/trace_pipe.
fn read_trace_pipe(max_lines: usize, timeout_secs: u64) -> Result<()> {
    let trace_pipe = Path::new("/sys/kernel/debug/tracing/trace_pipe");

    if !trace_pipe.exists() {
        bail!(
            "trace_pipe not found at {}. Make sure debugfs is mounted:\n  \
             sudo mount -t debugfs none /sys/kernel/debug",
            trace_pipe.display()
        );
    }

    println!(
        "Reading from trace_pipe (timeout: {}s, max lines: {})...",
        timeout_secs,
        if max_lines == 0 {
            "unlimited".to_string()
        } else {
            max_lines.to_string()
        }
    );
    println!("---");

    let file = File::open(trace_pipe).context(
        "Failed to open trace_pipe. You may need root or CAP_SYS_ADMIN:\n  \
         sudo ebpf-assist output trace",
    )?;

    let reader = BufReader::new(file);
    let mut lines_read = 0;
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    for line in reader.lines() {
        if timeout_secs > 0 && start.elapsed() > timeout {
            println!("---");
            println!("Timeout reached ({} seconds)", timeout_secs);
            break;
        }

        match line {
            Ok(line) => {
                println!("{}", line);
                lines_read += 1;
                if max_lines > 0 && lines_read >= max_lines {
                    break;
                }
            }
            Err(e) => {
                eprintln!("Error reading trace_pipe: {}", e);
                break;
            }
        }
    }

    println!("---");
    println!("Read {} lines", lines_read);
    Ok(())
}
