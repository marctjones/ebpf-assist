//! ebpf-assist - CLI for managing eBPF programs.

mod client;
mod commands;
mod compile;
mod trigger;
pub mod vm;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "ebpf-assist")]
#[command(about = "Manage eBPF programs via ebpf-assistd")]
#[command(version)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Output in JSON format
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile an eBPF C source file to an object file
    Compile {
        /// Path to the eBPF C source file
        source: PathBuf,

        /// Output path for the object file (default: source.o)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Additional include directories
        #[arg(short = 'I', long = "include")]
        includes: Vec<PathBuf>,

        /// Preprocessor defines (KEY or KEY=VALUE)
        #[arg(short = 'D', long = "define")]
        defines: Vec<String>,

        /// Disable BTF generation
        #[arg(long)]
        no_btf: bool,

        /// Optimization level (0-3)
        #[arg(short = 'O', long = "opt", default_value = "2")]
        opt_level: u8,
    },

    /// Create a new eBPF program from a template
    New {
        /// Template type (kprobe, kretprobe, tracepoint, xdp, raw_tracepoint)
        template: String,

        /// Program name
        name: String,

        /// Target function/tracepoint for the template
        #[arg(short, long)]
        target: Option<String>,

        /// Output directory (default: current directory)
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
    },

    /// Load an eBPF program from a file
    Load {
        /// Path to the eBPF object file
        path: std::path::PathBuf,

        /// Name of the program within the object file (required if multiple)
        #[arg(short, long)]
        name: Option<String>,

        /// Run in isolated MicroVM (safer for risky programs)
        #[arg(long)]
        isolate: bool,
    },

    /// Unload a loaded eBPF program
    Unload {
        /// Program ID to unload
        id: u32,
    },

    /// Attach a loaded program to a target
    Attach {
        /// Program ID to attach
        id: u32,

        /// Target to attach to (e.g., function name for kprobe, interface for XDP)
        target: String,
    },

    /// Detach a program from its target
    Detach {
        /// Program ID to detach
        id: u32,
    },

    /// List all loaded programs
    List,

    /// Show daemon status
    Status,

    /// Check if daemon is running
    Ping,

    /// Authenticate with polkit (triggers GUI prompt, caches for 15 min)
    Unlock,

    /// Clear authentication cache (require re-auth on next operation)
    Lock,

    /// Check authentication status
    Auth,

    /// Trigger kernel activity for testing eBPF programs
    #[command(subcommand)]
    Trigger(TriggerCommands),

    /// Read output from eBPF programs (trace_pipe, maps, etc.)
    #[command(subcommand)]
    Output(OutputCommands),

    /// Manage BPF maps for loaded programs
    #[command(subcommand)]
    Map(MapCommands),

    /// Manage MicroVM isolation for safe eBPF testing
    #[command(subcommand)]
    Vm(VmCommands),
}

#[derive(Subcommand)]
enum VmCommands {
    /// Initialize MicroVM environment (check assets, KVM access)
    Init,

    /// List running MicroVMs
    List,

    /// Stop a running MicroVM
    Stop {
        /// VM ID to stop
        vm_id: String,
    },

    /// Show detailed status of a MicroVM
    Status {
        /// VM ID to query
        vm_id: String,
    },

    /// Show VM pool status and configuration
    Pool,
}

#[derive(Subcommand)]
enum TriggerCommands {
    /// Trigger a syscall
    Syscall {
        /// Syscall name (openat, execve, connect, etc.)
        name: String,

        /// Arguments for the syscall
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Trigger filesystem activity
    Fs {
        /// Operation (create, delete, rename, chmod, read, write)
        op: String,

        /// Path(s) for the operation
        #[arg(trailing_var_arg = true)]
        paths: Vec<String>,
    },

    /// Trigger process activity
    Proc {
        /// Operation (fork, exec, exit)
        op: String,

        /// Arguments (command for exec, exit code for exit)
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Trigger network activity
    Net {
        /// Operation (ping, tcp-connect, udp-send, http-get)
        op: String,

        /// Target (host:port or URL)
        target: String,

        /// Optional data to send
        #[arg(short, long)]
        data: Option<String>,
    },
}

#[derive(Subcommand)]
enum OutputCommands {
    /// Read from kernel trace_pipe (bpf_printk output)
    Trace {
        /// Number of lines to read (0 = continuous)
        #[arg(short, long, default_value = "10")]
        lines: usize,

        /// Timeout in seconds (0 = no timeout)
        #[arg(short, long, default_value = "5")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
enum MapCommands {
    /// List maps for a loaded program
    List {
        /// Program ID
        id: u32,
    },

    /// Read map entries
    Read {
        /// Program ID
        id: u32,

        /// Map name
        name: String,

        /// Optional: specific key to read (hex or decimal)
        #[arg(short, long)]
        key: Option<String>,
    },

    /// Write to a map
    Write {
        /// Program ID
        id: u32,

        /// Map name
        name: String,

        /// Key (hex with 0x prefix or decimal)
        key: String,

        /// Value (hex with 0x prefix or decimal)
        value: String,
    },

    /// Delete a map entry
    Delete {
        /// Program ID
        id: u32,

        /// Map name
        name: String,

        /// Key (hex with 0x prefix or decimal)
        key: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set up logging
    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::WARN
    };
    FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .init();

    match cli.command {
        Commands::Compile {
            source,
            output,
            includes,
            defines,
            no_btf,
            opt_level,
        } => {
            let mut options = compile::CompileOptions::default();
            options.includes = includes;
            options.btf = !no_btf;
            options.opt_level = opt_level;

            // Parse defines
            for def in defines {
                if let Some((key, value)) = def.split_once('=') {
                    options
                        .defines
                        .push((key.to_string(), Some(value.to_string())));
                } else {
                    options.defines.push((def, None));
                }
            }

            match compile::compile(&source, output.as_deref(), &options) {
                Ok(result) => {
                    if cli.json {
                        let json = serde_json::json!({
                            "success": true,
                            "output": result.output_path.display().to_string(),
                            "warnings": result.warnings
                        });
                        println!("{}", serde_json::to_string_pretty(&json)?);
                    } else {
                        println!(
                            "Compiled: {} -> {}",
                            source.display(),
                            result.output_path.display()
                        );
                        for warning in &result.warnings {
                            println!("  Warning: {}", warning);
                        }
                    }
                    Ok(())
                }
                Err(e) => {
                    if cli.json {
                        let json = serde_json::json!({
                            "success": false,
                            "error": e.to_string()
                        });
                        println!("{}", serde_json::to_string_pretty(&json)?);
                        std::process::exit(1);
                    } else {
                        Err(e)
                    }
                }
            }
        }

        Commands::New {
            template,
            name,
            target,
            output_dir,
        } => {
            let template_type: compile::TemplateType = template.parse()?;
            let content = compile::generate_template(template_type, &name, target.as_deref());

            let output_path = output_dir
                .unwrap_or_else(|| PathBuf::from("."))
                .join(format!("{}.c", name));

            std::fs::write(&output_path, &content)?;

            if cli.json {
                let json = serde_json::json!({
                    "success": true,
                    "path": output_path.display().to_string(),
                    "template": format!("{:?}", template_type),
                    "name": name
                });
                println!("{}", serde_json::to_string_pretty(&json)?);
            } else {
                println!("Created: {}", output_path.display());
                println!("  Template: {:?}", template_type);
                println!("  Next steps:");
                println!("    1. Edit {} as needed", output_path.display());
                println!(
                    "    2. Compile: ebpf-assist compile {}",
                    output_path.display()
                );
                println!("    3. Load: ebpf-assist load {}.o", name);
            }
            Ok(())
        }

        Commands::Load { path, name, isolate } => {
            if isolate {
                vm::load_isolated(&path, name.as_deref(), cli.json).await
            } else {
                commands::load(&path, name.as_deref(), cli.json).await
            }
        }
        Commands::Unload { id } => commands::unload(id, cli.json).await,
        Commands::Attach { id, target } => commands::attach(id, &target, cli.json).await,
        Commands::Detach { id } => commands::detach(id, cli.json).await,
        Commands::List => commands::list(cli.json).await,
        Commands::Status => commands::status(cli.json).await,
        Commands::Ping => commands::ping(cli.json).await,
        Commands::Unlock => commands::unlock(cli.json).await,
        Commands::Lock => commands::lock(cli.json).await,
        Commands::Auth => commands::auth_status(cli.json).await,
        Commands::Trigger(cmd) => trigger::run(cmd).await,
        Commands::Output(cmd) => trigger::output(cmd).await,
        Commands::Map(cmd) => match cmd {
            MapCommands::List { id } => commands::map_list(id, cli.json).await,
            MapCommands::Read { id, name, key } => {
                commands::map_read(id, &name, key.as_deref(), cli.json).await
            }
            MapCommands::Write {
                id,
                name,
                key,
                value,
            } => commands::map_write(id, &name, &key, &value, cli.json).await,
            MapCommands::Delete { id, name, key } => {
                commands::map_delete(id, &name, &key, cli.json).await
            }
        },
        Commands::Vm(cmd) => match cmd {
            VmCommands::Init => vm::init(cli.json).await,
            VmCommands::List => vm::list(cli.json).await,
            VmCommands::Stop { vm_id } => vm::stop(&vm_id, cli.json).await,
            VmCommands::Status { vm_id } => vm::status(&vm_id, cli.json).await,
            VmCommands::Pool => vm::pool_status(cli.json).await,
        },
    }
}
