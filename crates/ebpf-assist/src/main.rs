//! ebpf-assist - CLI for managing eBPF programs.

mod client;
mod commands;
mod trigger;

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

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Load an eBPF program from a file
    Load {
        /// Path to the eBPF object file
        path: std::path::PathBuf,

        /// Name of the program within the object file (required if multiple)
        #[arg(short, long)]
        name: Option<String>,
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

    /// Trigger kernel activity for testing eBPF programs
    #[command(subcommand)]
    Trigger(TriggerCommands),

    /// Read output from eBPF programs (trace_pipe, maps, etc.)
    #[command(subcommand)]
    Output(OutputCommands),
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

    /// Dump a BPF map (future feature)
    Map {
        /// Map name or ID
        name: String,

        /// Output format (json, table)
        #[arg(short, long, default_value = "table")]
        format: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set up logging
    let level = if cli.verbose { Level::DEBUG } else { Level::WARN };
    FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .init();

    match cli.command {
        Commands::Load { path, name } => commands::load(&path, name.as_deref()).await,
        Commands::Unload { id } => commands::unload(id).await,
        Commands::Attach { id, target } => commands::attach(id, &target).await,
        Commands::Detach { id } => commands::detach(id).await,
        Commands::List => commands::list().await,
        Commands::Status => commands::status().await,
        Commands::Ping => commands::ping().await,
        Commands::Trigger(cmd) => trigger::run(cmd).await,
        Commands::Output(cmd) => trigger::output(cmd).await,
    }
}
