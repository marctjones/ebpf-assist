//! ebpf-assist - CLI for managing eBPF programs.

mod client;
mod commands;

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
    }
}
