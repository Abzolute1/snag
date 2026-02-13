#![allow(dead_code)]

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod app;
mod config;
mod crypto;
mod discovery;
mod headless;
mod network;
mod protocol;
mod qr;
mod relay_server;
mod share_code;
mod state;
mod transfer;
mod ui;
mod updater;

#[cfg(test)]
mod e2e_tests;

#[derive(Parser)]
#[command(name = "snag", version, about = "P2P file sharing from your terminal")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Send files to someone
    #[command(alias = "s")]
    Send {
        /// Files or directories to share
        paths: Vec<PathBuf>,

        /// Port to listen on (0 for random)
        #[arg(short, long, default_value = "0")]
        port: u16,

        /// Read from stdin instead of files
        #[arg(long)]
        pipe: bool,

        /// Bind address for the listener
        #[arg(long)]
        bind: Option<String>,

        /// Disable compression
        #[arg(long)]
        no_compress: bool,

        /// Auto-stop after duration (e.g. 30m, 2h, 1h30m)
        #[arg(long, conflicts_with = "until")]
        timer: Option<String>,

        /// Auto-stop at clock time (24h format, e.g. 18:00)
        #[arg(long, conflicts_with = "timer")]
        until: Option<String>,

        /// Auto-stop after N completed downloads
        #[arg(long)]
        downloads: Option<u32>,

        /// Show detailed connection diagnostics
        #[arg(short, long)]
        verbose: bool,
    },
    /// Receive files using a share code
    #[command(alias = "r")]
    Receive {
        /// Share code from the sender
        code: String,

        /// Output directory for downloaded files
        #[arg(short, long, default_value = ".")]
        output: PathBuf,

        /// Write received data to stdout (for piping)
        #[arg(long)]
        pipe: bool,

        /// Overwrite existing files instead of renaming
        #[arg(long)]
        overwrite: bool,

        /// Accept transfer without confirmation prompt
        #[arg(short, long)]
        yes: bool,

        /// Show detailed connection diagnostics
        #[arg(short, long)]
        verbose: bool,
    },
    /// Discover peers sharing files on your local network
    #[command(alias = "d")]
    Discover {
        /// How long to scan in seconds
        #[arg(short, long, default_value = "5")]
        timeout: u64,
    },
    /// Show default configuration
    #[command(alias = "cfg")]
    Config,
    /// Start a relay server for NAT traversal
    Relay {
        /// Port to listen on
        #[arg(long, default_value = "19816")]
        port: u16,

        /// Maximum number of concurrent relay rooms
        #[arg(long, default_value = "1000")]
        max_rooms: usize,
    },
    /// Update snag to the latest version
    #[command(alias = "u")]
    Update {
        /// Only check for updates, don't install
        #[arg(long)]
        check: bool,

        /// Force reinstall even if already up to date
        #[arg(long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        match cli.command {
            // Subcommands -> headless mode
            Some(Commands::Send {
                paths,
                port,
                pipe,
                bind,
                no_compress,
                timer,
                until,
                downloads,
                verbose,
            }) => {
                headless::headless_send(
                    paths,
                    port,
                    pipe,
                    bind,
                    no_compress,
                    timer,
                    until,
                    downloads,
                    verbose,
                )
                .await
            }
            Some(Commands::Receive {
                code,
                output,
                pipe,
                overwrite,
                yes,
                verbose,
            }) => headless::headless_receive(code, output, pipe, overwrite, yes, verbose).await,
            Some(Commands::Discover { timeout }) => headless::run_discover(timeout).await,
            Some(Commands::Config) => {
                print!("{}", crate::config::Config::dump_default());
                Ok(())
            }
            Some(Commands::Relay { port, max_rooms }) => {
                relay_server::run_relay(port, max_rooms).await
            }
            Some(Commands::Update { check, force }) => updater::run_update(check, force).await,
            // No subcommand -> interactive TUI dashboard
            None => app::run_main_menu().await,
        }
    })
}
