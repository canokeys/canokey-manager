//! CanoKey management CLI.
//!
//! Phase 1 scope: `list` and `info` over PC/SC. Later phases add
//! config/oath/piv/openpgp/fido subcommands on top of the same device
//! selection and probing pipeline.

mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "ckman",
    version,
    about = "Configure your CanoKey via the command line"
)]
struct Cli {
    /// Specify which CanoKey to interact with by serial number.
    #[arg(short, long, value_name = "SERIAL")]
    device: Option<u32>,
    /// Specify a CanoKey by smart card reader name.
    #[arg(short, long, value_name = "NAME", conflicts_with = "device")]
    reader: Option<String>,
    /// Enable logging at the given verbosity level.
    #[arg(short = 'l', long, value_name = "LEVEL")]
    log_level: Option<tracing::Level>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show general information about the device.
    Info,
    /// List connected CanoKeys.
    List {
        /// Only output serial numbers, one per line.
        #[arg(long)]
        serials: bool,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    if let Some(level) = cli.log_level {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(level)
            .init();
    }
    let result = match &cli.command {
        Commands::Info => commands::info::run(cli.device, cli.reader.as_deref()),
        Commands::List { serials } => commands::list::run(*serials, cli.reader.as_deref()),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERROR: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
