//! CanoKey management CLI, pure Rust on top of libcanokey.
//!
//! This library target holds the CLI definition (shared with the man-page
//! generator) and the entry-point logic; `main.rs` is a thin wrapper.

pub mod cli;
pub mod commands;

use clap::Parser;

use cli::{Cli, Commands};

/// The `ckman` entry point.
pub fn run() -> std::process::ExitCode {
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
        Commands::Config { command } => {
            commands::config::run(cli.device, cli.reader.as_deref(), command)
        }
        Commands::Oath { command } => {
            commands::oath::run(cli.device, cli.reader.as_deref(), command)
        }
        Commands::Piv { command } => commands::piv::run(cli.device, cli.reader.as_deref(), command),
        Commands::Openpgp { command } => {
            commands::openpgp::run(cli.device, cli.reader.as_deref(), command)
        }
        Commands::Fido { command } => {
            commands::fido::run(cli.device, cli.reader.as_deref(), command)
        }
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERROR: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
