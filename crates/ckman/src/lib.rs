//! CanoKey management CLI, pure Rust on top of libcanokey.
//!
//! This library target holds the CLI definition (shared with the man-page
//! generator) and the entry-point logic; `main.rs` is a thin wrapper.

pub mod cli;
pub mod commands;
mod diagnose;

use clap::Parser;

use cli::{Cli, Commands};

/// The `ckman` entry point.
pub fn run() -> std::process::ExitCode {
    let cli = Cli::parse();
    if let Some(level) = cli.log_level {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(level)
            .with_writer(std::io::stderr);
        match &cli.log_file {
            Some(path) => match std::fs::File::create(path) {
                Ok(file) => subscriber.with_writer(std::sync::Mutex::new(file)).init(),
                Err(error) => {
                    eprintln!("ERROR: cannot open log file {path}: {error}");
                    return std::process::ExitCode::FAILURE;
                }
            },
            None => subscriber.init(),
        }
    }
    if cli.diagnose {
        return match diagnose::run() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("ERROR: {error}");
                std::process::ExitCode::FAILURE
            }
        };
    }
    let Some(command) = &cli.command else {
        let _ = <Cli as clap::CommandFactory>::command().print_help();
        eprintln!();
        return std::process::ExitCode::FAILURE;
    };
    let result = match command {
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
        Commands::Completions { shell } => {
            use std::io::Write as _;
            let mut command = <Cli as clap::CommandFactory>::command();
            let mut buffer = Vec::new();
            clap_complete::generate(*shell, &mut command, "ckman", &mut buffer);
            // A closed pipe (e.g. `ckman completions bash | head`) is not an error.
            match std::io::stdout().write_all(&buffer) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                Err(error) => Err(error.into()),
            }
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
