//! CanoKey management CLI.
//!
//! Scope so far: `list` and `info` over PC/SC, plus the `config` group
//! (NFC toggle, factory reset, configuration readout). Later phases add
//! oath/piv/openpgp/fido subcommands on top of the same device selection and
//! probing pipeline.

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
    /// Read or change device configuration.
    Config {
        #[command(subcommand)]
        command: commands::config::ConfigCommand,
    },
    /// Manage the OATH application.
    Oath {
        #[command(subcommand)]
        command: commands::oath::OathCommand,
    },
    /// Manage the PIV application.
    Piv {
        #[command(subcommand)]
        command: commands::piv::PivCommand,
    },
    /// Manage the OpenPGP application.
    Openpgp {
        #[command(subcommand)]
        command: commands::openpgp::OpenPgpCommand,
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
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERROR: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
