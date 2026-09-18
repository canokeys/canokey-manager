//! Command-line interface definition, shared by the `ckman` binary and the
//! man-page generator.

use clap::{Parser, Subcommand};

use crate::commands;

#[derive(Parser)]
#[command(
    name = "ckman",
    version,
    about = "Configure your CanoKey via the command line"
)]
pub struct Cli {
    /// Specify which CanoKey to interact with by serial number.
    #[arg(short, long, value_name = "SERIAL", global = true)]
    pub device: Option<u32>,
    /// Specify a CanoKey by smart card reader name (case-insensitive substring).
    #[arg(
        short,
        long,
        value_name = "NAME",
        conflicts_with = "device",
        global = true
    )]
    pub reader: Option<String>,
    /// Enable logging at the given verbosity level.
    #[arg(short = 'l', long, value_name = "LEVEL")]
    pub log_level: Option<tracing::Level>,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
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
    /// Manage FIDO2/U2F.
    Fido {
        #[command(subcommand)]
        command: commands::fido::FidoCommand,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_and_reader_are_global_options() {
        // Old CLI rewrote argv for this; global args must parse after the
        // subcommand path.
        let cli = Cli::try_parse_from(["ckman", "oath", "info", "--device", "42"]).unwrap();
        assert_eq!(cli.device, Some(42));
        let cli = Cli::try_parse_from(["ckman", "piv", "info", "--reader", "CanoKey"]).unwrap();
        assert_eq!(cli.reader.as_deref(), Some("CanoKey"));
        let cli = Cli::try_parse_from(["ckman", "--device", "7", "list"]).unwrap();
        assert_eq!(cli.device, Some(7));
        // --device and --reader still conflict.
        assert!(Cli::try_parse_from(["ckman", "info", "--device", "1", "--reader", "x"]).is_err());
    }
}
