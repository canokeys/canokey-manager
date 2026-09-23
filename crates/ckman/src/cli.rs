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
    #[arg(short = 'l', long, value_name = "LEVEL", global = true)]
    pub log_level: Option<tracing::Level>,
    /// Write log output to FILE instead of stderr (requires --log-level).
    #[arg(long, value_name = "FILE", requires = "log_level", global = true)]
    pub log_file: Option<String>,
    /// Print a diagnostic report for bug reports and exit.
    #[arg(long, global = true)]
    pub diagnose: bool,
    #[command(subcommand)]
    pub command: Option<Commands>,
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
    /// Print shell completions to stdout.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
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
        // Global args must parse after the subcommand path.
        let cli = Cli::try_parse_from(["ckman", "oath", "info", "--device", "42"]).unwrap();
        assert_eq!(cli.device, Some(42));
        let cli = Cli::try_parse_from(["ckman", "piv", "info", "--reader", "CanoKey"]).unwrap();
        assert_eq!(cli.reader.as_deref(), Some("CanoKey"));
        let cli = Cli::try_parse_from(["ckman", "--device", "7", "list"]).unwrap();
        assert_eq!(cli.device, Some(7));
        // --device and --reader still conflict.
        assert!(Cli::try_parse_from(["ckman", "info", "--device", "1", "--reader", "x"]).is_err());
    }

    #[test]
    fn piv_extended_algorithms_parse() {
        for arg in [
            "rsa1024",
            "rsa2048",
            "rsa3072",
            "rsa4096",
            "ecc-p256",
            "ecc-p384",
            "ecc-p521",
            "secp256k1",
            "sm2",
            "ed25519",
            "x25519",
            "ml-dsa65",
            "ml-kem768",
        ] {
            Cli::try_parse_from(["ckman", "piv", "keys", "generate", "9a", "-", "-a", arg])
                .unwrap_or_else(|e| panic!("{arg}: {e}"));
        }
        assert!(Cli::try_parse_from([
            "ckman", "piv", "keys", "generate", "9a", "-", "-a", "ecc25519"
        ])
        .is_err());
    }

    #[test]
    fn diagnose_and_log_file_parse() {
        let cli = Cli::try_parse_from(["ckman", "--diagnose"]).unwrap();
        assert!(cli.diagnose);
        assert!(cli.command.is_none());
        let cli = Cli::try_parse_from([
            "ckman",
            "info",
            "--log-level",
            "info",
            "--log-file",
            "f.log",
        ])
        .unwrap();
        assert_eq!(cli.log_file.as_deref(), Some("f.log"));
        // --log-file requires --log-level.
        assert!(Cli::try_parse_from(["ckman", "info", "--log-file", "f.log"]).is_err());
        assert!(Cli::try_parse_from(["ckman", "--diagnose", "--device", "1"]).is_ok());
    }

    #[test]
    fn feature_subcommands_parse() {
        for argv in [
            &["ckman", "config", "led", "on"][..],
            &["ckman", "config", "ndef-read-only", "off"][..],
            &["ckman", "config", "webusb-landing", "on"][..],
            &["ckman", "config", "pass", "info"][..],
            &[
                "ckman", "config", "pass", "set", "short", "static", "--enter",
            ][..],
            &[
                "ckman", "config", "pass", "set", "long", "hmac", "--key", "00",
            ][..],
            &["ckman", "config", "ndef", "read"][..],
            &["ckman", "config", "ndef", "write", "-"][..],
            &["ckman", "config", "keyboard", "layout"][..],
            &["ckman", "config", "keyboard", "read-keymap", "-"][..],
            &[
                "ckman",
                "config",
                "keyboard",
                "write-keymap",
                "--layout",
                "1",
                "f.bin",
            ][..],
            &["ckman", "config", "keyboard", "clear-keymap"][..],
            &["ckman", "config", "keyboard", "return", "on"][..],
            &["ckman", "config", "sm2"][..],
            &["ckman", "config", "sm2", "set", "--curve-id", "9"][..],
            &["ckman", "config", "sm2", "set", "--algorithm-id=-54"][..],
            &["ckman", "config", "admin-pin", "change"][..],
            &["ckman", "config", "admin-pin", "status"][..],
            &["ckman", "openpgp", "cardholder", "set-name", "Alice"][..],
            &["ckman", "openpgp", "cardholder", "set-sex", "female"][..],
            &["ckman", "openpgp", "access", "set-touch-cache", "15"][..],
            &["ckman", "openpgp", "keys", "export", "sig", "-"][..],
            &[
                "ckman",
                "oath",
                "accounts",
                "set-default",
                "test",
                "--slot",
                "long",
                "--enter",
            ][..],
            &["ckman", "piv", "objects", "name", "9a", "My Key"][..],
            &["ckman", "piv", "objects", "name", "f9"][..],
            &["ckman", "piv", "sign", "9c", "-", "-"][..],
            &["ckman", "piv", "sign", "9c", "m.bin", "s.bin", "--raw"][..],
            &["ckman", "piv", "decrypt", "9d", "c.bin", "p.bin"][..],
            &["ckman", "piv", "derive", "9d", "peer.bin", "-"][..],
            &["ckman", "piv", "decapsulate", "9d", "ct.bin", "ss.bin"][..],
            &[
                "ckman",
                "piv",
                "agree-sm2",
                "9d",
                "--peer-static",
                "s.bin",
                "--peer-ephemeral",
                "e.bin",
                "key.bin",
            ][..],
            &["ckman", "piv", "random", "32"][..],
            &["ckman", "piv", "random", "32", "rand.bin"][..],
            &["ckman", "piv", "logout"][..],
            &["ckman", "piv", "keys", "generate-batch", "--slots", "9a,9c"][..],
            &["ckman", "completions", "bash"][..],
            &["ckman", "completions", "zsh"][..],
            &["ckman", "oath", "serial"][..],
            &["ckman", "oath", "challenge-response", "short", "deadbeef"][..],
            &[
                "ckman",
                "oath",
                "challenge-response",
                "long",
                "--text",
                "hi",
            ][..],
            &["ckman", "fido", "touch-test"][..],
            &["ckman", "fido", "config", "enable-long-touch-for-reset"][..],
            &[
                "ckman",
                "fido",
                "credentials",
                "update-user",
                "abcd",
                "-u",
                "x",
            ][..],
            &["ckman", "fido", "blobs", "read", "-"][..],
            &["ckman", "fido", "blobs", "write", "f.bin"][..],
        ] {
            Cli::try_parse_from(argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
        }
        // update-user requires at least one field to change.
        assert!(
            Cli::try_parse_from(["ckman", "fido", "credentials", "update-user", "abcd"]).is_err()
        );
        // --raw conflicts with --hash; generate-batch requires --slots.
        assert!(Cli::try_parse_from([
            "ckman", "piv", "sign", "9c", "-", "-", "--raw", "--hash", "sha256"
        ])
        .is_err());
        assert!(Cli::try_parse_from(["ckman", "piv", "keys", "generate-batch"]).is_err());
        // write-keymap requires --layout.
        assert!(
            Cli::try_parse_from(["ckman", "config", "keyboard", "write-keymap", "f.bin"]).is_err()
        );
        // sm2 set requires at least one identifier.
        assert!(Cli::try_parse_from(["ckman", "config", "sm2", "set"]).is_err());
        // Negative algorithm identifiers parse as values, not flags.
        let cli = Cli::try_parse_from(["ckman", "config", "sm2", "set", "--algorithm-id", "-54"])
            .unwrap();
        let Some(Commands::Config { command }) = cli.command else {
            panic!("expected config command")
        };
        let commands::config::ConfigCommand::Sm2 {
            command:
                Some(commands::config::Sm2Command::Set {
                    algorithm_id: Some(-54),
                    ..
                }),
        } = command
        else {
            panic!("expected sm2 set --algorithm-id -54")
        };
    }
}
