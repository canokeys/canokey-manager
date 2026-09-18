//! CanoKey management CLI (placeholder binary, filled in from Phase 1 on).

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "ckman",
    version,
    about = "Configure your CanoKey via the command line"
)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
}
