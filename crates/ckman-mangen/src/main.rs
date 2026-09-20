//! Regenerate the committed man pages under `man/`:
//!
//! ```sh
//! cargo run -p ckman-mangen -- man
//! ```

use ckman::cli::Cli;
use clap::CommandFactory;

fn main() -> std::process::ExitCode {
    let output = match std::env::args().nth(1) {
        Some(dir) => dir,
        None => {
            eprintln!("usage: ckman-mangen <output-dir>");
            return std::process::ExitCode::FAILURE;
        }
    };
    let command = Cli::command();
    match generate(&command, &output, command.get_name().to_string()) {
        Ok(count) => {
            eprintln!("wrote {count} man page(s) to {output}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ERROR: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Render `command`, then one page per subcommand (recursively), with the
/// full hyphenated command name (`ckman-oath-accounts-add.1`).
fn generate(command: &clap::Command, dir: &str, name: String) -> std::io::Result<usize> {
    let mut count = 0;
    let page = command.clone().name(&*name.clone().leak());
    let man = clap_mangen::Man::new(page).source("ckman");
    let mut buffer = Vec::new();
    man.render(&mut buffer)?;
    std::fs::write(format!("{dir}/{name}.1"), buffer)?;
    count += 1;
    for sub in command.get_subcommands().filter(|s| s.get_name() != "help") {
        count += generate(sub, dir, format!("{name}-{}", sub.get_name()))?;
    }
    Ok(count)
}
