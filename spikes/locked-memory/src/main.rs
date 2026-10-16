//! `locked-memory checks <group>` runs the harness; `locked-memory subject <scenario> <variant>
//! <material>` is the process the harness inspects.

use std::path::Path;
use std::process::ExitCode;

use locked_memory::{checks, subject};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("checks") if args.len() == 3 => {
            let mut report = checks::Report::default();
            if let Err(error) = checks::run(&args[2], &mut report) {
                println!("FAIL harness-{}: {error}", args[2]);
                return ExitCode::FAILURE;
            }
            if report.failures() == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Some("subject") if args.len() == 5 => {
            let code = subject::run(&args[2], &args[3], Path::new(&args[4]));
            ExitCode::from(u8::try_from(code).unwrap_or(1))
        }
        _ => {
            eprintln!(
                "usage: locked-memory checks <main|noptrace|nomemlock|swap>\n       locked-memory subject <scenario> <variant> <material>"
            );
            ExitCode::from(64)
        }
    }
}
