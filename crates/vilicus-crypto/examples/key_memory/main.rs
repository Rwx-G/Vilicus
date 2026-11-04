//! The key memory regression harness of Story 4.2 (AC2, AC6, AC7, AC9, AC10), the inspection
//! method of Story 1.10 on the product build: a subject process plants known keys in the locked
//! pool through `vilicus_crypto`, runs one of the crate's key operations and drops the keys; the
//! harness, another process, reads every mapping of the subject through `/proc/<pid>/mem` at
//! each phase and looks for the keys and for every value recomputed from them. Each absence in
//! the product shape is paired with the residue the default shape leaves on the same path: the
//! same operation run on aws-lc-rs directly, keys in ordinary heap memory.
//!
//! `key_memory checks <group>` runs one group of checks and prints one `PASS`, `FAIL`, `SKIP` or
//! `INFO` line per check; `key_memory subject <scenario> <variant> <material>` is the inspected
//! process. `ci/key_memory.py` runs each group in a container given only the capabilities and
//! limits its checks need.

mod checks;
mod material;
mod scan;
mod subject;

use std::path::Path;
use std::process::ExitCode;

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
                "usage: key_memory checks <{}>\n       key_memory subject <scenario> <variant> <material>",
                checks::GROUPS.join("|")
            );
            ExitCode::from(64)
        }
    }
}
