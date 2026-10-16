//! Runs every E17 check and prints one `PASS <name>` or `FAIL <name>` line per check,
//! each followed by indented evidence. Exits non-zero when any check fails.

use std::process::ExitCode;

use secure_delete_wal::checks;

fn main() -> ExitCode {
    match checks::environment() {
        Ok(lines) => lines.iter().for_each(|line| println!("INFO {line}")),
        Err(error) => println!("INFO environment unavailable: {error}"),
    }
    let mut failures = 0;
    for check in checks::all() {
        match check.run() {
            Ok(evidence) => {
                println!("PASS {}", check.name);
                evidence.iter().for_each(|line| println!("  {line}"));
            }
            Err(error) => {
                failures += 1;
                println!("FAIL {}", check.name);
                println!("  {error}");
            }
        }
    }
    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
