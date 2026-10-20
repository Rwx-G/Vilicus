//! The run plan of the fuzz targets, for `ci/fuzz.py`.
//!
//! Without arguments, prints one JSON object per target and line: its name, the shape of its
//! input, its longest input and its memory limits, derived from its socket kind in
//! `vilicus-proto`. With `seeds <directory>`, writes the seed corpus of every target into
//! `<directory>/<target>/`, from the committed vectors and failing inputs.

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [] => {
            for target in vilicus_fuzz::TARGETS {
                println!(
                    r#"{{"name": "{}", "input": "{}", "max_len": {}, "malloc_limit_mb": {}, "rss_limit_mb": {}}}"#,
                    target.name,
                    target.input.as_str(),
                    target.max_len(),
                    target.malloc_limit_mib(),
                    target.rss_limit_mib()
                );
            }
            ExitCode::SUCCESS
        }
        [mode, directory] if mode == "seeds" => {
            for target in vilicus_fuzz::TARGETS {
                let corpus = Path::new(directory).join(target.name);
                std::fs::create_dir_all(&corpus).expect("seed directory");
                for (index, seed) in target.seeds().iter().enumerate() {
                    std::fs::write(corpus.join(format!("seed-{index:06}")), seed)
                        .expect("seed file");
                }
            }
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: fuzz-plan [seeds <directory>]");
            ExitCode::FAILURE
        }
    }
}
