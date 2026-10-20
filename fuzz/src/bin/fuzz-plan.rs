//! The run plan of the fuzz targets, for `ci/fuzz.py`.
//!
//! Without arguments, prints one JSON object per target and line: its name, the shape of its
//! input, its longest input and its memory limits, derived from its socket kind in
//! `vilicus-proto`. With `seeds <directory>`, writes the seed corpus of every target into
//! `<directory>/<target>/`, from the committed vectors and failing inputs. With `decoders`,
//! prints one JSON object: the decoders each target declares and the byte-taking functions that
//! decode nothing, with their reasons, for `ci/check_fuzz_coverage.py`.

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
        [mode] if mode == "decoders" => {
            let targets: Vec<String> = vilicus_fuzz::TARGETS
                .iter()
                .map(|target| {
                    format!(
                        "{}: {}",
                        json_string(target.name),
                        json_list(target.decoders)
                    )
                })
                .collect();
            let reasons: Vec<String> = vilicus_fuzz::NOT_DECODERS
                .iter()
                .map(|(name, reason)| format!("{}: {}", json_string(name), json_string(reason)))
                .collect();
            println!(
                r#"{{"targets": {{{}}}, "not_decoders": {{{}}}}}"#,
                targets.join(", "),
                reasons.join(", ")
            );
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: fuzz-plan [seeds <directory> | decoders]");
            ExitCode::FAILURE
        }
    }
}

/// A JSON string, backslashes and quotes escaped: names and reasons hold no control character.
fn json_string(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

fn json_list(items: &[&str]) -> String {
    let items: Vec<String> = items.iter().map(|item| json_string(item)).collect();
    format!("[{}]", items.join(", "))
}
