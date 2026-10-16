//! Command line: `serve` runs the probe, `report` prints the per-credential table.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use prf_probe::server::{self, Config};
use prf_probe::{probe, store};
use webauthn_rs::prelude::Url;

const USAGE: &str = "usage:
  prf-probe serve <listen-addr> <data-dir> <rp-id> <origin>
  prf-probe report <data-dir>";

fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args {
        [command, listen, dir, rp_id, origin] if command == "serve" => {
            let config = Config {
                listen: listen.parse()?,
                data_dir: PathBuf::from(dir),
                rp_id: rp_id.clone(),
                origin: Url::parse(origin)?,
            };
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(server::serve(config))
        }
        [command, dir] if command == "report" => {
            let records = store::read_records(&PathBuf::from(dir))?;
            print!("{}", probe::render(&probe::summarize(&records)));
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
