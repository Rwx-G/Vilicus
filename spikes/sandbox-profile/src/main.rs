//! `e10-spike <subcommand>`: every process of the spike is this one binary.
//!
//! - `core --runtime DIR --gate FILE --peer UNIT[:gated]...` the Core-like listener;
//! - `plugin --socket PATH` the reference plugin: probes its sandbox, then serves;
//! - `probe` the sandbox probes alone;
//! - `probe-ip ADDR:PORT` TCP connect and UDP send, for the IP filter;
//! - `probe-udp ADDR:PORT` UDP send only, for the startup check;
//! - `connect --socket PATH [--leave-after-hello] [--fork-hold]` one session, prints its outcome;
//! - `ipfilter-check [--without-filter]` the host check run before the Core starts;
//! - `late-pidfd` what `SO_PEERPIDFD` gives for a reaped peer on this kernel;
//! - `listen-tcp ADDR:PORT`, `listen-abstract NAME` targets for the probes;
//! - `expected-cgroup UNIT` the cgroup path the Core derives for a unit.

use std::env;
use std::io;
use std::net::TcpListener;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr as UnixAddr, UnixListener};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sandbox_profile::client::{self, Outcome};
use sandbox_profile::core::{self, PeerSpec};
use sandbox_profile::{probe, startup, unit};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn values<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
    args.windows(2)
        .filter(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
        .collect()
}

fn value<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    values(args, flag)
        .first()
        .copied()
        .ok_or_else(|| format!("missing {flag}"))
}

fn run(args: &[String]) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let Some(command) = args.first() else {
        return Err("no subcommand".into());
    };
    let rest = &args[1..];
    match command.as_str() {
        "core" => {
            let peers = values(rest, "--peer")
                .into_iter()
                .map(PeerSpec::parse)
                .collect::<Result<Vec<_>, _>>()?;
            core::run(
                Path::new(value(rest, "--runtime")?),
                &peers,
                Path::new(value(rest, "--gate")?),
            )?;
        }
        "plugin" => {
            probe::all();
            client::plugin(Path::new(value(rest, "--socket")?))?;
        }
        "probe" => probe::all(),
        "probe-ip" => probe::ip(value(args, "probe-ip")?.parse()?),
        "probe-udp" => probe::udp(value(args, "probe-udp")?.parse()?),
        "ipfilter-check" => {
            let with_filter = !rest.iter().any(|a| a == "--without-filter");
            if !startup::ipfilter_check(&env::current_exe()?, with_filter)? {
                return Ok(ExitCode::FAILURE);
            }
        }
        "late-pidfd" => println!("LATE_PIDFD {}", startup::late_pidfd(&env::current_exe()?)?),
        "unshare-child" => probe::unshare_child(value(args, "unshare-child")?.parse()?),
        "connect" => {
            let socket = PathBuf::from(value(rest, "--socket")?);
            let leave = rest.iter().any(|a| a == "--leave-after-hello");
            let fork_hold = rest.iter().any(|a| a == "--fork-hold");
            println!(
                "CLIENT pid={} uid={}",
                std::process::id(),
                // SAFETY: getuid(2) cannot fail and has no preconditions.
                unsafe { libc::getuid() }
            );
            let outcome = client::session(&socket, "-", leave, false, fork_hold);
            match outcome {
                Ok(Outcome::Served) => println!("OUTCOME served"),
                Ok(Outcome::Rejected(reason)) => println!("OUTCOME rejected {reason}"),
                Ok(Outcome::LeftEarly) => println!("OUTCOME left-early"),
                Err(e) => println!("OUTCOME error {e}"),
            }
        }
        "listen-tcp" => {
            let listener = TcpListener::bind(value(args, "listen-tcp")?)?;
            sandbox_profile::notify::ready()?;
            for stream in listener.incoming() {
                drop(stream);
            }
        }
        "listen-abstract" => {
            let name = value(args, "listen-abstract")?;
            let listener = UnixListener::bind_addr(&UnixAddr::from_abstract_name(name)?)?;
            sandbox_profile::notify::ready()?;
            for stream in listener.incoming() {
                drop(stream);
            }
        }
        "expected-cgroup" => {
            let name = value(args, "expected-cgroup")?;
            let path = unit::expected_cgroup(name)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not accepted"))?;
            println!("{path}");
        }
        other => return Err(format!("unknown subcommand {other}").into()),
    }
    Ok(ExitCode::SUCCESS)
}
