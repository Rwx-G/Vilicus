//! Peer side: the reference plugin, and the one-shot client the impersonation checks run.

use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

/// How one connection to the Core ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The Core asked for and accepted a response.
    Served,
    /// The Core refused the peer, with the reason the spike Core sends back.
    Rejected(String),
    /// The client left after the Core's hello, before any verification.
    LeftEarly,
}

/// Reads the plugin's one credential from the directory systemd gives it.
pub fn read_credential(name: &str) -> io::Result<String> {
    let dir = env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no CREDENTIALS_DIRECTORY"))?;
    Ok(fs::read_to_string(dir.join(name))?.trim().to_owned())
}

/// One session with the Core: waits for its hello, answers its request, then, when `hold` is
/// set, stays connected until the Core closes the connection. With `fork_hold`, the process
/// forks where the session would end: the parent returns, and the child keeps the connection
/// open until the Core closes it, then prints `HELD_CLOSED` and exits.
pub fn session(
    socket: &Path,
    credential: &str,
    leave_after_hello: bool,
    hold: bool,
    fork_hold: bool,
) -> io::Result<Outcome> {
    let outcome = exchange(socket, credential, leave_after_hello, hold)?;
    match outcome {
        (outcome, Some(stream)) if fork_hold => {
            // SAFETY: the client is single-threaded, so the child may keep running Rust code.
            match unsafe { libc::fork() } {
                -1 => Err(io::Error::last_os_error()),
                0 => {
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    while reader.read_line(&mut line).unwrap_or(0) > 0 {
                        line.clear();
                    }
                    println!("HELD_CLOSED");
                    std::process::exit(0);
                }
                _ => Ok(outcome),
            }
        }
        (outcome, _) => Ok(outcome),
    }
}

fn exchange(
    socket: &Path,
    credential: &str,
    leave_after_hello: bool,
    hold: bool,
) -> io::Result<(Outcome, Option<UnixStream>)> {
    let mut stream = UnixStream::connect(socket)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.trim() != "HELLO" {
        return Ok((Outcome::Rejected(line.trim().to_owned()), None));
    }
    if leave_after_hello {
        return Ok((Outcome::LeftEarly, Some(stream)));
    }
    line.clear();
    reader.read_line(&mut line)?;
    let Some(nonce) = line.trim().strip_prefix("REQ ") else {
        let reason = line.trim().strip_prefix("REJECT ").unwrap_or(line.trim());
        return Ok((Outcome::Rejected(reason.to_owned()), None));
    };
    writeln!(stream, "RESP {nonce} {credential}")?;
    line.clear();
    reader.read_line(&mut line)?;
    if line.trim() != "OK" {
        return Ok((
            Outcome::Rejected(format!("after-response:{}", line.trim())),
            None,
        ));
    }
    if hold {
        println!("SERVED");
        line.clear();
        while reader.read_line(&mut line)? > 0 {
            line.clear();
        }
    }
    Ok((Outcome::Served, Some(stream)))
}

/// The reference plugin: serves the Core, and reconnects whenever the Core goes away.
pub fn plugin(socket: &Path) -> io::Result<()> {
    let credential = read_credential("token")?;
    println!("CREDENTIAL read len={}", credential.len());
    loop {
        match session(socket, &credential, false, true, false) {
            Ok(Outcome::Served) => println!("CORE_GONE"),
            Ok(other) => println!("SESSION {other:?}"),
            Err(e) => println!("CONNECT_ERROR {e}"),
        }
        thread::sleep(Duration::from_millis(200));
    }
}
