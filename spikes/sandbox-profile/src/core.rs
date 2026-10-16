//! A Core-like listener: one socket per peer unit, each connection identified before it is served.
//!
//! The socket of unit `U` is `<runtime>/peer/U/core.sock`. `<runtime>/peer` is mode 0700, so
//! no other account reaches it by path; the per-unit directory is bind-mounted into `U`'s
//! namespace by its unit file, which is how only `U` reaches its socket. The identity check
//! below is the second layer, for the case where the first one fails.

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::peer::{PeerEvidence, Watch, errno_name, pidfd_alive, read_evidence, watch};
use crate::unit::{cgroup_dir, leaf, parse_proc_cgroup, procs_contains};

/// Connections one peer socket may have open at once, verified or waiting to be; more are
/// closed at accept. A peer instance needs one.
pub const MAX_CONNECTIONS_PER_PEER: usize = 8;
/// Longest line the Core reads from a peer.
pub const MAX_LINE: u64 = 4096;
/// How long the Core waits for a peer's response.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// One peer unit the Core expects.
#[derive(Clone, Debug)]
pub struct PeerSpec {
    pub unit: String,
    /// Hold every connection on this socket until the gate file exists, before verifying it.
    /// Only the pid reuse test uses it, to open the window a real race would need.
    pub gated: bool,
    /// The unit's cgroup as systemd reports it, pinned at its first successful read.
    cgroup: Arc<OnceLock<String>>,
    in_flight: Arc<AtomicUsize>,
}

impl PeerSpec {
    /// Parses `UNIT` or `UNIT:gated`. The name becomes a directory name, so it may not hold a
    /// slash or start with a dot.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (unit, gated) = match text.strip_suffix(":gated") {
            Some(unit) => (unit, true),
            None => (text, false),
        };
        if unit.is_empty() || unit.contains('/') || unit.starts_with('.') {
            return Err(format!("unit name not accepted: {unit}"));
        }
        Ok(Self {
            unit: unit.to_owned(),
            gated,
            cgroup: Arc::new(OnceLock::new()),
            in_flight: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// The unit's cgroup path, asked of systemd (`ControlGroup`) until it is known, then pinned.
    /// systemd reports an empty path while the unit is inactive, so it cannot be read before the
    /// peer has started; the first connection of an active unit pins it.
    pub fn cgroup(&self) -> Result<String, String> {
        if let Some(path) = self.cgroup.get() {
            return Ok(path.clone());
        }
        let output = Command::new("systemctl")
            .args(["show", "--property=ControlGroup", "--value", &self.unit])
            .output()
            .map_err(|e| format!("systemctl-{}", errno_name(&e)))?;
        let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !output.status.success() || !path.starts_with('/') {
            return Err("unit-cgroup-unknown".into());
        }
        Ok(self.cgroup.get_or_init(|| path).clone())
    }
}

/// Everything the Core learned about one connection, and its decision.
#[derive(Debug)]
pub struct Verification {
    pub pid: i32,
    pub uid: u32,
    /// The pid is in the expected unit's `cgroup.procs` (or why that could not be read).
    pub cgroup_member: Result<bool, String>,
    /// The pidfd still names a running process after the membership read.
    pub pidfd_alive: bool,
    /// `/proc/<pid>/cgroup` as the Core can read it, for comparison only.
    pub proc_cgroup: Result<String, String>,
    pub accepted: bool,
    pub reason: &'static str,
}

impl Verification {
    /// One log line with every method's view, so the checks can compare them.
    pub fn log_line(&self, unit: &str) -> String {
        let member = match &self.cgroup_member {
            Ok(true) => "yes".to_owned(),
            Ok(false) => "no".to_owned(),
            Err(e) => format!("unreadable({e})"),
        };
        let (proc_cgroup, leaf_check) = match &self.proc_cgroup {
            Ok(path) => (
                path.clone(),
                if leaf(path) == unit {
                    "accept"
                } else {
                    "reject"
                },
            ),
            Err(e) => (format!("unreadable({e})"), "unreadable"),
        };
        let pid_only = if matches!(self.cgroup_member, Ok(true)) {
            "accept"
        } else {
            "reject"
        };
        format!(
            "DECISION unit={unit} pid={} uid={} cgroup_member={member} pidfd_alive={} \
             pid_only_check={pid_only} proc_cgroup={proc_cgroup} leaf_check={leaf_check} \
             verdict={} reason={}",
            self.pid,
            self.uid,
            self.pidfd_alive,
            if self.accepted { "accept" } else { "reject" },
            self.reason
        )
    }
}

/// Decides whether the peer behind `evidence` is a process of the unit whose cgroup is
/// `cgroup`, reading that cgroup's `cgroup.procs` through `read_procs`.
///
/// Order matters: membership is read first, then the pidfd is checked. If the process that
/// connected was still running after the read, its pid could not have been reused before it,
/// so the pid found in `cgroup.procs` was that process. `read_procs` is a parameter so a test
/// can make the peer exit during the read.
pub fn verify_with(
    cgroup: &Result<String, String>,
    evidence: &PeerEvidence,
    read_procs: impl FnOnce(&Path) -> io::Result<String>,
) -> Verification {
    let cgroup_member = cgroup.clone().and_then(|path| {
        read_procs(&cgroup_dir(&path).join("cgroup.procs"))
            .map(|procs| procs_contains(&procs, evidence.pid))
            .map_err(|e| errno_name(&e))
    });
    let alive = pidfd_alive(&evidence.pidfd).unwrap_or(false);
    let proc_cgroup = fs::read_to_string(format!("/proc/{}/cgroup", evidence.pid))
        .map_err(|e| errno_name(&e))
        .and_then(|text| {
            parse_proc_cgroup(&text)
                .map(str::to_owned)
                .ok_or_else(|| "no-v2-line".to_owned())
        });
    let (accepted, reason) = match (&cgroup_member, alive) {
        (Ok(true), true) => (true, "unit-match"),
        (Ok(true), false) => (false, "peer-exited"),
        (Ok(false), _) => (false, "other-unit"),
        (Err(_), _) => (false, "cgroup-unreadable"),
    };
    Verification {
        pid: evidence.pid,
        uid: evidence.uid,
        cgroup_member,
        pidfd_alive: alive,
        proc_cgroup,
        accepted,
        reason,
    }
}

/// Creates the per-peer sockets, reports readiness to systemd, and serves until killed.
pub fn run(runtime: &Path, peers: &[PeerSpec], gate: &Path) -> io::Result<()> {
    let peer_root = runtime.join("peer");
    fs::create_dir_all(&peer_root)?;
    fs::set_permissions(&peer_root, fs::Permissions::from_mode(0o700))?;
    let mut listeners = Vec::new();
    for spec in peers {
        let dir = peer_root.join(&spec.unit);
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))?;
        let path = dir.join("core.sock");
        match fs::remove_file(&path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;
        println!("LISTEN unit={} path={}", spec.unit, path.display());
        listeners.push((spec.clone(), listener));
    }
    crate::notify::ready()?;
    let gate: PathBuf = gate.to_owned();
    let handles: Vec<_> = listeners
        .into_iter()
        .map(|(spec, listener)| {
            let gate = gate.clone();
            thread::spawn(move || accept_loop(&spec, &listener, &gate))
        })
        .collect();
    for handle in handles {
        let _ = handle.join();
    }
    Ok(())
}

/// Releases one connection slot of a peer socket when the connection's thread ends.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn accept_loop(spec: &PeerSpec, listener: &UnixListener, gate: &Path) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(e) => {
                println!("ACCEPT_ERROR unit={} error={e}", spec.unit);
                continue;
            }
        };
        if spec.in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS_PER_PEER {
            spec.in_flight.fetch_sub(1, Ordering::SeqCst);
            println!("BUSY unit={} connection closed at accept", spec.unit);
            continue;
        }
        let slot = Slot(Arc::clone(&spec.in_flight));
        let spec = spec.clone();
        let gate = gate.to_owned();
        thread::spawn(move || {
            let _slot = slot;
            if let Err(e) = handle(&spec, stream, &gate) {
                println!("CONNECTION_ERROR unit={} error={e}", spec.unit);
            }
        });
    }
}

fn handle(spec: &PeerSpec, mut stream: UnixStream, gate: &Path) -> io::Result<()> {
    let evidence = match read_evidence(&stream) {
        Ok(evidence) => evidence,
        Err(e) => {
            println!(
                "DECISION unit={} verdict=reject reason=no-pidfd({})",
                spec.unit,
                errno_name(&e)
            );
            stream.write_all(b"REJECT no-pidfd\n")?;
            return Ok(());
        }
    };
    stream.write_all(b"HELLO\n")?;
    if spec.gated {
        wait_for(gate, Duration::from_secs(120));
    }
    let verification = verify_with(&spec.cgroup(), &evidence, |path| fs::read_to_string(path));
    println!("{}", verification.log_line(&spec.unit));
    if !verification.accepted {
        // The reason goes back to the peer only because this is a spike; the product says nothing.
        writeln!(stream, "REJECT {}", verification.reason)?;
        return Ok(());
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    writeln!(stream, "REQ {nonce}")?;
    stream.set_read_timeout(Some(RESPONSE_TIMEOUT))?;
    let mut line = String::new();
    BufReader::new((&stream).take(MAX_LINE)).read_line(&mut line)?;
    let mut words = line.split_whitespace();
    let nonce_ok = words.next() == Some("RESP") && words.next() == Some(&nonce.to_string());
    let credential = words.next().unwrap_or("-");
    println!(
        "SERVED unit={} pid={} nonce_ok={nonce_ok} credential={credential}",
        spec.unit, evidence.pid
    );
    stream.write_all(if nonce_ok { b"OK\n" } else { b"BAD\n" })?;
    stream.set_read_timeout(None)?;
    // The connection lives only as long as the process that opened it: when that process
    // exits, the Core closes the connection even if another process still holds it (a forked
    // child, or a descriptor passed with SCM_RIGHTS), and revokes what was bound to it.
    match watch(&stream, &evidence.pidfd, None)? {
        Watch::PeerExited => {
            println!(
                "PEER_EXITED unit={} pid={} connection closed, bound tokens revoked",
                spec.unit, evidence.pid
            );
            stream.shutdown(Shutdown::Both)?;
        }
        Watch::Closed | Watch::TimedOut => {
            println!("CLOSED unit={} pid={}", spec.unit, evidence.pid);
        }
    }
    Ok(())
}

fn wait_for(path: &Path, limit: Duration) {
    let start = Instant::now();
    while !path.exists() && start.elapsed() < limit {
        thread::sleep(Duration::from_millis(50));
    }
}
