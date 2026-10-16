//! Kernel behaviour the Core's check rests on, outside systemd: the evidence read at accept
//! time, what a pidfd says once the peer that connected has exited, the order of the Core's
//! verification, and the end of a connection whose process exited while another holds it.

use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use sandbox_profile::core::verify_with;
use sandbox_profile::peer::{
    Watch, peer_cred, peer_pidfd, pidfd_alive, pidfd_pid, read_evidence, watch,
};

fn socket_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("e10-{name}-{}.sock", std::process::id()))
}

/// Binds a fresh socket and starts `e10-spike connect` on it with `extra` arguments.
fn listen_and_connect(name: &str, extra: &[&str]) -> (PathBuf, UnixListener, Child) {
    let path = socket_path(name);
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_e10-spike"))
        .args(["connect", "--socket", path.to_str().unwrap()])
        .args(extra)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    (path, listener, child)
}

#[test]
fn verify_rejects_a_peer_that_exits_during_the_membership_read() {
    let (path, listener, mut child) = listen_and_connect("order-exit", &["--leave-after-hello"]);
    let (mut stream, _) = listener.accept().unwrap();
    let evidence = read_evidence(&stream).unwrap();
    let pid = evidence.pid;
    // The reader returns a cgroup.procs that lists the pid, but the peer exits and is reaped
    // while it runs: a check of liveness before the read would accept this peer.
    let verification = verify_with(&Ok("/e10-test.service".into()), &evidence, |_| {
        stream
            .write_all(
                b"HELLO
",
            )
            .unwrap();
        child.wait().unwrap();
        Ok(format!(
            "{pid}
"
        ))
    });
    assert_eq!(verification.cgroup_member, Ok(true));
    assert!(!verification.accepted);
    assert_eq!(verification.reason, "peer-exited");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn verify_accepts_a_peer_alive_after_the_membership_read() {
    let (path, listener, mut child) = listen_and_connect("order-alive", &[]);
    let (mut stream, _) = listener.accept().unwrap();
    let evidence = read_evidence(&stream).unwrap();
    let pid = evidence.pid;
    let verification = verify_with(&Ok("/e10-test.service".into()), &evidence, |_| {
        Ok(format!(
            "1
{pid}
"
        ))
    });
    assert!(verification.accepted);
    assert_eq!(verification.reason, "unit-match");
    let other = verify_with(&Ok("/e10-test.service".into()), &evidence, |_| {
        Ok("1
"
        .into())
    });
    assert_eq!(other.reason, "other-unit");
    stream
        .write_all(
            b"HELLO
REJECT test
",
        )
        .unwrap();
    child.wait().unwrap();
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn watch_reports_the_peer_exit_while_a_forked_child_holds_the_connection() {
    let (path, listener, mut child) =
        listen_and_connect("fork-hold", &["--leave-after-hello", "--fork-hold"]);
    let (mut stream, _) = listener.accept().unwrap();
    let evidence = read_evidence(&stream).unwrap();
    stream
        .write_all(
            b"HELLO
",
        )
        .unwrap();
    child.wait().unwrap();
    // The process that connected is gone, but its forked child keeps the socket open, so the
    // connection never reaches end of file on its own.
    let ended = watch(&stream, &evidence.pidfd, Some(Duration::from_secs(5))).unwrap();
    assert_eq!(ended, Watch::PeerExited);
    stream.shutdown(std::net::Shutdown::Both).unwrap();
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn watch_reports_a_close_while_the_peer_lives() {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let evidence = read_evidence(&ours).unwrap();
    drop(theirs);
    let ended = watch(&ours, &evidence.pidfd, Some(Duration::from_secs(5))).unwrap();
    assert_eq!(ended, Watch::Closed);
    let (ours, _theirs) = UnixStream::pair().unwrap();
    let evidence = read_evidence(&ours).unwrap();
    let ended = watch(&ours, &evidence.pidfd, Some(Duration::from_millis(100))).unwrap();
    assert_eq!(ended, Watch::TimedOut);
}

#[test]
fn evidence_of_a_live_peer_names_it() {
    let (ours, _theirs) = UnixStream::pair().unwrap();
    let evidence = read_evidence(&ours).unwrap();
    let me = i32::try_from(std::process::id()).unwrap();
    assert_eq!(evidence.pid, me);
    // SAFETY: getuid(2) cannot fail.
    assert_eq!(evidence.uid, unsafe { libc::getuid() });
    assert!(pidfd_alive(&evidence.pidfd).unwrap());
    assert_eq!(pidfd_pid(&evidence.pidfd).unwrap(), Some(me));
}

#[test]
fn pidfd_reports_a_peer_that_exited_while_its_pid_stays_in_peercred() {
    let path = socket_path("exited");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_e10-spike"))
        .args([
            "connect",
            "--socket",
            path.to_str().unwrap(),
            "--leave-after-hello",
        ])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    let evidence = read_evidence(&stream).unwrap();
    assert!(pidfd_alive(&evidence.pidfd).unwrap());
    stream.write_all(b"HELLO\n").unwrap();
    assert!(child.wait().unwrap().success());

    assert_eq!(evidence.pid, i32::try_from(child.id()).unwrap());
    assert!(!pidfd_alive(&evidence.pidfd).unwrap());
    assert_eq!(pidfd_pid(&evidence.pidfd).unwrap(), None);
    // SO_PEERCRED still reports the old pid number: on its own it cannot tell that the process
    // is gone, nor that a new process may now hold that number.
    assert_eq!(peer_cred(&stream).unwrap().pid, evidence.pid);
    // A pidfd asked for only now is refused on older kernels; newer ones (seen on 6.18) return
    // a pidfd for the reaped process. Either way it never names a live process.
    match peer_pidfd(&stream) {
        Err(_) => {}
        Ok(late) => assert!(!pidfd_alive(&late).unwrap()),
    }
    std::fs::remove_file(&path).unwrap();
}
