//! Host checks that run before the Core starts, and kernel behaviour the run records.

use std::fs;
use std::io::{self, Write};
use std::net::UdpSocket;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::peer::{errno_name, peer_pidfd, pidfd_alive};

/// Whether the host enforces `IPAddressDeny=any`, checked with a loopback UDP listener this
/// process owns, from a unit outside the filter.
///
/// Control leg: a datagram this process sends to its own listener must arrive, which shows
/// that nothing else (a netfilter rule, for instance) drops loopback traffic. Filtered leg: a
/// transient unit with `IPAddressDeny=any` sends one datagram to the same listener; the send
/// must fail with `EPERM` and nothing may arrive. Anything else fails the check, and the Core
/// does not start. `with_filter = false` leaves the filter off the probe unit, so a test can
/// show that the check refuses a host that does not filter.
pub fn ipfilter_check(bin: &Path, with_filter: bool) -> io::Result<bool> {
    let listener = UdpSocket::bind("127.0.0.1:0")?;
    listener.set_read_timeout(Some(Duration::from_secs(1)))?;
    let target = listener.local_addr()?;
    let mut buffer = [0u8; 64];

    UdpSocket::bind("127.0.0.1:0")?.send_to(b"control", target)?;
    let control = matches!(listener.recv(&mut buffer), Ok(n) if &buffer[..n] == b"control");
    if !control {
        println!("IPFILTER_CHECK fail control-datagram-not-received");
        return Ok(false);
    }

    let mut probe = Command::new("systemd-run");
    probe.args([
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--unit=vilicus-ipfilter-probe",
        "--property=DynamicUser=yes",
    ]);
    if with_filter {
        probe.arg("--property=IPAddressDeny=any");
    }
    let output = probe
        .arg(bin)
        .arg("probe-udp")
        .arg(target.to_string())
        .stdin(Stdio::null())
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let eperm = text.lines().any(|l| l == "PROBE udp_send blocked EPERM");
    let received = listener.recv(&mut buffer).is_ok();
    let passed = output.status.success() && eperm && !received;
    println!(
        "IPFILTER_CHECK {} probe=[{}] datagram_received={received}",
        if passed { "pass" } else { "fail" },
        text.trim().replace('\n', ";")
    );
    Ok(passed)
}

/// What `SO_PEERPIDFD` gives when it is asked for only after the peer has exited and been
/// reaped, on the running kernel: refused (older kernels) or a pidfd of an exited process.
pub fn late_pidfd(bin: &Path) -> io::Result<String> {
    let path = std::env::temp_dir().join(format!("e10-late-{}.sock", std::process::id()));
    match fs::remove_file(&path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let listener = UnixListener::bind(&path)?;
    let mut child = Command::new(bin)
        .arg("connect")
        .arg("--socket")
        .arg(&path)
        .arg("--leave-after-hello")
        .stdout(Stdio::null())
        .spawn()?;
    let (mut stream, _) = listener.accept()?;
    stream.write_all(b"HELLO\n")?;
    child.wait()?;
    let result = match peer_pidfd(&stream) {
        Err(e) => format!("refused({})", errno_name(&e)),
        Ok(pidfd) => format!("returned(alive={})", pidfd_alive(&pidfd)?),
    };
    fs::remove_file(&path)?;
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")?;
    Ok(format!("kernel={} late_pidfd={result}", kernel.trim()))
}
