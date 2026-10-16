//! Attempts a sandboxed process makes to reach beyond what its unit grants.
//!
//! Every probe prints one line, `PROBE <name> blocked <reason>` or `PROBE <name> open`, and
//! never decides on its own whether the outcome is good: the checks in `checks.sh` do, per
//! profile, because the same probe must be open under one profile and blocked under another.

use std::env;
use std::fs;
use std::io;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr as UnixAddr, UnixStream};
use std::process::Command;
use std::time::Duration;

use crate::peer::errno_name;

fn report(name: &str, outcome: io::Result<()>) {
    match outcome {
        Ok(()) => println!("PROBE {name} open"),
        Err(e) => println!("PROBE {name} blocked {}", errno_name(&e)),
    }
}

fn open_socket(domain: libc::c_int, kind: libc::c_int, protocol: libc::c_int) -> io::Result<()> {
    // SAFETY: plain socket(2) call; the returned descriptor is closed right away below.
    let fd = unsafe { libc::socket(domain, kind, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by socket(2) and is owned by nothing else.
    unsafe { libc::close(fd) };
    Ok(())
}

/// Socket families a plugin must not be able to open at all.
pub fn socket_families() {
    let cases = [
        ("socket_inet_tcp", libc::AF_INET, libc::SOCK_STREAM, 0),
        ("socket_inet6_tcp", libc::AF_INET6, libc::SOCK_STREAM, 0),
        ("socket_inet_udp", libc::AF_INET, libc::SOCK_DGRAM, 0),
        (
            "socket_inet_raw",
            libc::AF_INET,
            libc::SOCK_RAW,
            libc::IPPROTO_ICMP,
        ),
        ("socket_packet", libc::AF_PACKET, libc::SOCK_RAW, 0),
        (
            "socket_netlink",
            libc::AF_NETLINK,
            libc::SOCK_RAW,
            libc::NETLINK_ROUTE,
        ),
    ];
    for (name, domain, kind, protocol) in cases {
        report(name, open_socket(domain, kind, protocol));
    }
}

/// Filesystem Unix sockets a plugin is not granted: the system bus, systemd's private socket,
/// the journal's stream socket, and another plugin's Core socket.
pub const PATH_PROBES: &[(&str, &str)] = &[
    ("dbus_system_bus", "/run/dbus/system_bus_socket"),
    ("systemd_private", "/run/systemd/private"),
    ("journal_stdout", "/run/systemd/journal/stdout"),
    (
        "other_peer",
        "/run/vilicus/core/peer/vilicus-plugin@other.service/core.sock",
    ),
];

/// Abstract Unix sockets listening in the host's network namespace (`run.sh` starts one).
pub const ABSTRACT_PROBES: &[(&str, &str)] = &[("abstract_host", "e10-abstract")];

/// Every probe, in a fixed order.
pub fn all() {
    socket_families();
    for (name, path) in PATH_PROBES {
        unix_path(name, path);
    }
    for (name, abstract_name) in ABSTRACT_PROBES {
        unix_abstract(name, abstract_name);
    }
    namespaces();
    proc_visibility();
    writes();
}

/// Connects to a filesystem Unix socket the probe was not granted.
pub fn unix_path(name: &str, path: &str) {
    report(name, UnixStream::connect(path).map(drop));
}

/// Connects to an abstract Unix socket, which no file permission protects.
pub fn unix_abstract(name: &str, abstract_name: &str) {
    let outcome = UnixAddr::from_abstract_name(abstract_name.as_bytes())
        .and_then(|addr| UnixStream::connect_addr(&addr))
        .map(drop);
    report(name, outcome);
}

/// Runs `unshare(flags)` in a child process, so a success does not move this process.
pub fn namespaces() {
    let cases = [
        ("unshare_net", libc::CLONE_NEWNET),
        ("unshare_user_net", libc::CLONE_NEWUSER | libc::CLONE_NEWNET),
    ];
    for (name, flags) in cases {
        let outcome = env::current_exe().and_then(|exe| {
            Command::new(exe)
                .arg("unshare-child")
                .arg(flags.to_string())
                .output()
        });
        match outcome {
            Ok(output) => {
                let text = String::from_utf8_lossy(&output.stdout);
                println!("PROBE {name} {}", text.trim());
            }
            Err(e) => println!("PROBE {name} blocked spawn-{}", errno_name(&e)),
        }
    }
}

/// Body of the `unshare-child` subcommand.
pub fn unshare_child(flags: libc::c_int) {
    // SAFETY: unshare(2) only changes this short-lived child's namespaces.
    let rc = unsafe { libc::unshare(flags) };
    if rc == 0 {
        println!("open");
    } else {
        println!("blocked {}", errno_name(&io::Error::last_os_error()));
    }
}

/// Counts processes of other users visible in `/proc`.
pub fn proc_visibility() {
    let me = std::process::id().to_string();
    let others = fs::read_dir("/proc").map(|entries| {
        entries
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.bytes().all(|b| b.is_ascii_digit()) && *name != me)
            .count()
    });
    match others {
        Ok(0) => println!("PROBE proc_other_pids blocked none-visible"),
        Ok(count) => println!("PROBE proc_other_pids open {count}"),
        Err(e) => println!("PROBE proc_other_pids blocked {}", errno_name(&e)),
    }
}

/// Tries to create files outside the unit's writable paths.
pub fn writes() {
    for (name, path) in [
        ("write_etc", "/etc/e10-probe"),
        ("write_var_lib", "/var/lib/e10-probe"),
        ("write_usr", "/usr/local/bin/e10-probe"),
    ] {
        report(name, fs::write(path, b"x"));
    }
    report(
        "read_root_home",
        fs::read_dir("/root").and_then(|mut entries| entries.next().transpose().map(drop)),
    );
}

/// TCP connect and UDP send to one address, for the IP filter checks.
pub fn ip(target: SocketAddr) {
    report(
        "tcp_connect",
        TcpStream::connect_timeout(&target, Duration::from_secs(3)).map(drop),
    );
    udp(target);
}

/// One UDP datagram to `target`, from an ephemeral port.
pub fn udp(target: SocketAddr) {
    let unspecified: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid literal")
    } else {
        "[::]:0".parse().expect("valid literal")
    };
    report(
        "udp_send",
        UdpSocket::bind(unspecified).and_then(|socket| socket.send_to(b"probe", target).map(drop)),
    );
}
