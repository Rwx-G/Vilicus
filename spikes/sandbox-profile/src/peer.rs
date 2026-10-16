//! What the kernel says about the process at the other end of a Unix stream socket.
//!
//! `SO_PEERCRED` gives the pid, uid and gid recorded when the peer called `connect`.
//! `SO_PEERPIDFD` (Linux 6.5 and later) gives a pidfd for that same process: unlike the pid
//! number, a pidfd can never come to name another process, so it tells whether the peer that
//! connected is still the process now holding that pid.

use std::fs;
use std::io::{self, Read};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// The peer's identity as read once, right after `accept`.
#[derive(Debug)]
pub struct PeerEvidence {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
    pub pidfd: OwnedFd,
}

/// Reads `SO_PEERCRED` and `SO_PEERPIDFD` from a connected Unix stream socket.
///
/// Fails when the kernel has no pidfd to give, which happens when the peer is already reaped.
pub fn read_evidence(socket: &impl AsRawFd) -> io::Result<PeerEvidence> {
    let cred = peer_cred(socket)?;
    let pidfd = peer_pidfd(socket)?;
    Ok(PeerEvidence {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
        pidfd,
    })
}

/// `SO_PEERCRED`: pid, uid and gid of the peer as recorded at `connect`. The pid number is
/// kept even after that process is gone.
pub fn peer_cred(socket: &impl AsRawFd) -> io::Result<libc::ucred> {
    let fd = socket.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` is a valid, writable `ucred` and `len` holds its exact size, as
    // getsockopt(SO_PEERCRED) requires; the kernel writes at most `len` bytes.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred)
}

/// `SO_PEERPIDFD`: a new pidfd for the peer process. Fails once that process is reaped.
pub fn peer_pidfd(socket: &impl AsRawFd) -> io::Result<OwnedFd> {
    let fd = socket.as_raw_fd();
    let mut pidfd: libc::c_int = -1;
    let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `pidfd` is a valid, writable int and `len` holds its size; SO_PEERPIDFD writes one
    // int, a new file descriptor this process then owns.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&raw mut pidfd).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel returned a fresh descriptor that nothing else in this process owns.
    Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
}

/// True while the process behind `pidfd` has not exited.
///
/// A pidfd becomes readable when its process exits, so a zero-timeout poll that reports no
/// event means the process still runs. This needs no permission over the process, unlike
/// `pidfd_send_signal`.
pub fn pidfd_alive(pidfd: &OwnedFd) -> io::Result<bool> {
    let mut entry = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd entry, count 1, zero timeout.
    let rc = unsafe { libc::poll(&raw mut entry, 1, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc == 0)
}

/// How [`watch`] ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Watch {
    /// The process that opened the connection exited, whoever still holds the socket.
    PeerExited,
    /// The other end closed the connection.
    Closed,
    /// The timeout passed with neither.
    TimedOut,
}

/// Waits until the peer process exits or the connection closes, discarding whatever the peer
/// sends meanwhile. `None` waits without limit.
pub fn watch(stream: &UnixStream, pidfd: &OwnedFd, timeout: Option<Duration>) -> io::Result<Watch> {
    let deadline = timeout.map(|t| Instant::now() + t);
    let mut buffer = [0u8; 512];
    loop {
        let wait_ms = match deadline {
            None => -1,
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Ok(Watch::TimedOut);
                }
                libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX)
            }
        };
        let mut entries = [
            libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: two valid pollfd entries, count 2.
        let rc = unsafe { libc::poll(entries.as_mut_ptr(), 2, wait_ms) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if entries[0].revents != 0 {
            return Ok(Watch::PeerExited);
        }
        if entries[1].revents != 0 && (&*stream).read(&mut buffer)? == 0 {
            return Ok(Watch::Closed);
        }
    }
}

/// The pid a pidfd refers to, as `/proc/self/fdinfo` reports it: `None` once the process is
/// reaped (the kernel prints -1).
pub fn pidfd_pid(pidfd: &OwnedFd) -> io::Result<Option<i32>> {
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))?;
    let line = info
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no Pid line in fdinfo"))?;
    let pid: i32 = line
        .trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad Pid line in fdinfo"))?;
    Ok((pid > 0).then_some(pid))
}

/// Short name of an OS error number, for the PASS/FAIL evidence lines.
pub fn errno_name(error: &io::Error) -> String {
    match error.raw_os_error() {
        Some(libc::EPERM) => "EPERM".into(),
        Some(libc::ENOENT) => "ENOENT".into(),
        Some(libc::ESRCH) => "ESRCH".into(),
        Some(libc::EACCES) => "EACCES".into(),
        Some(libc::EINVAL) => "EINVAL".into(),
        Some(libc::EROFS) => "EROFS".into(),
        Some(libc::EAFNOSUPPORT) => "EAFNOSUPPORT".into(),
        Some(libc::ECONNREFUSED) => "ECONNREFUSED".into(),
        Some(libc::ENETUNREACH) => "ENETUNREACH".into(),
        Some(libc::ETIMEDOUT) => "ETIMEDOUT".into(),
        Some(libc::EADDRNOTAVAIL) => "EADDRNOTAVAIL".into(),
        Some(libc::ENOSYS) => "ENOSYS".into(),
        Some(code) => format!("errno{code}"),
        None => format!("{:?}", error.kind()),
    }
}
