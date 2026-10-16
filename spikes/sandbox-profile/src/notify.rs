//! `sd_notify(READY=1)` without libsystemd, for `Type=notify` units.

use std::env;
use std::io;
use std::os::unix::net::UnixDatagram;

/// Tells systemd the service is ready. Does nothing when not started by systemd.
///
/// Only a path socket is supported: an abstract `@` socket would be unreachable from a unit
/// with `PrivateNetwork=yes`, and systemd uses `/run/systemd/notify`.
pub fn ready() -> io::Result<()> {
    let Some(path) = env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let socket = UnixDatagram::unbound()?;
    socket.send_to(b"READY=1", path)?;
    Ok(())
}
