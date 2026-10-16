//! The CONNECT proxy: one Unix listener per caller, CONNECT tunnels only, no TLS interception.
//!
//! Per connection, in order: a slot under the caller's connection limit; the peer uid must be
//! the caller's; the request must be one `CONNECT host:port` in HTTP/1.0 or HTTP/1.1, in visible ASCII; the
//! target must be on the caller's allowlist or be one of its named private destinations, which is
//! decided before any lookup, so a refused name never reaches the resolver; then one lookup, a
//! check of every returned address, the host budget, and a dial of exactly the checked addresses
//! under one deadline. The name is never resolved again for that tunnel. A tunnel ends when idle
//! or at its maximum lifetime; for a caller with `sni-check`, its first TLS record must be a
//! ClientHello naming the CONNECT host, without Encrypted Client Hello.

use std::collections::hash_map::RandomState;
use std::future::Future;
use std::hash::BuildHasher;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::address::{self, Prefix};
use crate::budget::Budgets;
use crate::config::{Caller, Config, in_nameable_private};
use crate::sni;
use crate::target::{HostPort, TargetError, parse_authority};

/// Largest CONNECT header accepted, request line included.
pub const MAX_HEADER_BYTES: usize = 8192;

/// Delay before the next address is tried while earlier dials are still pending (RFC 8305's
/// recommended connection attempt delay).
const DIAL_STAGGER: Duration = Duration::from_millis(250);

/// Back-off after an accept error that a busy host can recover from.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Linux `ENFILE`, `EMFILE` and `ECONNABORTED`: the accept loop survives them.
const RECOVERABLE_ACCEPT_ERRNOS: [i32; 3] = [23, 24, 103];

/// Name resolution as the proxy uses it: one lookup per tunnel.
pub trait Resolve: Send + Sync + 'static {
    /// Every address `host` resolves to, with `port`.
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<Vec<SocketAddr>>> + Send;
}

/// The C library resolver (`getaddrinfo`), as `tokio::net::lookup_host` calls it. The name is
/// passed absolute (trailing dot), so no search list is applied. A lookup that times out keeps
/// its blocking thread until the C library returns (story 1.12, Story 5.5 requirement).
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((format!("{host}."), port))
            .await?
            .collect())
    }
}

/// Opening the upstream connection to one checked address.
pub trait Dial: Send + Sync + 'static {
    /// Connects to exactly `addr`.
    fn dial(&self, addr: SocketAddr) -> impl Future<Output = io::Result<TcpStream>> + Send;
}

/// A plain TCP connect.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectDialer;

impl Dial for DirectDialer {
    async fn dial(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect(addr).await
    }
}

/// What the caller asked for, as far as the allowlist goes.
#[derive(Clone, Copy, Debug)]
enum Permission {
    Public,
    Private(Prefix),
}

/// A refusal: the status sent to the caller and the reason logged and returned in a header.
#[derive(Debug)]
struct Refusal {
    status: u16,
    reason: String,
}

fn refusal(status: u16, reason: impl Into<String>) -> Refusal {
    Refusal {
        status,
        reason: reason.into(),
    }
}

/// The proxy shared by every caller's listener.
#[derive(Debug)]
pub struct Proxy<R, D> {
    config: Config,
    budgets: Budgets,
    resolver: R,
    dialer: Arc<D>,
    slots: Vec<Arc<Semaphore>>,
    log_key: RandomState,
    resolve_timeout: Duration,
}

impl<R: Resolve, D: Dial> Proxy<R, D> {
    /// Builds the proxy.
    #[must_use]
    pub fn new(config: Config, resolver: R, dialer: D) -> Self {
        Self {
            budgets: Budgets::new(&config),
            slots: config
                .callers
                .iter()
                .map(|_| Arc::new(Semaphore::new(config.caller_connections)))
                .collect(),
            config,
            resolver,
            dialer: Arc::new(dialer),
            log_key: RandomState::new(),
            resolve_timeout: Duration::from_secs(5),
        }
    }

    /// The configuration in force.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Binds `<dir>/<caller>.sock` for every caller and serves them until a listener fails.
    ///
    /// The socket files are mode 0666 so that the spike can show the peer uid check refusing a
    /// connection; in the product, file permissions and the peer identity check both apply.
    ///
    /// # Errors
    /// Returns the first bind error or unrecoverable accept error.
    pub async fn serve_all(self: Arc<Self>, dir: &Path) -> io::Result<()> {
        let mut tasks = JoinSet::new();
        for index in 0..self.config.callers.len() {
            let path = dir.join(format!("{}.sock", self.config.callers[index].name));
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            let listener = UnixListener::bind(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
            tasks.spawn(Arc::clone(&self).serve(index, listener));
        }
        eprintln!("event=ready sockets={}", self.config.callers.len());
        while let Some(result) = tasks.join_next().await {
            result.map_err(io::Error::other)??;
        }
        Ok(())
    }

    /// Serves one caller's listener. File descriptor exhaustion and aborted connections are
    /// logged and retried after a back-off; they never stop the listener.
    ///
    /// # Errors
    /// Returns any other accept error.
    pub async fn serve(
        self: Arc<Self>,
        caller_index: usize,
        listener: UnixListener,
    ) -> io::Result<()> {
        let caller_name = &self.config.callers[caller_index].name;
        loop {
            let mut stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(e)
                    if e.raw_os_error()
                        .is_some_and(|n| RECOVERABLE_ACCEPT_ERRNOS.contains(&n)) =>
                {
                    eprintln!("caller={caller_name} event=accept-error error={e:?}");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let Ok(slot) = Arc::clone(&self.slots[caller_index]).try_acquire_owned() else {
                let caller = &self.config.callers[caller_index];
                let refused = refusal(503, "caller connection limit reached");
                tokio::spawn(async move {
                    // The caller is already refused; a failed write changes nothing.
                    let _ = write_refusal(&mut stream, &refused).await;
                });
                eprintln!(
                    "caller={} target=- decision=refuse status=503 reason=\"caller connection limit reached\"",
                    caller.name
                );
                continue;
            };
            let proxy = Arc::clone(&self);
            tokio::spawn(async move {
                let caller = &proxy.config.callers[caller_index];
                if let Err(e) = proxy.handle(caller, stream).await {
                    eprintln!(
                        "caller={} event=io-error error={:?}",
                        caller.name,
                        e.to_string()
                    );
                }
                drop(slot);
            });
        }
    }

    async fn handle(&self, caller: &Caller, mut client: UnixStream) -> io::Result<()> {
        let peer_uid = client.peer_cred()?.uid();
        if peer_uid != caller.uid {
            let refused = refusal(
                403,
                format!("caller identity mismatch (peer uid {peer_uid})"),
            );
            return self
                .respond_refusal(&mut client, caller, None, &refused)
                .await;
        }
        let (target_text, leftover) = match self.read_request(&mut client).await {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(()),
            Err(refused) => {
                return self
                    .respond_refusal(&mut client, caller, None, &refused)
                    .await;
            }
        };
        let target = match parse_target(&target_text) {
            Ok(target) => target,
            Err(refused) => {
                let shown = self.redacted(&target_text);
                return self
                    .respond_refusal(&mut client, caller, Some(&shown), &refused)
                    .await;
            }
        };
        let Some(permission) = permission(caller, &target) else {
            let shown = self.redacted(&target_text);
            let refused = refusal(403, "not on the caller's allowlist");
            return self
                .respond_refusal(&mut client, caller, Some(&shown), &refused)
                .await;
        };
        // From here the target is on the caller's allowlist, so logging it discloses nothing new.
        let shown = target.to_string();
        let (upstream_addr, mut upstream) =
            match self.open_tunnel(caller, &target, permission).await {
                Ok(tunnel) => tunnel,
                Err(refused) => {
                    return self
                        .respond_refusal(&mut client, caller, Some(&shown), &refused)
                        .await;
                }
            };
        eprintln!(
            "caller={} target={shown} decision=allow addr={upstream_addr}",
            caller.name
        );
        client
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
        let first = if caller.sni_check {
            match self.first_record(&mut client, leftover, &target.host).await {
                Ok(record) => record,
                Err(reason) => {
                    eprintln!(
                        "caller={} target={shown} decision=close-tunnel reason={reason:?}",
                        caller.name
                    );
                    return Ok(());
                }
            }
        } else {
            leftover
        };
        upstream.write_all(&first).await?;
        let outcome = tokio::time::timeout(
            self.config.tunnel_lifetime,
            relay(&mut client, &mut upstream, self.config.tunnel_idle),
        )
        .await;
        let end = match outcome {
            Ok(Ok(())) => "closed",
            Ok(Err(e)) if e.kind() == io::ErrorKind::TimedOut => "idle-timeout",
            Ok(Err(e)) => return Err(e),
            Err(_) => "lifetime-reached",
        };
        eprintln!(
            "caller={} target={shown} event=tunnel-end end={end}",
            caller.name
        );
        Ok(())
    }

    /// Reads one request header within the header timeout, measured over the whole header.
    /// `Ok(None)` when the caller closed before sending one.
    async fn read_request(
        &self,
        client: &mut UnixStream,
    ) -> Result<Option<(String, Vec<u8>)>, Refusal> {
        let mut buffer = Vec::with_capacity(1024);
        let read = async {
            let mut chunk = [0_u8; 1024];
            loop {
                if let Some(end) = find_header_end(&buffer) {
                    return Ok(Some(end));
                }
                if buffer.len() > MAX_HEADER_BYTES {
                    return Err(refusal(431, "request header too large"));
                }
                let n = client
                    .read(&mut chunk)
                    .await
                    .map_err(|e| refusal(400, format!("read error: {e}")))?;
                if n == 0 {
                    return Ok(None);
                }
                buffer.extend_from_slice(&chunk[..n]);
            }
        };
        let end = match tokio::time::timeout(self.config.header_timeout, read).await {
            Ok(Ok(Some(end))) => end,
            Ok(Ok(None)) => return Ok(None),
            Ok(Err(refused)) => return Err(refused),
            Err(_) => return Err(refusal(408, "request header timeout")),
        };
        if end > MAX_HEADER_BYTES {
            return Err(refusal(431, "request header too large"));
        }
        let first_line = buffer[..end]
            .split(|b| *b == b'\n')
            .next()
            .unwrap_or_default();
        let request_line = first_line.strip_suffix(b"\r").unwrap_or(first_line);
        if !request_line
            .iter()
            .all(|b| b.is_ascii_graphic() || *b == b' ')
        {
            return Err(refusal(400, "request line is not visible ASCII"));
        }
        let request_line = String::from_utf8_lossy(request_line);
        let parts: Vec<&str> = request_line.split(' ').collect();
        let [method, target, version] = parts.as_slice() else {
            return Err(refusal(400, "malformed request line"));
        };
        if *method != "CONNECT" {
            return Err(refusal(405, "method not supported, CONNECT only"));
        }
        // HTTP/1.0 stays: common CONNECT clients (socat among them) still send it.
        if !matches!(*version, "HTTP/1.1" | "HTTP/1.0") {
            return Err(refusal(400, "version not supported, HTTP/1.x only"));
        }
        Ok(Some(((*target).to_owned(), buffer[end + 4..].to_vec())))
    }

    async fn open_tunnel(
        &self,
        caller: &Caller,
        target: &HostPort,
        permission: Permission,
    ) -> Result<(SocketAddr, TcpStream), Refusal> {
        let resolved = tokio::time::timeout(
            self.resolve_timeout,
            self.resolver.resolve(&target.host, target.port),
        )
        .await
        .map_err(|_| refusal(502, "resolution timeout"))?
        .map_err(|e| refusal(502, format!("resolution failed: {e}")))?;
        if resolved.is_empty() {
            return Err(refusal(502, "name has no address"));
        }
        let checked = self.check_addresses(permission, &resolved)?;
        if !self
            .budgets
            .try_take(&target.host, caller.kind.is_core_side(), Instant::now())
        {
            return Err(refusal(429, "host budget exhausted"));
        }
        self.race(checked).await
    }

    /// Dials the checked addresses, IPv6 and IPv4 interleaved, starting the next one every
    /// [`DIAL_STAGGER`] while earlier ones are pending, all under one deadline. The first
    /// connection wins; the others are aborted.
    async fn race(&self, checked: Vec<SocketAddr>) -> Result<(SocketAddr, TcpStream), Refusal> {
        let order = interleave_families(checked);
        let mut errors = Vec::new();
        let mut pending = JoinSet::new();
        let mut next = order.iter();
        let attempt = async {
            loop {
                if let Some(&addr) = next.next() {
                    let dialer = Arc::clone(&self.dialer);
                    pending.spawn(async move { (addr, dialer.dial(addr).await) });
                } else if pending.is_empty() {
                    return None;
                }
                let more_to_start = next.len() > 0;
                tokio::select! {
                    Some(joined) = pending.join_next() => match joined {
                        Ok((addr, Ok(stream))) => return Some((addr, stream)),
                        Ok((addr, Err(e))) => errors.push(format!("{addr}: {e}")),
                        Err(e) => errors.push(format!("dial task: {e}")),
                    },
                    () = tokio::time::sleep(DIAL_STAGGER), if more_to_start => {}
                }
            }
        };
        match tokio::time::timeout(self.config.dial_deadline, attempt).await {
            Ok(Some(connected)) => Ok(connected),
            Ok(None) => Err(refusal(
                502,
                format!("upstream connect failed ({})", errors.join("; ")),
            )),
            Err(_) => Err(refusal(502, "upstream connect deadline reached")),
        }
    }

    /// Every resolved address must pass; one refused address refuses the whole name.
    fn check_addresses(
        &self,
        permission: Permission,
        resolved: &[SocketAddr],
    ) -> Result<Vec<SocketAddr>, Refusal> {
        resolved
            .iter()
            .map(|addr| {
                let ip = match permission {
                    Permission::Public => address::check(addr.ip(), &self.config.policy)
                        .map_err(|r| refusal(403, format!("internal address: {r}")))?,
                    Permission::Private(range) => self.check_private(addr.ip(), range)?,
                };
                Ok(SocketAddr::new(ip, addr.port()))
            })
            .collect()
    }

    fn check_private(&self, ip: IpAddr, range: Prefix) -> Result<IpAddr, Refusal> {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 @ IpAddr::V4(_) => v4,
        };
        if !range.contains(ip) {
            return Err(refusal(
                403,
                format!("{ip} is outside the named private destination ({range})"),
            ));
        }
        if !in_nameable_private(ip) {
            return Err(refusal(
                403,
                format!("{ip} is not in RFC 1918 or unique local space"),
            ));
        }
        if let Some(prefix) = self.config.policy.blocked.iter().find(|p| p.contains(ip)) {
            return Err(refusal(
                403,
                format!("{ip} is blocked by deployment policy ({prefix})"),
            ));
        }
        Ok(ip)
    }

    /// Reads the tunnel's first TLS record and checks its ClientHello against `host`.
    async fn first_record(
        &self,
        client: &mut UnixStream,
        mut buffer: Vec<u8>,
        host: &str,
    ) -> Result<Vec<u8>, &'static str> {
        let read = async {
            let mut needed = sni::RECORD_HEADER;
            let mut chunk = [0_u8; 4096];
            while buffer.len() < needed {
                let n = client.read(&mut chunk).await.map_err(|_| "read error")?;
                if n == 0 {
                    return Err("closed before a ClientHello");
                }
                buffer.extend_from_slice(&chunk[..n]);
                if needed == sni::RECORD_HEADER && buffer.len() >= sni::RECORD_HEADER {
                    let header: [u8; sni::RECORD_HEADER] = buffer[..sni::RECORD_HEADER]
                        .try_into()
                        .map_err(|_| "short header")?;
                    needed = sni::record_length(&header)?;
                }
            }
            sni::check_client_hello(&buffer[..needed], host)?;
            Ok(())
        };
        tokio::time::timeout(self.config.header_timeout, read)
            .await
            .map_err(|_| "no ClientHello before the header timeout")??;
        Ok(buffer)
    }

    /// What the log shows of a target that is not on the caller's allowlist: its length and a
    /// hash keyed per process, so refusals can be correlated without the name, which may carry
    /// data a caller tried to smuggle out, reaching the journal.
    fn redacted(&self, target_text: &str) -> String {
        format!(
            "redacted(len={},hash={:016x})",
            target_text.len(),
            self.log_key.hash_one(target_text)
        )
    }

    async fn respond_refusal(
        &self,
        client: &mut UnixStream,
        caller: &Caller,
        shown: Option<&str>,
        refused: &Refusal,
    ) -> io::Result<()> {
        eprintln!(
            "caller={} target={} decision=refuse status={} reason={:?}",
            caller.name,
            shown.unwrap_or("-"),
            refused.status,
            refused.reason
        );
        write_refusal(client, refused).await
    }
}

fn parse_target(target_text: &str) -> Result<HostPort, Refusal> {
    parse_authority(target_text).map_err(|e| match e {
        TargetError::IpLiteral => refusal(403, e.reason()),
        TargetError::BadPort | TargetError::BadHostname => refusal(400, e.reason()),
    })
}

fn permission(caller: &Caller, target: &HostPort) -> Option<Permission> {
    if caller.allow.contains(target) {
        return Some(Permission::Public);
    }
    caller
        .private
        .iter()
        .find(|(destination, _)| destination == target)
        .map(|(_, range)| Permission::Private(*range))
}

/// IPv6 first, then alternating families, each family in resolver order (RFC 8305 section 4).
fn interleave_families(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let (v6, v4): (Vec<_>, Vec<_>) = addrs.into_iter().partition(SocketAddr::is_ipv6);
    let mut out = Vec::with_capacity(v6.len() + v4.len());
    let (mut v6, mut v4) = (v6.into_iter(), v4.into_iter());
    loop {
        match (v6.next(), v4.next()) {
            (None, None) => return out,
            (a, b) => out.extend(a.into_iter().chain(b)),
        }
    }
}

/// Copies both directions until both are closed, or fails with `TimedOut` after `idle` without
/// a byte in either direction.
async fn relay(
    client: &mut UnixStream,
    upstream: &mut TcpStream,
    idle: Duration,
) -> io::Result<()> {
    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();
    let mut to_upstream = vec![0_u8; 16 * 1024];
    let mut to_client = vec![0_u8; 16 * 1024];
    let (mut client_open, mut upstream_open) = (true, true);
    while client_open || upstream_open {
        tokio::select! {
            read = client_read.read(&mut to_upstream), if client_open => match read? {
                0 => {
                    client_open = false;
                    upstream_write.shutdown().await?;
                }
                n => upstream_write.write_all(&to_upstream[..n]).await?,
            },
            read = upstream_read.read(&mut to_client), if upstream_open => match read? {
                0 => {
                    upstream_open = false;
                    client_write.shutdown().await?;
                }
                n => client_write.write_all(&to_client[..n]).await?,
            },
            () = tokio::time::sleep(idle) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "tunnel idle"));
            }
        }
    }
    Ok(())
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|w| w == b"\r\n\r\n")
}

fn status_text(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Bad Gateway",
    }
}

async fn write_refusal(client: &mut UnixStream, refused: &Refusal) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\nx-egress-refusal: {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        refused.status,
        status_text(refused.status),
        refused
            .reason
            .replace(|c: char| !c.is_ascii_graphic() && c != ' ', " ")
    );
    client.write_all(response.as_bytes()).await?;
    client.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_are_interleaved_ipv6_first() {
        let addrs: Vec<SocketAddr> = [
            "203.0.113.1:1",
            "203.0.113.2:1",
            "[2001:db8::1]:1",
            "203.0.113.3:1",
        ]
        .iter()
        .map(|a| a.parse().unwrap())
        .collect();
        let order: Vec<String> = interleave_families(addrs)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            order,
            [
                "[2001:db8::1]:1",
                "203.0.113.1:1",
                "203.0.113.2:1",
                "203.0.113.3:1"
            ]
        );
    }
}
