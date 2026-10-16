//! The TLS 1.3 test server: rustls with the aws-lc-rs provider and its default group list, which
//! puts X25519MLKEM768 first (D27). Each connection yields one [`HandshakeRecord`].

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{HandshakeKind, ProtocolVersion, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::client_hello::{self, Offer};
use crate::groups;

/// ALPN the server offers. HTTP/1.1 only: the spike reads one request line and nothing more.
pub const ALPN_HTTP11: &[u8] = b"http/1.1";
/// Path prefix a client uses to name itself in the server log: `/client/<name>`.
pub const CLIENT_PATH_PREFIX: &str = "/client/";
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_HEAD_BYTES: usize = 16 * 1024;

/// Builds the server configuration: TLS 1.3 only (D27), the aws-lc-rs provider with its default
/// key exchange groups, HTTP/1.1 ALPN.
pub fn config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    Ok(config)
}

/// The server's key exchange groups in its configured order, as IANA code points.
pub fn configured_groups(config: &ServerConfig) -> Vec<u16> {
    config
        .crypto_provider()
        .kx_groups
        .iter()
        .map(|group| u16::from(group.name()))
        .collect()
}

/// One accepted connection, as the server saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeRecord {
    /// The `<name>` of a `/client/<name>` request, `-` when the client sent no such request.
    pub client: String,
    /// The negotiated group, `None` when the handshake failed.
    pub group: Option<u16>,
    /// The negotiated protocol version, `None` when the handshake failed.
    pub protocol: Option<ProtocolVersion>,
    /// True when rustls reports a full handshake with a HelloRetryRequest.
    pub hello_retry: bool,
    /// True when the negotiated group had no key share in the first ClientHello: the
    /// spike's own inference of a HelloRetryRequest, logged to cross-check `hello_retry`.
    pub hello_retry_inferred: bool,
    pub offer: Offer,
    pub alpn: Option<String>,
    pub sni: Option<String>,
    pub user_agent: Option<String>,
    pub error: Option<String>,
}

impl HandshakeRecord {
    fn failed(offer: Offer, error: String) -> Self {
        Self {
            client: "-".to_owned(),
            group: None,
            protocol: None,
            hello_retry: false,
            hello_retry_inferred: false,
            offer,
            alpn: None,
            sni: None,
            user_agent: None,
            error: Some(error),
        }
    }

    /// The negotiated group's name, `none` when the handshake failed.
    pub fn group_name(&self) -> String {
        self.group.map_or_else(|| "none".to_owned(), groups::name)
    }
}

/// One log line per connection. Space-separated `key=value` fields; the free-text fields
/// (`ua`, `error`) come last, quoted.
impl fmt::Display for HandshakeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HANDSHAKE client={} protocol={} group={} hrr={} hrr_inferred={} offered={} key_shares={} alpn={} sni={}",
            self.client,
            self.protocol
                .map_or_else(|| "none".to_owned(), |version| format!("{version:?}")),
            self.group_name(),
            yes_no(self.hello_retry),
            yes_no(self.hello_retry_inferred),
            groups::join(&self.offer.groups),
            groups::join(&self.offer.key_shares),
            self.alpn.as_deref().unwrap_or("-"),
            self.sni.as_deref().unwrap_or("-"),
        )?;
        if let Some(error) = &self.error {
            write!(f, " error=\"{}\"", log_safe(error))?;
        }
        write!(
            f,
            " ua=\"{}\"",
            log_safe(self.user_agent.as_deref().unwrap_or("-"))
        )
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Keeps a client-controlled string inside its quoted log field: control characters (a bare
/// line feed would start a forged `HANDSHAKE` line) become `?`, double quotes become `'`.
fn log_safe(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '"' => '\'',
            c if c.is_control() => '?',
            c => c,
        })
        .collect()
}

/// Accepts connections until the listener fails, sending one record per connection to `records`.
pub async fn serve(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    records: UnboundedSender<HandshakeRecord>,
) -> io::Result<()> {
    let acceptor = TlsAcceptor::from(config);
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let records = records.clone();
        tokio::spawn(async move {
            let record = handle(stream, acceptor).await;
            // The receiver is gone only when the process is shutting down.
            let _ = records.send(record);
        });
    }
}

async fn handle(mut stream: TcpStream, acceptor: TlsAcceptor) -> HandshakeRecord {
    let captured = match timeout(IO_TIMEOUT, client_hello::read(&mut stream)).await {
        Ok(Ok(captured)) => captured,
        Ok(Err(error)) => return HandshakeRecord::failed(Offer::default(), error.to_string()),
        Err(_) => {
            return HandshakeRecord::failed(Offer::default(), "ClientHello timeout".to_owned());
        }
    };
    let offer = captured.offer;
    let replay = Replay::new(captured.raw, stream);
    let mut tls = match timeout(IO_TIMEOUT, acceptor.accept(replay)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(error)) => return HandshakeRecord::failed(offer, error.to_string()),
        Err(_) => return HandshakeRecord::failed(offer, "handshake timeout".to_owned()),
    };

    let (_, connection) = tls.get_ref();
    let group = connection
        .negotiated_key_exchange_group()
        .map(|group| u16::from(group.name()));
    let alpn = connection
        .alpn_protocol()
        .map(|alpn| String::from_utf8_lossy(alpn).into_owned());
    let sni = connection.server_name().map(str::to_owned);
    let protocol = connection.protocol_version();
    let hello_retry = connection.handshake_kind() == Some(HandshakeKind::FullWithHelloRetryRequest);
    let hello_retry_inferred = group.is_some_and(|group| !offer.key_shares.contains(&group));

    let mut record = HandshakeRecord {
        client: "-".to_owned(),
        group,
        protocol,
        hello_retry,
        hello_retry_inferred,
        offer,
        alpn,
        sni,
        user_agent: None,
        error: None,
    };

    match timeout(IO_TIMEOUT, read_request_head(&mut tls)).await {
        Ok(Ok(head)) => {
            let (client, user_agent) = parse_request_head(&head);
            record.client = client;
            record.user_agent = user_agent;
            let body = format!("{record}\n");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            if let Err(error) = tls.write_all(response.as_bytes()).await {
                record.error = Some(format!("response write failed: {error}"));
            }
            // A client that already closed its side makes shutdown fail; the record is complete.
            let _ = tls.shutdown().await;
        }
        Ok(Err(error)) => record.error = Some(format!("no request: {error}")),
        Err(_) => record.error = Some("no request before timeout".to_owned()),
    }
    record
}

async fn read_request_head(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        if head.len() > MAX_REQUEST_HEAD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
        let read = stream.read(&mut buf).await?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        head.extend_from_slice(&buf[..read]);
    }
    Ok(head)
}

/// Returns the client name from a `GET /client/<name>` request line and the `User-Agent`.
fn parse_request_head(head: &[u8]) -> (String, Option<String>) {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let path = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .unwrap_or("");
    let client = path
        .strip_prefix(CLIENT_PATH_PREFIX)
        .filter(|name| {
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        })
        .unwrap_or("-")
        .to_owned();
    let user_agent = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("user-agent")
            .then(|| value.trim().to_owned())
    });
    (client, user_agent)
}

/// A TCP stream whose first reads return bytes already consumed from it (the ClientHello).
struct Replay {
    prefix: Vec<u8>,
    position: usize,
    inner: TcpStream,
}

impl Replay {
    fn new(prefix: Vec<u8>, inner: TcpStream) -> Self {
        Self {
            prefix,
            position: 0,
            inner,
        }
    }
}

impl AsyncRead for Replay {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.position < self.prefix.len() {
            let remaining = &self.prefix[self.position..];
            let len = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..len]);
            self.position += len;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Replay {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_client_name_and_user_agent() {
        let head = b"GET /client/curl-debian13 HTTP/1.1\r\nHost: server\r\nuser-agent: curl/8.14.1\r\n\r\n";
        let (client, user_agent) = parse_request_head(head);
        assert_eq!(client, "curl-debian13");
        assert_eq!(user_agent.as_deref(), Some("curl/8.14.1"));
    }

    #[test]
    fn client_strings_cannot_break_out_of_their_log_field() {
        let mut record = HandshakeRecord::failed(Offer::default(), "bad\r\n\"x\"".to_owned());
        record.user_agent = Some("ua\nHANDSHAKE client=forged group=X25519MLKEM768".to_owned());
        let line = record.to_string();
        assert_eq!(line.lines().count(), 1);
        assert!(line.contains(r#"error="bad??'x'""#));
        assert!(line.contains(r#"ua="ua?HANDSHAKE client=forged"#));
    }

    #[test]
    fn other_paths_and_odd_names_are_not_attributed() {
        assert_eq!(
            parse_request_head(b"GET /favicon.ico HTTP/1.1\r\n\r\n").0,
            "-"
        );
        assert_eq!(
            parse_request_head(b"GET /client/a%20b HTTP/1.1\r\n\r\n").0,
            "-"
        );
        assert_eq!(parse_request_head(b"GET /client/ HTTP/1.1\r\n\r\n").0, "-");
    }
}
