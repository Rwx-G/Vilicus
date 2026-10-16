//! The spike's protocol-level test client. Each subcommand checks its own expectations and exits 0
//! when they hold, 1 otherwise, printing what it observed either way.
//!
//! - `tunnel --socket P --target T --expect-status N [--expect-reason S] [--expect-upstream NAME]
//!   [--path /p] [--host H] [--extra-header "Name: value"]`: sends `CONNECT T` over the Unix socket;
//!   after a 200, sends plain HTTP inside the tunnel. The spike's upstreams answer plain HTTP on
//!   their TLS port with `upstream=<name>` (nginx's 497 handler), which names the server reached.
//! - `raw --socket P --data D --expect-status N [--expect-reason S] [--expect-body S]`: sends `D`
//!   (with `\r`, `\n` and `\xNN` escapes) and checks the reply. `--expect-close` instead expects
//!   the proxy to close without a status line.
//! - `direct-tcp --addr A --expect ok|fail`: a direct TCP connection, no proxy.
//! - `dns-query --server A --name N (--expect-a IP | --expect-fail)`: one A query over UDP.
//! - `canary --listen A --name NAME`: a TCP listener that answers `upstream=NAME` to anything.
//! - `hold --socket P --target T --count N --seconds S`: opens N tunnels and keeps them open for
//!   S seconds, to fill a caller's connection limit.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprintln!("usage: egress-probe <tunnel|raw|direct-tcp|dns-query|canary> --option value...");
        return ExitCode::from(2);
    };
    let options = match parse_options(rest) {
        Ok(options) => options,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let result = match command.as_str() {
        "tunnel" => tunnel(&options),
        "raw" => raw(&options),
        "direct-tcp" => direct_tcp(&options),
        "dns-query" => dns_query(&options),
        "canary" => canary(&options),
        "hold" => hold(&options),
        other => Err(format!("unknown command {other}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            println!("expectation failed: {e}");
            ExitCode::FAILURE
        }
    }
}

type Options = HashMap<String, Vec<String>>;

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut options = Options::new();
    let mut iter = args.iter();
    while let Some(key) = iter.next() {
        let key = key
            .strip_prefix("--")
            .ok_or_else(|| format!("expected an option, got {key}"))?;
        if matches!(key, "expect-close" | "expect-fail") {
            options.entry(key.into()).or_default().push(String::new());
            continue;
        }
        let value = iter
            .next()
            .ok_or_else(|| format!("--{key} needs a value"))?;
        options.entry(key.into()).or_default().push(value.clone());
    }
    Ok(options)
}

fn one<'a>(options: &'a Options, key: &str) -> Result<&'a str, String> {
    options
        .get(key)
        .and_then(|v| v.first())
        .map(String::as_str)
        .ok_or_else(|| format!("--{key} is required"))
}

fn maybe<'a>(options: &'a Options, key: &str) -> Option<&'a str> {
    options.get(key).and_then(|v| v.first()).map(String::as_str)
}

fn connect_unix(options: &Options) -> Result<UnixStream, String> {
    let path = one(options, "socket")?;
    let stream = UnixStream::connect(path).map_err(|e| format!("connect {path}: {e}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    Ok(stream)
}

/// Reads a response header; returns the status, the headers and any bytes read past them.
fn read_head(stream: &mut impl Read) -> Result<Option<(u16, String, Vec<u8>)>, String> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
            let status = head
                .split(' ')
                .nth(1)
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| format!("no status in {head:?}"))?;
            return Ok(Some((status, head, buffer[end + 4..].to_vec())));
        }
        let n = stream.read(&mut chunk).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return if buffer.is_empty() {
                Ok(None)
            } else {
                Err(format!(
                    "closed mid-header: {:?}",
                    String::from_utf8_lossy(&buffer)
                ))
            };
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
}

fn read_rest(stream: &mut impl Read, mut already: Vec<u8>) -> String {
    // A read timeout or reset ends the body as well as a close does; what was read is checked.
    let _ = stream.read_to_end(&mut already);
    String::from_utf8_lossy(&already).into_owned()
}

fn refusal_header(head: &str) -> String {
    head.lines()
        .find_map(|l| l.strip_prefix("x-egress-refusal: "))
        .unwrap_or_default()
        .to_owned()
}

fn check_head(options: &Options, status: u16, head: &str) -> Result<(), String> {
    let reason = refusal_header(head);
    println!("status={status} refusal={reason:?}");
    let expected: u16 = one(options, "expect-status")?
        .parse()
        .map_err(|_| "bad --expect-status")?;
    if status != expected {
        return Err(format!("status {status}, expected {expected}"));
    }
    if let Some(want) = maybe(options, "expect-reason")
        && !reason.contains(want)
    {
        return Err(format!("refusal {reason:?} does not contain {want:?}"));
    }
    Ok(())
}

fn tunnel(options: &Options) -> Result<(), String> {
    let target = one(options, "target")?;
    let mut stream = connect_unix(options)?;
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    for header in options.get("extra-header").into_iter().flatten() {
        request.push_str(header);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    // A proxy that refuses before reading (wrong peer uid) may close first; its reply is what
    // counts, so a failed write is not an error here.
    let _ = stream.write_all(request.as_bytes());
    let (status, head, rest) = read_head(&mut stream)?.ok_or("proxy closed without a response")?;
    check_head(options, status, &head)?;
    if let Some(upstream) = maybe(options, "expect-upstream") {
        let host = maybe(options, "host")
            .unwrap_or_else(|| target.rsplit_once(':').map_or(target, |(h, _)| h));
        let path = maybe(options, "path").unwrap_or("/");
        let inner = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(inner.as_bytes())
            .map_err(|e| e.to_string())?;
        let body = read_rest(&mut stream, rest);
        println!(
            "upstream response: {:?}",
            body.lines().last().unwrap_or_default()
        );
        let want = format!("upstream={upstream}");
        if !body.contains(&want) {
            return Err(format!("upstream response does not contain {want:?}"));
        }
    }
    Ok(())
}

fn unescape(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut bytes = text.bytes();
    while let Some(b) = bytes.next() {
        if b != b'\\' {
            out.push(b);
            continue;
        }
        match bytes.next() {
            Some(b'r') => out.push(b'\r'),
            Some(b'n') => out.push(b'\n'),
            Some(b'\\') => out.push(b'\\'),
            Some(b'x') => {
                let hex: Vec<u8> = bytes.by_ref().take(2).collect();
                let hex = std::str::from_utf8(&hex).map_err(|e| e.to_string())?;
                out.push(u8::from_str_radix(hex, 16).map_err(|e| format!("\\x{hex}: {e}"))?);
            }
            other => return Err(format!("unknown escape {other:?}")),
        }
    }
    Ok(out)
}

fn raw(options: &Options) -> Result<(), String> {
    let mut stream = connect_unix(options)?;
    let data = unescape(one(options, "data")?)?;
    let repeat: usize = maybe(options, "repeat")
        .map_or(Ok(1), str::parse)
        .map_err(|_| "bad --repeat")?;
    for _ in 0..repeat {
        // The proxy may refuse and close before everything is written; the reply is what counts.
        if stream.write_all(&data).is_err() {
            break;
        }
    }
    let Some((status, head, rest)) = read_head(&mut stream)? else {
        println!("closed without a response");
        return if options.contains_key("expect-close") {
            Ok(())
        } else {
            Err("proxy closed without a response".into())
        };
    };
    if options.contains_key("expect-close") {
        return Err(format!("expected a close, got status {status}"));
    }
    check_head(options, status, &head)?;
    if let Some(want) = maybe(options, "expect-body") {
        let body = read_rest(&mut stream, rest);
        println!(
            "after the status: {:?}",
            body.lines().last().unwrap_or_default()
        );
        if !body.contains(want) {
            return Err(format!("reply does not contain {want:?}"));
        }
    }
    Ok(())
}

fn expect_outcome<T>(options: &Options, outcome: Result<T, String>) -> Result<(), String> {
    let expected = one(options, "expect")?;
    let observed = match &outcome {
        Ok(_) => "ok",
        Err(e) => {
            println!("error: {e}");
            "fail"
        }
    };
    println!("outcome={observed}");
    if observed == expected {
        Ok(())
    } else {
        Err(format!("outcome {observed}, expected {expected}"))
    }
}

fn direct_tcp(options: &Options) -> Result<(), String> {
    let addr: SocketAddr = one(options, "addr")?.parse().map_err(|_| "bad --addr")?;
    let outcome = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|e| format!("{:?}: {e}", e.kind()));
    expect_outcome(options, outcome)
}

fn dns_query(options: &Options) -> Result<(), String> {
    let server: SocketAddr = one(options, "server")?
        .parse()
        .map_err(|_| "bad --server")?;
    let name = one(options, "name")?;
    let outcome = query_a(server, name);
    if options.contains_key("expect-fail") {
        let options: Options = HashMap::from([("expect".to_owned(), vec!["fail".to_owned()])]);
        return expect_outcome(&options, outcome);
    }
    let answer = outcome?;
    println!("answer={answer}");
    let want: Ipv4Addr = one(options, "expect-a")?
        .parse()
        .map_err(|_| "bad --expect-a")?;
    if answer == want {
        Ok(())
    } else {
        Err(format!("answer {answer}, expected {want}"))
    }
}

fn query_a(server: SocketAddr, name: &str) -> Result<Ipv4Addr, String> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .map_err(|_| "bind")?;
    let socket = UdpSocket::bind(bind).map_err(|e| format!("bind: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    let mut packet = vec![0x13, 0x37, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        packet.push(u8::try_from(label.len()).map_err(|_| "label too long")?);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    socket
        .send_to(&packet, server)
        .map_err(|e| format!("send: {:?}: {e}", e.kind()))?;
    let mut reply = [0_u8; 1500];
    let len = socket
        .recv(&mut reply)
        .map_err(|e| format!("receive: {:?}: {e}", e.kind()))?;
    let reply = &reply[..len];
    // The answer section follows the echoed question; its first record's data is the last four
    // bytes when the server sends one A record, as the spike's resolver does.
    let answers = u16::from_be_bytes([reply[6], reply[7]]);
    if answers == 0 || len < packet.len() + 16 {
        return Err("no answer".into());
    }
    let data = &reply[len - 4..];
    Ok(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
}

fn hold(options: &Options) -> Result<(), String> {
    let target = one(options, "target")?;
    let count: usize = one(options, "count")?.parse().map_err(|_| "bad --count")?;
    let seconds: u64 = one(options, "seconds")?
        .parse()
        .map_err(|_| "bad --seconds")?;
    let mut held = Vec::with_capacity(count);
    for _ in 0..count {
        let mut stream = connect_unix(options)?;
        let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|e| e.to_string())?;
        let (status, _, _) = read_head(&mut stream)?.ok_or("proxy closed without a response")?;
        if status != 200 {
            return Err(format!("tunnel {} got status {status}", held.len() + 1));
        }
        held.push(stream);
    }
    println!("held={}", held.len());
    std::thread::sleep(Duration::from_secs(seconds));
    Ok(())
}

fn canary(options: &Options) -> Result<(), String> {
    let listen = one(options, "listen")?;
    let name = one(options, "name")?.to_owned();
    let listener = TcpListener::bind(listen).map_err(|e| format!("bind {listen}: {e}"))?;
    println!("canary listening on {listen}");
    for stream in listener.incoming().flatten() {
        let name = name.clone();
        std::thread::spawn(move || {
            let mut stream = stream;
            let peer = stream
                .peer_addr()
                .map_or_else(|_| IpAddr::from([0, 0, 0, 0]), |a| a.ip());
            println!("canary connection from {peer}");
            let mut buffer = [0_u8; 1024];
            let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
            let _ = stream.read(&mut buffer);
            let body = format!("upstream={name}\n");
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        });
    }
    Ok(())
}
