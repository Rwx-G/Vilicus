//! The proxy in process, with a scripted resolver and a dialer that records the address it was
//! asked for and connects to a local echo server instead. These tests pin the order of the
//! checks and the one-lookup, dial-what-was-checked rule; `run.sh` repeats them on real traffic.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use egress_filter::address::Prefix;
use egress_filter::config::Config;
use egress_filter::proxy::{Dial, Proxy, Resolve};
use egress_filter::sni::test_support::client_hello;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};

#[derive(Clone, Default)]
struct Scripted {
    answers: Arc<Mutex<HashMap<String, VecDeque<Vec<IpAddr>>>>>,
    calls: Arc<Mutex<Vec<String>>>,
}

impl Scripted {
    /// Each lookup of `host` takes the next answer; the last one repeats.
    fn script(&self, host: &str, answers: &[&[&str]]) {
        let parsed = answers
            .iter()
            .map(|answer| answer.iter().map(|a| a.parse().unwrap()).collect())
            .collect();
        self.answers.lock().unwrap().insert(host.to_owned(), parsed);
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn lookup(&self, host: &str) -> Vec<IpAddr> {
        self.calls.lock().unwrap().push(host.to_owned());
        let mut answers = self.answers.lock().unwrap();
        let queue = answers.get_mut(host).expect("unscripted host");
        if queue.len() > 1 {
            queue.pop_front().unwrap()
        } else {
            queue.front().cloned().unwrap()
        }
    }
}

impl Resolve for Scripted {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(self
            .lookup(host)
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }
}

/// Every address in `unreachable` hangs, like a black-holed route; the rest connect to the
/// local echo server.
#[derive(Clone)]
struct Recording {
    echo: SocketAddr,
    dialled: Arc<Mutex<Vec<SocketAddr>>>,
    unreachable: Arc<Mutex<Vec<SocketAddr>>>,
}

impl Dial for Recording {
    async fn dial(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        self.dialled.lock().unwrap().push(addr);
        let hangs = self.unreachable.lock().unwrap().contains(&addr);
        if hangs {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
        TcpStream::connect(self.echo).await
    }
}

struct Harness {
    dir: PathBuf,
    resolver: Scripted,
    dialled: Arc<Mutex<Vec<SocketAddr>>>,
    unreachable: Arc<Mutex<Vec<SocketAddr>>>,
}

impl Harness {
    fn socket(&self, caller: &str) -> PathBuf {
        self.dir.join(format!("{caller}.sock"))
    }

    fn make_unreachable(&self, addr: &str) {
        self.unreachable.lock().unwrap().push(addr.parse().unwrap());
    }

    fn dialled(&self) -> Vec<String> {
        self.dialled
            .lock()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn current_uid(dir: &Path) -> u32 {
    std::fs::metadata(dir).unwrap().uid()
}

/// Starts a proxy whose configuration is `config`, with `{uid}` replaced by the test's own uid
/// and `{other}` by another one.
async fn start(name: &str, config: &str, resolver: Scripted) -> Harness {
    start_with(name, config, resolver, |_| {}).await
}

/// As [`start`], with `adjust` applied to the parsed configuration, to build states the parser
/// refuses.
async fn start_with(
    name: &str,
    config: &str,
    resolver: Scripted,
    adjust: impl FnOnce(&mut Config),
) -> Harness {
    let dir = std::env::temp_dir().join(format!("egress-filter-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let uid = current_uid(&dir);
    let text = config
        .replace("{uid}", &uid.to_string())
        .replace("{other}", &(uid + 1).to_string());
    let mut config = Config::parse(&text).unwrap();
    adjust(&mut config);
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    let dialled = Arc::new(Mutex::new(Vec::new()));
    let unreachable = Arc::new(Mutex::new(Vec::new()));
    let dialer = Recording {
        echo,
        dialled: Arc::clone(&dialled),
        unreachable: Arc::clone(&unreachable),
    };
    let proxy = Arc::new(Proxy::new(config, resolver.clone(), dialer));
    let callers: Vec<String> = proxy
        .config()
        .callers
        .iter()
        .map(|c| c.name.clone())
        .collect();
    let socket_dir = dir.clone();
    tokio::spawn(async move { proxy.serve_all(&socket_dir).await });
    for caller in callers {
        let path = dir.join(format!("{caller}.sock"));
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    Harness {
        dir,
        resolver,
        dialled,
        unreachable,
    }
}

/// Sends `request` and returns the status and the response head.
async fn send(stream: &mut UnixStream, request: &[u8]) -> (u16, String) {
    stream.write_all(request).await.unwrap();
    let mut buffer = Vec::new();
    let mut byte = [0_u8; 1];
    while !buffer.ends_with(b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte))
            .await
            .expect("proxy did not answer")
            .unwrap();
        assert!(
            n == 1,
            "proxy closed mid-response: {:?}",
            String::from_utf8_lossy(&buffer)
        );
        buffer.push(byte[0]);
    }
    let head = String::from_utf8(buffer).unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, head)
}

async fn connect(harness: &Harness, caller: &str, target: &str) -> (UnixStream, u16, String) {
    let mut stream = UnixStream::connect(harness.socket(caller)).await.unwrap();
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    let (status, head) = send(&mut stream, request.as_bytes()).await;
    (stream, status, head)
}

async fn echo_round_trip(stream: &mut UnixStream, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    let mut back = vec![0_u8; payload.len()];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(back, payload);
}

const PLUGIN: &str = "documentation-ranges-public\n\
                      caller plugin-a kind=plugin uid={uid}\n\
                      caller plugin-b kind=plugin uid={other}\n\
                      allow plugin-a allowed.test:443\n\
                      allow plugin-a rebind.test:443\n\
                      allow plugin-a mixed.test:443\n\
                      allow plugin-a internal.test:443\n\
                      allow plugin-a push.lan:8443\n\
                      allow plugin-b other.test:443\n\
                      budget allowed.test tunnels=4 window=60 reserve=1\n\
                      header-timeout 1\n";

#[tokio::test]
async fn allowlisted_name_is_resolved_once_and_the_checked_address_dialled() {
    let resolver = Scripted::default();
    resolver.script("allowed.test", &[&["203.0.113.10", "2001:db8:113::10"]]);
    let harness = start("allowed", PLUGIN, resolver).await;
    let (mut stream, status, _) = connect(&harness, "plugin-a", "ALLOWED.test:443").await;
    assert_eq!(status, 200);
    echo_round_trip(&mut stream, b"through the tunnel").await;
    assert_eq!(harness.dialled(), ["[2001:db8:113::10]:443"]);
    assert_eq!(harness.resolver.calls(), ["allowed.test"]);
}

#[tokio::test]
async fn name_that_rebinds_after_an_advisory_lookup_is_refused_without_a_dial() {
    let resolver = Scripted::default();
    resolver.script("rebind.test", &[&["203.0.113.10"], &["10.77.0.10"]]);
    let advisory = resolver.lookup("rebind.test");
    assert_eq!(advisory, ["203.0.113.10".parse::<IpAddr>().unwrap()]);
    let harness = start("rebind-advisory", PLUGIN, resolver).await;
    let (_, status, head) = connect(&harness, "plugin-a", "rebind.test:443").await;
    assert_eq!(status, 403);
    assert!(head.contains("10.77.0.10 is private (RFC 1918)"), "{head}");
    assert!(harness.dialled().is_empty());
}

#[tokio::test]
async fn name_that_rebinds_after_the_proxy_lookup_keeps_the_checked_address() {
    let resolver = Scripted::default();
    resolver.script("rebind.test", &[&["203.0.113.10"], &["10.77.0.10"]]);
    let harness = start("rebind-after", PLUGIN, resolver).await;
    let (mut stream, status, _) = connect(&harness, "plugin-a", "rebind.test:443").await;
    assert_eq!(status, 200);
    echo_round_trip(&mut stream, b"still the first address").await;
    assert_eq!(harness.dialled(), ["203.0.113.10:443"]);
    assert_eq!(harness.resolver.calls(), ["rebind.test"]);
    let rebound = harness.resolver.lookup("rebind.test");
    assert_eq!(rebound, ["10.77.0.10".parse::<IpAddr>().unwrap()]);
}

#[tokio::test]
async fn one_internal_address_in_an_answer_refuses_the_whole_name() {
    let resolver = Scripted::default();
    resolver.script("mixed.test", &[&["203.0.113.10", "10.77.0.10"]]);
    let harness = start("mixed", PLUGIN, resolver).await;
    let (_, status, head) = connect(&harness, "plugin-a", "mixed.test:443").await;
    assert_eq!(status, 403);
    assert!(head.contains("10.77.0.10"), "{head}");
    assert!(harness.dialled().is_empty());
}

#[tokio::test]
async fn allowlisted_names_resolving_to_internal_forms_are_refused() {
    let internal = [
        "10.77.0.10",
        "127.0.0.1",
        "0.0.0.0",
        "169.254.169.254",
        "100.64.0.1",
        "224.0.0.1",
        "::1",
        "::ffff:10.77.0.10",
        "::ffff:127.0.0.1",
        "64:ff9b::a4d:a",
        "2002:a4d:a::1",
        "fd00:77::10",
        "fe80::1",
        "ff02::1",
    ];
    for address in internal {
        let resolver = Scripted::default();
        resolver.script("internal.test", &[&[address]]);
        let harness = start("internal-forms", PLUGIN, resolver).await;
        let (_, status, head) = connect(&harness, "plugin-a", "internal.test:443").await;
        assert_eq!(status, 403, "{address}: {head}");
        assert!(head.contains("internal address"), "{address}: {head}");
        assert!(harness.dialled().is_empty(), "{address}");
    }
}

#[tokio::test]
async fn targets_off_the_allowlist_are_refused_before_any_lookup() {
    let harness = start("off-list", PLUGIN, Scripted::default()).await;
    let cases = [
        ("forbidden.test:443", 403, "not on the caller's allowlist"),
        ("other.test:443", 403, "not on the caller's allowlist"),
        ("allowed.test:8443", 403, "not on the caller's allowlist"),
        ("allowed.test:80", 403, "not on the caller's allowlist"),
        ("203.0.113.10:443", 403, "IP literals"),
        ("[2001:db8:113::10]:443", 403, "IP literals"),
        ("3405803786:443", 400, "malformed hostname"),
        ("allowed.test.:443", 400, "malformed hostname"),
        ("allowed.test@forbidden.test:443", 400, "malformed hostname"),
        ("allowed.test", 400, "port"),
        ("allowed.test:0443", 400, "port"),
    ];
    for (target, expected, reason) in cases {
        let (_, status, head) = connect(&harness, "plugin-a", target).await;
        assert_eq!(status, expected, "{target}: {head}");
        assert!(head.contains(reason), "{target}: {head}");
    }
    assert!(harness.resolver.calls().is_empty());
    assert!(harness.dialled().is_empty());
}

#[tokio::test]
async fn a_peer_with_another_uid_is_refused() {
    let resolver = Scripted::default();
    resolver.script("other.test", &[&["203.0.113.10"]]);
    let harness = start("uid", PLUGIN, resolver).await;
    let (_, status, head) = connect(&harness, "plugin-b", "other.test:443").await;
    assert_eq!(status, 403);
    assert!(head.contains("caller identity mismatch"), "{head}");
    assert!(harness.resolver.calls().is_empty());
}

#[tokio::test]
async fn only_http1_connect_is_served() {
    let harness = start("methods", PLUGIN, Scripted::default()).await;
    let cases: [(&[u8], u16); 10] = [
        (b"CONNECT allowed.test:443 HTTP/0.9\r\n\r\n", 400),
        (b"CONNECT allowed.test:443\x01 HTTP/1.1\r\n\r\n", 400),
        (b"CONNECT allowed.t\xc3\xa9st:443 HTTP/1.1\r\n\r\n", 400),
        (b"GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n", 405),
        (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 405),
        (b"connect allowed.test:443 HTTP/1.1\r\n\r\n", 405),
        (b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n", 405),
        (b"CONNECT allowed.test:443 HTTP/2.0\r\n\r\n", 400),
        (b"CONNECT allowed.test:443  HTTP/1.1\r\n\r\n", 400),
        (b"CONNECT\r\n\r\n", 400),
    ];
    for (request, expected) in cases {
        let mut stream = UnixStream::connect(harness.socket("plugin-a"))
            .await
            .unwrap();
        let (status, head) = send(&mut stream, request).await;
        assert_eq!(
            status,
            expected,
            "{:?}: {head}",
            String::from_utf8_lossy(request)
        );
    }
    let mut stream = UnixStream::connect(harness.socket("plugin-a"))
        .await
        .unwrap();
    let oversized = format!(
        "CONNECT allowed.test:443 HTTP/1.1\r\nX-Pad: {}\r\n\r\n",
        "a".repeat(9000)
    );
    let (status, _) = send(&mut stream, oversized.as_bytes()).await;
    assert_eq!(status, 431);
    assert!(harness.resolver.calls().is_empty());
}

#[tokio::test]
async fn an_incomplete_header_times_out() {
    let harness = start("timeout", PLUGIN, Scripted::default()).await;
    let mut stream = UnixStream::connect(harness.socket("plugin-a"))
        .await
        .unwrap();
    let (status, _) = send(&mut stream, b"CONNECT allowed.test:443 HTTP/1.1\r\n").await;
    assert_eq!(status, 408);
}

#[tokio::test]
async fn bytes_sent_after_the_header_reach_the_upstream() {
    let resolver = Scripted::default();
    resolver.script("allowed.test", &[&["203.0.113.10"]]);
    let harness = start("pipelined", PLUGIN, resolver).await;
    let mut stream = UnixStream::connect(harness.socket("plugin-a"))
        .await
        .unwrap();
    let (status, _) = send(
        &mut stream,
        b"CONNECT allowed.test:443 HTTP/1.1\r\n\r\nearly bytes",
    )
    .await;
    assert_eq!(status, 200);
    let mut back = [0_u8; 11];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"early bytes");
}

#[tokio::test]
async fn host_budget_refuses_past_its_limit() {
    let resolver = Scripted::default();
    resolver.script("allowed.test", &[&["203.0.113.10"]]);
    let harness = start("budget", PLUGIN, resolver).await;
    for _ in 0..3 {
        assert_eq!(
            connect(&harness, "plugin-a", "allowed.test:443").await.1,
            200
        );
    }
    let (_, status, head) = connect(&harness, "plugin-a", "allowed.test:443").await;
    assert_eq!(status, 429, "{head}");
    // The budget is taken after the lookup and the address check, so a refused tunnel costs
    // nothing; the fourth tunnel was resolved, then refused by the Core reserve.
    assert_eq!(harness.resolver.calls().len(), 4);
    assert_eq!(harness.dialled().len(), 3);
}

#[tokio::test]
async fn named_private_destination_reaches_only_its_range_and_only_for_the_core() {
    let core = "caller core kind=core uid={uid}\n\
                private core push.lan:8443 10.77.0.10/32\n";
    let cases = [
        ("10.77.0.10", 200, ""),
        ("::ffff:10.77.0.10", 200, ""),
        ("10.77.0.11", 403, "outside the named private destination"),
        ("127.0.0.1", 403, "outside the named private destination"),
    ];
    for (address, expected, reason) in cases {
        let resolver = Scripted::default();
        resolver.script("push.lan", &[&[address]]);
        let harness = start("private-core", core, resolver).await;
        let (_, status, head) = connect(&harness, "core", "push.lan:8443").await;
        assert_eq!(status, expected, "{address}: {head}");
        assert!(head.contains(reason), "{address}: {head}");
        if expected == 200 {
            assert_eq!(harness.dialled(), ["10.77.0.10:8443"]);
        }
    }
    let resolver = Scripted::default();
    resolver.script("push.lan", &[&["10.77.0.10"]]);
    let harness = start("private-plugin", PLUGIN, resolver).await;
    let (_, status, head) = connect(&harness, "plugin-a", "push.lan:8443").await;
    assert_eq!(status, 403);
    assert!(head.contains("internal address"), "{head}");
    assert!(harness.dialled().is_empty());
}

#[tokio::test]
async fn named_private_destination_refuses_blocked_and_non_private_addresses_at_connect_time() {
    let core = "caller core kind=core uid={uid}\n\
                private core push.lan:8443 10.77.0.0/24\n\
                blocked 10.77.0.10/32\n";
    let resolver = Scripted::default();
    resolver.script("push.lan", &[&["10.77.0.10"]]);
    let harness = start("private-blocked", core, resolver).await;
    let (_, status, head) = connect(&harness, "core", "push.lan:8443").await;
    assert_eq!(status, 403, "{head}");
    assert!(head.contains("blocked by deployment policy"), "{head}");
    // A range the parser refuses, forced into the configuration: the connect-time check holds.
    let resolver = Scripted::default();
    resolver.script("push.lan", &[&["127.0.0.1"]]);
    let harness = start_with("private-loopback", core, resolver, |config| {
        config.callers[0].private[0].1 = Prefix::parse("127.0.0.0/8").unwrap();
    })
    .await;
    let (_, status, head) = connect(&harness, "core", "push.lan:8443").await;
    assert_eq!(status, 403, "{head}");
    assert!(
        head.contains("not in RFC 1918 or unique local space"),
        "{head}"
    );
    assert!(harness.dialled().is_empty());
}

#[tokio::test]
async fn an_unterminated_64_kib_header_is_refused_before_the_timeout() {
    let config = PLUGIN.replace("header-timeout 1", "header-timeout 5");
    let harness = start("unterminated", &config, Scripted::default()).await;
    let mut stream = UnixStream::connect(harness.socket("plugin-a"))
        .await
        .unwrap();
    let started = Instant::now();
    let (status, _) = send(&mut stream, &vec![b'a'; 64 * 1024]).await;
    assert_eq!(status, 431);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_trickled_header_hits_the_total_header_timeout() {
    let harness = start("trickle", PLUGIN, Scripted::default()).await;
    let stream = UnixStream::connect(harness.socket("plugin-a"))
        .await
        .unwrap();
    let (mut reader, mut writer) = stream.into_split();
    let started = Instant::now();
    tokio::spawn(async move {
        for byte in b"CONNECT allowed.test:443 HTTP/1.1\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
            if writer.write_all(&[*byte]).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    let mut response = [0_u8; 12];
    tokio::time::timeout(Duration::from_secs(3), reader.read_exact(&mut response))
        .await
        .expect("no response while trickling")
        .unwrap();
    assert_eq!(&response, b"HTTP/1.1 408");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(2),
        "{elapsed:?}"
    );
}

const LIMITED: &str = "documentation-ranges-public\n\
                       caller plugin-a kind=plugin uid={uid}\n\
                       caller plugin-b kind=plugin uid={other}\n\
                       allow plugin-a allowed.test:443\n\
                       caller-connections 2\n\
                       header-timeout 5\n";

#[tokio::test]
async fn a_caller_at_its_connection_limit_is_refused_and_other_sockets_are_served() {
    let resolver = Scripted::default();
    resolver.script("allowed.test", &[&["203.0.113.10"]]);
    let harness = start("limit", LIMITED, resolver).await;
    let first = UnixStream::connect(harness.socket("plugin-a"))
        .await
        .unwrap();
    let _second = UnixStream::connect(harness.socket("plugin-a"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut third = UnixStream::connect(harness.socket("plugin-a"))
        .await
        .unwrap();
    let (status, head) = send(&mut third, b"").await;
    assert_eq!(status, 503, "{head}");
    // Another caller's socket still answers at once (with its own refusal: the test process
    // has one uid; run.sh shows a 200 for another caller under the same load).
    let (_, status, head) = connect(&harness, "plugin-b", "allowed.test:443").await;
    assert_eq!(status, 403, "{head}");
    assert!(head.contains("caller identity mismatch"), "{head}");
    drop(first);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (_, status, _) = connect(&harness, "plugin-a", "allowed.test:443").await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn an_idle_tunnel_is_closed() {
    let resolver = Scripted::default();
    resolver.script("allowed.test", &[&["203.0.113.10"]]);
    let config = format!("{PLUGIN}tunnel-idle 1\n");
    let harness = start("idle", &config, resolver).await;
    let (mut stream, status, _) = connect(&harness, "plugin-a", "allowed.test:443").await;
    assert_eq!(status, 200);
    echo_round_trip(&mut stream, b"busy").await;
    let started = Instant::now();
    let mut byte = [0_u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte))
        .await
        .expect("idle tunnel was not closed")
        .unwrap();
    assert_eq!(n, 0);
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_busy_tunnel_is_closed_at_its_lifetime() {
    let resolver = Scripted::default();
    resolver.script("allowed.test", &[&["203.0.113.10"]]);
    let config = format!("{PLUGIN}tunnel-lifetime 1\ntunnel-idle 10\n");
    let harness = start("lifetime", &config, resolver).await;
    let (mut stream, status, _) = connect(&harness, "plugin-a", "allowed.test:443").await;
    assert_eq!(status, 200);
    let started = Instant::now();
    loop {
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "tunnel outlived its lifetime"
        );
        if stream.write_all(b"ping").await.is_err() {
            break;
        }
        let mut back = [0_u8; 4];
        match tokio::time::timeout(Duration::from_millis(500), stream.read_exact(&mut back)).await {
            Ok(Ok(_)) => tokio::time::sleep(Duration::from_millis(200)).await,
            Ok(Err(_)) => break,
            Err(_) => {}
        }
    }
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_black_holed_address_does_not_stall_the_next_one() {
    let resolver = Scripted::default();
    resolver.script("allowed.test", &[&["2001:db8:113::10", "203.0.113.10"]]);
    let harness = start("race", PLUGIN, resolver).await;
    harness.make_unreachable("[2001:db8:113::10]:443");
    let started = Instant::now();
    let (mut stream, status, _) = connect(&harness, "plugin-a", "allowed.test:443").await;
    assert_eq!(status, 200);
    echo_round_trip(&mut stream, b"via the second address").await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        harness.dialled(),
        ["[2001:db8:113::10]:443", "203.0.113.10:443"]
    );
}

#[tokio::test]
async fn one_deadline_bounds_every_dial() {
    let resolver = Scripted::default();
    resolver.script("allowed.test", &[&["2001:db8:113::10", "203.0.113.10"]]);
    let config = format!("{PLUGIN}dial-deadline 1\n");
    let harness = start("deadline", &config, resolver).await;
    harness.make_unreachable("[2001:db8:113::10]:443");
    harness.make_unreachable("203.0.113.10:443");
    let started = Instant::now();
    let (_, status, head) = connect(&harness, "plugin-a", "allowed.test:443").await;
    assert_eq!(status, 502, "{head}");
    assert!(head.contains("deadline"), "{head}");
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
}

const SNI: &str = "documentation-ranges-public\n\
                   caller plugin-a kind=plugin uid={uid}\n\
                   allow plugin-a allowed.test:443\n\
                   sni-check plugin-a\n\
                   header-timeout 1\n";

#[tokio::test]
async fn sni_check_passes_a_matching_client_hello_and_closes_on_anything_else() {
    let resolver = Scripted::default();
    resolver.script("allowed.test", &[&["203.0.113.10"]]);
    let harness = start("sni", SNI, resolver).await;
    let hello = client_hello(Some("allowed.test"), false);
    let (mut stream, status, _) = connect(&harness, "plugin-a", "allowed.test:443").await;
    assert_eq!(status, 200);
    echo_round_trip(&mut stream, &hello).await;
    let refused = [
        client_hello(Some("forbidden.test"), false),
        client_hello(Some("allowed.test"), true),
        client_hello(None, false),
        b"GET / HTTP/1.1\r\nHost: forbidden.test\r\n\r\n".to_vec(),
    ];
    for first in refused {
        let (mut stream, status, _) = connect(&harness, "plugin-a", "allowed.test:443").await;
        assert_eq!(status, 200);
        stream.write_all(&first).await.unwrap();
        let mut back = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut back)).await;
        assert!(matches!(read, Ok(Ok(0) | Err(_))), "{read:?}");
        assert!(
            back.is_empty(),
            "the refused first record reached the upstream"
        );
    }
    // A ClientHello sent with the CONNECT header is checked the same way.
    let mut stream = UnixStream::connect(harness.socket("plugin-a"))
        .await
        .unwrap();
    let mut pipelined = b"CONNECT allowed.test:443 HTTP/1.1\r\n\r\n".to_vec();
    pipelined.extend(client_hello(Some("forbidden.test"), false));
    let (status, _) = send(&mut stream, &pipelined).await;
    assert_eq!(status, 200);
    let mut back = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut back)).await;
    assert!(read.is_ok(), "tunnel not closed");
    assert!(back.is_empty());
}
