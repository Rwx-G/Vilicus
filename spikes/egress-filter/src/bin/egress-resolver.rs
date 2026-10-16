//! A scripted DNS server for the spike's test network: `egress-resolver <zone file> <listen addr>...`.
//!
//! Zone lines: `a <name> <ipv4>`, `aaaa <name> <ipv6>` (repeat a line for several records), and
//! `rebind <name> <first ipv4> <later ipv4>`, which answers the first address to the first A query
//! for that name and the second address to every later one. Every answer has TTL 0. Each query is
//! logged as `query name=<name> type=<type> n=<count> answers=<list>`, which `run.sh` reads to
//! show what the proxy resolved and what it never asked for.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::sync::{Arc, Mutex};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

#[derive(Default)]
struct Zone {
    a: HashMap<String, Vec<Ipv4Addr>>,
    aaaa: HashMap<String, Vec<Ipv6Addr>>,
    rebind: HashMap<String, (Ipv4Addr, Ipv4Addr)>,
}

impl Zone {
    fn parse(text: &str) -> Result<Self, String> {
        let mut zone = Self::default();
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let words: Vec<&str> = line.split_whitespace().collect();
            let bad = || format!("bad zone line: {line}");
            match words.as_slice() {
                ["a", name, ip] => zone
                    .a
                    .entry((*name).into())
                    .or_default()
                    .push(ip.parse().map_err(|_| bad())?),
                ["aaaa", name, ip] => zone
                    .aaaa
                    .entry((*name).into())
                    .or_default()
                    .push(ip.parse().map_err(|_| bad())?),
                ["rebind", name, first, later] => {
                    let pair = (
                        first.parse().map_err(|_| bad())?,
                        later.parse().map_err(|_| bad())?,
                    );
                    zone.rebind.insert((*name).into(), pair);
                }
                _ => return Err(bad()),
            }
        }
        Ok(zone)
    }

    fn knows(&self, name: &str) -> bool {
        self.a.contains_key(name) || self.aaaa.contains_key(name) || self.rebind.contains_key(name)
    }
}

struct Query {
    id: [u8; 2],
    flags: u16,
    name: String,
    qtype: u16,
    question: Vec<u8>,
}

fn parse_query(packet: &[u8]) -> Option<Query> {
    if packet.len() < 12 || u16::from_be_bytes([packet[4], packet[5]]) != 1 {
        return None;
    }
    let mut labels = Vec::new();
    let mut at = 12;
    loop {
        let len = usize::from(*packet.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        labels.push(String::from_utf8_lossy(packet.get(at..at + len)?).to_ascii_lowercase());
        at += len;
    }
    let qtype = u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]);
    let question_end = at + 4;
    Some(Query {
        id: [packet[0], packet[1]],
        flags: u16::from_be_bytes([packet[2], packet[3]]),
        name: labels.join("."),
        qtype,
        question: packet.get(12..question_end)?.to_vec(),
    })
}

fn answer(query: &Query, rcode: u16, records: &[IpAddr]) -> Vec<u8> {
    // QR, the query's opcode and RD, AA, RA.
    let flags = 0x8000 | (query.flags & 0x7900) | 0x0400 | 0x0080 | rcode;
    let count = u16::try_from(records.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&query.id);
    out.extend_from_slice(&flags.to_be_bytes());
    for section in [1, count, 0, 0] {
        out.extend_from_slice(&u16::to_be_bytes(section));
    }
    out.extend_from_slice(&query.question);
    for record in records {
        out.extend_from_slice(&[0xc0, 0x0c]);
        let (rtype, data) = match record {
            IpAddr::V4(v4) => (TYPE_A, v4.octets().to_vec()),
            IpAddr::V6(v6) => (TYPE_AAAA, v6.octets().to_vec()),
        };
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1_u16.to_be_bytes());
        out.extend_from_slice(&0_u32.to_be_bytes());
        out.extend_from_slice(&u16::try_from(data.len()).unwrap_or_default().to_be_bytes());
        out.extend_from_slice(&data);
    }
    out
}

fn serve(socket: &UdpSocket, zone: &Zone, counts: &Mutex<HashMap<(String, u16), u32>>) {
    let mut buffer = [0_u8; 1500];
    loop {
        let Ok((len, from)) = socket.recv_from(&mut buffer) else {
            continue;
        };
        let Some(query) = parse_query(&buffer[..len]) else {
            continue;
        };
        let n = {
            let mut counts = counts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let count = counts.entry((query.name.clone(), query.qtype)).or_default();
            *count += 1;
            *count
        };
        let records: Vec<IpAddr> = match query.qtype {
            TYPE_A => match zone.rebind.get(&query.name) {
                Some((first, later)) => vec![IpAddr::V4(if n == 1 { *first } else { *later })],
                None => zone
                    .a
                    .get(&query.name)
                    .into_iter()
                    .flatten()
                    .copied()
                    .map(IpAddr::V4)
                    .collect(),
            },
            TYPE_AAAA => zone
                .aaaa
                .get(&query.name)
                .into_iter()
                .flatten()
                .copied()
                .map(IpAddr::V6)
                .collect(),
            _ => Vec::new(),
        };
        let rcode = if zone.knows(&query.name) { 0 } else { 3 };
        let qtype = match query.qtype {
            TYPE_A => "A".to_owned(),
            TYPE_AAAA => "AAAA".to_owned(),
            other => other.to_string(),
        };
        let shown: Vec<String> = records.iter().map(ToString::to_string).collect();
        println!(
            "query name={} type={qtype} n={n} from={from} answers=[{}]",
            query.name,
            shown.join(",")
        );
        // A lost reply is a lost UDP datagram; the client retries.
        let _ = socket.send_to(&answer(&query, rcode, &records), from);
    }
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((zone_path, listen)) = args.split_first().filter(|(_, l)| !l.is_empty()) else {
        return Err("usage: egress-resolver <zone file> <listen addr>...".into());
    };
    let text = std::fs::read_to_string(zone_path).map_err(|e| format!("{zone_path}: {e}"))?;
    let zone = Arc::new(Zone::parse(&text)?);
    let counts = Arc::new(Mutex::new(HashMap::new()));
    let mut threads = Vec::new();
    for addr in listen {
        let socket = UdpSocket::bind(addr).map_err(|e| format!("{addr}: {e}"))?;
        let (zone, counts) = (Arc::clone(&zone), Arc::clone(&counts));
        threads.push(std::thread::spawn(move || serve(&socket, &zone, &counts)));
    }
    println!("event=ready");
    for thread in threads {
        thread
            .join()
            .map_err(|_| "a listener thread panicked".to_owned())?;
    }
    Ok(())
}
