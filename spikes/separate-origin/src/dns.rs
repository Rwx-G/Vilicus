//! The test network's own DNS server. It answers A queries for the layout's instance names and for
//! every name under an attacker suffix, answers no data for other types of known names, and
//! NXDOMAIN for the rest. Every query is logged, which is how the harness sees DNS prefetching
//! and preconnects that never become HTTP requests.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::instances::Layout;
use crate::log::{Entry, Log};

const TYPE_A: u16 = 1;

/// The names the server knows.
pub struct Zone {
    exact: Vec<(String, Ipv4Addr)>,
    suffixes: Vec<(String, Ipv4Addr)>,
}

impl Zone {
    /// Builds the zone from the layout.
    pub fn from_layout(layout: &Layout) -> Result<Self, String> {
        let mut exact = Vec::new();
        for instance in &layout.instances {
            let address = layout
                .deployment_address(&instance.deployment)
                .ok_or_else(|| format!("no address for {}", instance.deployment))?;
            exact.push((instance.name.clone(), address));
        }
        let sink = layout.server_address("sink");
        let suffixes = layout
            .wildcards
            .iter()
            .filter_map(|(suffix, _)| sink.map(|a| (format!(".{suffix}"), a)))
            .collect();
        Ok(Self { exact, suffixes })
    }

    /// The address of `name`, or `None` when the name does not exist.
    pub fn lookup(&self, name: &str) -> Option<Ipv4Addr> {
        self.exact
            .iter()
            .find(|(n, _)| n == name)
            .or_else(|| {
                self.suffixes
                    .iter()
                    .find(|(s, _)| name.ends_with(s.as_str()))
            })
            .map(|(_, a)| *a)
    }
}

/// A parsed question.
#[derive(Debug, PartialEq, Eq)]
pub struct Question {
    pub id: [u8; 2],
    pub flags: u16,
    pub name: String,
    pub qtype: u16,
    /// The question section's bytes, echoed in the answer.
    pub raw: Vec<u8>,
}

/// Parses a single-question query; anything else is ignored.
pub fn parse(packet: &[u8]) -> Option<Question> {
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
    Some(Question {
        id: [packet[0], packet[1]],
        flags: u16::from_be_bytes([packet[2], packet[3]]),
        name: labels.join("."),
        qtype,
        raw: packet.get(12..at + 4)?.to_vec(),
    })
}

/// Builds the answer to `question`: one A record with TTL 0, no data, or NXDOMAIN.
pub fn answer(question: &Question, address: Option<Ipv4Addr>) -> Vec<u8> {
    let rcode = if address.is_some() { 0 } else { 3 };
    let record = address.filter(|_| question.qtype == TYPE_A);
    // QR, the query's opcode and RD, then AA and RA.
    let flags = 0x8000 | (question.flags & 0x7900) | 0x0400 | 0x0080 | rcode;
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&question.id);
    out.extend_from_slice(&flags.to_be_bytes());
    for count in [1, u16::from(record.is_some()), 0, 0] {
        out.extend_from_slice(&u16::to_be_bytes(count));
    }
    out.extend_from_slice(&question.raw);
    if let Some(address) = record {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&1_u16.to_be_bytes());
        out.extend_from_slice(&0_u32.to_be_bytes());
        out.extend_from_slice(&4_u16.to_be_bytes());
        out.extend_from_slice(&address.octets());
    }
    out
}

/// Serves DNS on `socket` until the process ends, logging every query into `log`.
pub async fn serve(socket: UdpSocket, zone: Arc<Zone>, log: Arc<Log>) {
    let mut buffer = [0_u8; 1500];
    loop {
        let Ok((len, from)) = socket.recv_from(&mut buffer).await else {
            continue;
        };
        let Some(question) = parse(&buffer[..len]) else {
            continue;
        };
        let address = zone.lookup(&question.name);
        log.push(entry(&question, from, address));
        // A lost reply is a lost datagram; the client retries.
        let _ = socket.send_to(&answer(&question, address), from).await;
    }
}

fn entry(question: &Question, from: SocketAddr, address: Option<Ipv4Addr>) -> Entry {
    Entry {
        kind: "dns",
        listener: "dns",
        peer: from.ip().to_string(),
        method: question.qtype.to_string(),
        host: question.name.clone(),
        outcome: address.map_or_else(|| "nxdomain".into(), |a| a.to_string()),
        ..Entry::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            packet.push(u8::try_from(label.len()).unwrap_or_default());
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet
    }

    fn zone() -> Zone {
        let layout = Layout::parse(
            "ca c C\ndeployment direct 10.0.0.10\nserver sink 10.0.0.30\n\
             instance o direct vilicus.internal c\nwildcard attacker.example c",
        )
        .unwrap_or_default();
        Zone::from_layout(&layout).unwrap_or(Zone {
            exact: Vec::new(),
            suffixes: Vec::new(),
        })
    }

    #[test]
    fn exact_and_wildcard_names_resolve() {
        let zone = zone();
        assert_eq!(
            zone.lookup("vilicus.internal"),
            Some(Ipv4Addr::new(10, 0, 0, 10))
        );
        assert_eq!(
            zone.lookup("r1-img.attacker.example"),
            Some(Ipv4Addr::new(10, 0, 0, 30))
        );
        assert_eq!(zone.lookup("attacker.example.evil"), None);
        assert_eq!(zone.lookup("other.internal"), None);
    }

    #[test]
    fn a_query_gets_one_record_and_others_get_no_data_or_nxdomain() {
        let zone = zone();
        let q = parse(&query("Vilicus.Internal", TYPE_A));
        assert_eq!(
            q.as_ref().map(|q| q.name.as_str()),
            Some("vilicus.internal")
        );
        let q = q.unwrap_or(Question {
            id: [0; 2],
            flags: 0,
            name: String::new(),
            qtype: 0,
            raw: Vec::new(),
        });
        let reply = answer(&q, zone.lookup(&q.name));
        assert_eq!(&reply[..2], &[0x12, 0x34]);
        assert_eq!(reply[3] & 0x0f, 0);
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1);
        assert_eq!(&reply[reply.len() - 4..], &[10, 0, 0, 10]);

        let aaaa = parse(&query("vilicus.internal", 28)).map(|q| answer(&q, zone.lookup(&q.name)));
        let aaaa = aaaa.unwrap_or_default();
        assert_eq!(aaaa[3] & 0x0f, 0);
        assert_eq!(u16::from_be_bytes([aaaa[6], aaaa[7]]), 0);

        let missing =
            parse(&query("nope.internal", TYPE_A)).map(|q| answer(&q, zone.lookup(&q.name)));
        assert_eq!(missing.unwrap_or_default()[3] & 0x0f, 3);
    }

    #[test]
    fn malformed_queries_are_ignored() {
        assert!(parse(&[0; 5]).is_none());
        let mut two_questions = query("a.b", TYPE_A);
        two_questions[5] = 2;
        assert!(parse(&two_questions).is_none());
    }
}
