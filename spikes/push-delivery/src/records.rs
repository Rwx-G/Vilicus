//! The results file: one tab-separated line per send and per acknowledgement, appended as they
//! happen. A record carries an anonymous phone label and a server kind, never a URL, a topic, a
//! token, a phone model or a server name (story 1.13, AC1); the types below cannot hold one.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use std::sync::Mutex;

use crate::token::is_alert_id;

/// An anonymous phone label, `phone-<n>` with `n` from 1 to 99. Anything else (a model, an owner
/// name) is refused, so it cannot reach the results.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhoneLabel(String);

impl PhoneLabel {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for PhoneLabel {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let valid = text.strip_prefix("phone-").is_some_and(|n| {
            !n.is_empty()
                && n.len() <= 2
                && !n.starts_with('0')
                && n.bytes().all(|b| b.is_ascii_digit())
        });
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(format!(
                "phone label `{text}` is not `phone-<1..99>`; labels are anonymous"
            ))
        }
    }
}

impl fmt::Display for PhoneLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which kind of push server carried an alert (D118). The server's name is never recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServerKind {
    SelfHosted,
    Public,
}

impl ServerKind {
    pub const ALL: [ServerKind; 2] = [ServerKind::SelfHosted, ServerKind::Public];

    pub fn as_str(self) -> &'static str {
        match self {
            ServerKind::SelfHosted => "self-hosted",
            ServerKind::Public => "public",
        }
    }
}

impl FromStr for ServerKind {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        ServerKind::ALL
            .into_iter()
            .find(|kind| kind.as_str() == text)
            .ok_or_else(|| format!("server kind `{text}` is neither self-hosted nor public"))
    }
}

impl fmt::Display for ServerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One alert handed to the push server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendRecord {
    pub id: String,
    pub phone: PhoneLabel,
    pub server: ServerKind,
    /// When the publish request started.
    pub sent_ms: u64,
    /// Whether the push server accepted it (2xx). A refused or failed publish counts as not
    /// delivered.
    pub published: bool,
}

/// One acknowledgement received by the collector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckRecord {
    pub id: String,
    /// When the acknowledgement reached the collector: an upper bound of the reception time,
    /// and the time the verdict uses.
    pub arrival_ms: u64,
    /// The reception time the phone reported, if any. Informational only: phone clocks drift.
    pub phone_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Send(SendRecord),
    Ack(AckRecord),
}

impl Record {
    pub fn to_line(&self) -> String {
        match self {
            Record::Send(send) => format!(
                "send\t{}\t{}\t{}\t{}\t{}",
                send.id,
                send.phone,
                send.server,
                send.sent_ms,
                if send.published { "ok" } else { "failed" }
            ),
            Record::Ack(ack) => format!(
                "ack\t{}\t{}\t{}",
                ack.id,
                ack.arrival_ms,
                ack.phone_ms
                    .map_or_else(|| "-".to_owned(), |ms| ms.to_string())
            ),
        }
    }

    pub fn parse(line: &str) -> Result<Record, String> {
        let fields: Vec<&str> = line.split('\t').collect();
        let number = |text: &str| {
            text.parse::<u64>()
                .map_err(|_| format!("`{text}` is not a time in ms"))
        };
        let id = |text: &str| {
            if is_alert_id(text) {
                Ok(text.to_owned())
            } else {
                Err(format!("`{text}` is not an alert id"))
            }
        };
        match fields.as_slice() {
            ["send", alert_id, phone, server, sent_ms, outcome] => Ok(Record::Send(SendRecord {
                id: id(alert_id)?,
                phone: phone.parse()?,
                server: server.parse()?,
                sent_ms: number(sent_ms)?,
                published: match *outcome {
                    "ok" => true,
                    "failed" => false,
                    other => return Err(format!("unknown publish outcome `{other}`")),
                },
            })),
            ["ack", alert_id, arrival_ms, phone_ms] => Ok(Record::Ack(AckRecord {
                id: id(alert_id)?,
                arrival_ms: number(arrival_ms)?,
                phone_ms: match *phone_ms {
                    "-" => None,
                    ms => Some(number(ms)?),
                },
            })),
            _ => Err(format!("unrecognised record `{line}`")),
        }
    }
}

/// Reads every record of a results file. A malformed line is an error, never skipped.
pub fn read_records(path: &Path) -> Result<Vec<Record>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read results file {}: {e}", path.display()))?;
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.is_empty())
        .map(|(n, line)| Record::parse(line).map_err(|e| format!("line {}: {e}", n + 1)))
        .collect()
}

/// The append-only results file shared by the sender and the collector.
pub struct ResultsLog {
    file: Mutex<File>,
}

impl ResultsLog {
    pub fn open(path: &Path) -> Result<Self, String> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("cannot open results file {}: {e}", path.display()))?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Appends one record and syncs it, so a crash during the 7-day run loses at most the
    /// record being written.
    pub fn append(&self, record: &Record) -> Result<(), String> {
        let line = format!("{}\n", record.to_line());
        let mut file = self
            .file
            .lock()
            .map_err(|_| "results file lock poisoned".to_owned())?;
        file.write_all(line.as_bytes())
            .and_then(|()| file.sync_data())
            .map_err(|e| format!("cannot append to the results file: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn records_round_trip() {
        let records = [
            Record::Send(SendRecord {
                id: ID.to_owned(),
                phone: "phone-2".parse().unwrap(),
                server: ServerKind::Public,
                sent_ms: 1_000,
                published: false,
            }),
            Record::Ack(AckRecord {
                id: ID.to_owned(),
                arrival_ms: 2_000,
                phone_ms: Some(1_900),
            }),
            Record::Ack(AckRecord {
                id: ID.to_owned(),
                arrival_ms: 2_000,
                phone_ms: None,
            }),
        ];
        for record in records {
            assert_eq!(Record::parse(&record.to_line()), Ok(record));
        }
    }

    #[test]
    fn phone_labels_are_anonymous() {
        for valid in ["phone-1", "phone-9", "phone-42"] {
            assert!(valid.parse::<PhoneLabel>().is_ok(), "{valid}");
        }
        for invalid in [
            "phone-0",
            "phone-01",
            "phone-100",
            "phone-",
            "Pixel-8",
            "phone-1 pixel",
            "alice-phone",
        ] {
            assert!(invalid.parse::<PhoneLabel>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn server_kinds_round_trip_and_nothing_else_parses() {
        for kind in ServerKind::ALL {
            assert_eq!(kind.as_str().parse::<ServerKind>(), Ok(kind));
        }
        assert!("ntfy.sh".parse::<ServerKind>().is_err());
    }

    #[test]
    fn a_send_line_holds_only_id_label_kind_time_and_outcome() {
        let line = Record::Send(SendRecord {
            id: ID.to_owned(),
            phone: "phone-1".parse().unwrap(),
            server: ServerKind::SelfHosted,
            sent_ms: 5,
            published: true,
        })
        .to_line();
        assert_eq!(line, format!("send\t{ID}\tphone-1\tself-hosted\t5\tok"));
    }

    #[test]
    fn malformed_lines_are_errors() {
        for line in [
            "send\tnotanid\tphone-1\tpublic\t1\tok",
            "send\t0123456789abcdef0123456789abcdef\tphone-1\tntfy.sh\t1\tok",
            "send\t0123456789abcdef0123456789abcdef\tphone-1\tpublic\t1\tmaybe",
            "ack\t0123456789abcdef0123456789abcdef\tsoon\t-",
            "hello",
        ] {
            assert!(Record::parse(line).is_err(), "{line}");
        }
    }
}
