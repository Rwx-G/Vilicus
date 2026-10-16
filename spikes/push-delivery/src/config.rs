//! The run configuration: a line-based file, one setting per line, `#` for comments. Topics and
//! tokens may be given as `env:NAME` so the file itself holds no secret. See
//! `push-delivery.example.conf` for every setting.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::records::{PhoneLabel, ServerKind};
use crate::token::is_alert_id;

/// The pass criterion of an evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Criterion {
    /// An alert counts as delivered when acknowledged within this delay.
    pub deadline_ms: u64,
    /// The observation window each phone must cover.
    pub window_ms: u64,
    /// The minimum share of alerts delivered in time, in hundredths of a percent.
    pub threshold_bp: u64,
    /// Below this many evaluated alerts a phone's result is incomplete, not a pass (spike
    /// choice: at 99 %, fewer than 100 alerts cannot tell one miss from a pass).
    pub min_alerts: u64,
}

impl Criterion {
    /// The D105 criterion: 99 % of alerts within 10 minutes over 7 days per phone.
    pub const D105: Criterion = Criterion {
        deadline_ms: 10 * 60 * 1000,
        window_ms: 7 * 24 * 60 * 60 * 1000,
        threshold_bp: 9_900,
        min_alerts: 100,
    };

    /// Whether this criterion is the D105 one (the minimum alert count is a spike addition and
    /// may only be raised).
    pub fn is_d105(&self) -> bool {
        self.deadline_ms == Self::D105.deadline_ms
            && self.window_ms == Self::D105.window_ms
            && self.threshold_bp == Self::D105.threshold_bp
            && self.min_alerts >= Self::D105.min_alerts
    }
}

/// The local hours counted as night, to show that idle nights were measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Night {
    pub utc_offset_minutes: i64,
    pub start_hour: u64,
    pub end_hour: u64,
}

impl Night {
    pub fn contains(&self, unix_ms: u64) -> bool {
        const DAY_S: i64 = 86_400;
        let local_s = (unix_ms / 1000) as i64 + self.utc_offset_minutes * 60;
        let hour = (local_s.rem_euclid(DAY_S) / 3600) as u64;
        if self.start_hour <= self.end_hour {
            (self.start_hour..self.end_hour).contains(&hour)
        } else {
            hour >= self.start_hour || hour < self.end_hour
        }
    }
}

/// One phone on one push server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub phone: PhoneLabel,
    pub server: ServerKind,
    pub base_url: String,
    pub topic: String,
    pub token: Option<String>,
}

impl Target {
    /// The publish and subscribe URL of the topic, without query.
    pub fn topic_url(&self) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), self.topic)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub results: PathBuf,
    pub listen: SocketAddr,
    pub mean_interval_ms: u64,
    pub criterion: Criterion,
    pub night: Night,
    pub ca_file: Option<PathBuf>,
    pub targets: Vec<Target>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
        Config::parse(&text, |name| std::env::var(name).ok())
    }

    /// Parses a configuration; `env` resolves `env:NAME` values.
    pub fn parse(text: &str, env: impl Fn(&str) -> Option<String>) -> Result<Config, String> {
        let mut config = Config {
            results: PathBuf::from("results.tsv"),
            listen: "0.0.0.0:8080".parse().map_err(|e| format!("{e}"))?,
            mean_interval_ms: 30 * 60 * 1000,
            criterion: Criterion::D105,
            night: Night {
                utc_offset_minutes: 0,
                start_hour: 0,
                end_hour: 6,
            },
            ca_file: None,
            targets: Vec::new(),
        };
        let mut seen = HashSet::new();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            let at = |e: String| format!("config line {}: {e}", index + 1);
            match fields.as_slice() {
                ["results", path] => config.results = PathBuf::from(path),
                ["listen", addr] => {
                    config.listen = addr
                        .parse()
                        .map_err(|e| at(format!("listen address: {e}")))?;
                }
                ["mean_interval_ms", n] => config.mean_interval_ms = positive(n).map_err(at)?,
                ["deadline_ms", n] => config.criterion.deadline_ms = positive(n).map_err(at)?,
                ["window_ms", n] => config.criterion.window_ms = positive(n).map_err(at)?,
                ["min_alerts", n] => config.criterion.min_alerts = positive(n).map_err(at)?,
                ["threshold_percent", p] => {
                    config.criterion.threshold_bp = basis_points(p).map_err(at)?;
                }
                ["night", offset, start, end] => {
                    config.night = Night {
                        utc_offset_minutes: offset
                            .parse()
                            .map_err(|_| at(format!("UTC offset `{offset}`")))?,
                        start_hour: hour(start).map_err(at)?,
                        end_hour: hour(end).map_err(at)?,
                    };
                }
                ["ca_file", path] => config.ca_file = Some(PathBuf::from(path)),
                ["target", phone, server, base_url, topic, token] => {
                    let target = Target {
                        phone: phone.parse().map_err(at)?,
                        server: server.parse().map_err(at)?,
                        base_url: url(base_url).map_err(at)?,
                        topic: resolve(topic, &env).map_err(at)?,
                        token: match *token {
                            "-" => None,
                            value => Some(resolve(value, &env).map_err(at)?),
                        },
                    };
                    check_topic(&target).map_err(at)?;
                    if !seen.insert((target.phone.clone(), target.server)) {
                        return Err(at(format!(
                            "{} on {} is configured twice",
                            target.phone, target.server
                        )));
                    }
                    config.targets.push(target);
                }
                _ => return Err(at(format!("unrecognised setting `{line}`"))),
            }
        }
        if config.targets.is_empty() {
            return Err("config has no target".to_owned());
        }
        Ok(config)
    }
}

fn positive(text: &str) -> Result<u64, String> {
    match text.parse::<u64>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(format!("`{text}` is not a positive integer")),
    }
}

fn hour(text: &str) -> Result<u64, String> {
    match text.parse::<u64>() {
        Ok(h) if h < 24 => Ok(h),
        _ => Err(format!("`{text}` is not an hour from 0 to 23")),
    }
}

/// `99` or `99.5` or `99.25` as basis points.
fn basis_points(text: &str) -> Result<u64, String> {
    let error = || format!("`{text}` is not a percentage with at most two decimals");
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if fraction.len() > 2 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return Err(error());
    }
    let whole: u64 = whole.parse().map_err(|_| error())?;
    let fraction: u64 = format!("{fraction:0<2}").parse().map_err(|_| error())?;
    let bp = whole * 100 + fraction;
    if bp == 0 || bp > 10_000 {
        return Err(error());
    }
    Ok(bp)
}

fn url(text: &str) -> Result<String, String> {
    if (text.starts_with("http://") || text.starts_with("https://")) && !text.contains('?') {
        Ok(text.to_owned())
    } else {
        Err(format!("`{text}` is not an http(s) base URL"))
    }
}

fn resolve(value: &str, env: &impl Fn(&str) -> Option<String>) -> Result<String, String> {
    match value.strip_prefix("env:") {
        Some(name) => env(name).ok_or_else(|| format!("environment variable {name} is not set")),
        None => Ok(value.to_owned()),
    }
}

/// AD-32: a topic uses an access token or a random name of at least 128 bits. Without a token
/// the topic must have the shape `push-delivery new-topic` prints.
fn check_topic(target: &Target) -> Result<(), String> {
    let valid_chars = !target.topic.is_empty()
        && target.topic.len() <= 64
        && target
            .topic
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !valid_chars {
        return Err("a topic is 1 to 64 letters, digits, `-` or `_`".to_owned());
    }
    if target.token.is_none() && !is_alert_id(&target.topic) {
        return Err(format!(
            "{} on {}: a topic without an access token must be 128 random bits (use `push-delivery new-topic`)",
            target.phone, target.server
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOPIC: &str = "0123456789abcdef0123456789abcdef";

    fn env(name: &str) -> Option<String> {
        match name {
            "TOKEN" => Some("tk_secret".to_owned()),
            "TOPIC" => Some(TOPIC.to_owned()),
            _ => None,
        }
    }

    #[test]
    fn defaults_are_the_d105_criterion() {
        let config = Config::parse(
            &format!("target phone-1 public https://push.example.com {TOPIC} -"),
            env,
        )
        .unwrap();
        assert_eq!(config.criterion, Criterion::D105);
        assert!(config.criterion.is_d105());
    }

    #[test]
    fn full_config_parses() {
        let text = "\
            # comment\n\
            results /tmp/r.tsv\n\
            listen 127.0.0.1:9000\n\
            mean_interval_ms 500\n\
            deadline_ms 3000   # simulation\n\
            window_ms 40000\n\
            threshold_percent 99.5\n\
            min_alerts 50\n\
            night 60 23 6\n\
            target phone-1 self-hosted http://ntfy-self/ my-topic env:TOKEN\n\
            target phone-1 public http://ntfy-public env:TOPIC -\n";
        let config = Config::parse(text, env).unwrap();
        assert_eq!(config.listen, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(config.criterion.threshold_bp, 9_950);
        assert!(!config.criterion.is_d105());
        assert_eq!(config.targets[0].token.as_deref(), Some("tk_secret"));
        assert_eq!(config.targets[0].topic_url(), "http://ntfy-self/my-topic");
        assert_eq!(config.targets[1].topic, TOPIC);
    }

    #[test]
    fn unsafe_or_ambiguous_settings_are_refused() {
        for text in [
            "target phone-1 public https://push.example.com short-topic -",
            "target Pixel-8 public https://push.example.com env:TOPIC -",
            "target phone-1 ntfy.sh https://push.example.com env:TOPIC -",
            "target phone-1 public ftp://push.example.com env:TOPIC -",
            "target phone-1 public https://push.example.com env:MISSING -",
            "target phone-1 public https://a.example.com env:TOPIC -\ntarget phone-1 public https://b.example.com env:TOPIC -",
            "threshold_percent 99.555\ntarget phone-1 public https://a.example.com env:TOPIC -",
            "deadline_ms 0\ntarget phone-1 public https://a.example.com env:TOPIC -",
            "colour blue\ntarget phone-1 public https://a.example.com env:TOPIC -",
            "",
        ] {
            assert!(Config::parse(text, env).is_err(), "{text}");
        }
    }

    #[test]
    fn the_example_config_parses_with_the_d105_criterion() {
        let example = include_str!("../push-delivery.example.conf");
        let config = Config::parse(example, |name| {
            Some(if name.starts_with("TOKEN") {
                "tk_example".to_owned()
            } else {
                TOPIC.to_owned()
            })
        })
        .unwrap();
        assert!(config.criterion.is_d105());
        assert_eq!(config.targets.len(), 4);
    }

    #[test]
    fn night_wraps_midnight() {
        let night = Night {
            utc_offset_minutes: 60,
            start_hour: 23,
            end_hour: 6,
        };
        let hour_ms = 3_600_000;
        // 22:30 UTC is 23:30 at UTC+1.
        assert!(night.contains(22 * hour_ms + hour_ms / 2));
        // 05:30 UTC is 06:30 at UTC+1.
        assert!(!night.contains(5 * hour_ms + hour_ms / 2));
        assert!(!night.contains(12 * hour_ms));
    }
}
