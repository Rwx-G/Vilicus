//! The proxy configuration: callers, their allowlists, named private destinations, the address
//! policy, per-host budgets and the connection limits.
//!
//! A line-based format keeps the spike free of a serialisation dependency. One directive per
//! line, `#` starts a comment:
//!
//! ```text
//! caller <name> kind=<core|backup|plugin|ai> uid=<uid>
//! allow <caller> <host:port>
//! private <caller> <host:port> <prefix>
//! sni-check <caller>
//! blocked <prefix>
//! nat64-prefix <ipv6 prefix>/96
//! budget <host> tunnels=<n> window=<seconds> reserve=<n>
//! budget-default tunnels=<n> window=<seconds> reserve=<n>
//! header-timeout <seconds>
//! caller-connections <n>
//! tunnel-idle <seconds>
//! tunnel-lifetime <seconds>
//! dial-deadline <seconds>
//! documentation-ranges-public          (only with the `test-network` feature)
//! ```

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use crate::address::{AddressPolicy, Prefix};
use crate::target::{HostPort, parse_authority, parse_hostname};

/// What a caller is; only the Core and the backup caller may hold named private destinations
/// (D105) or draw on a budget's reserve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerKind {
    /// The Core's own fetches.
    Core,
    /// `vilicus backup`'s upload identity.
    Backup,
    /// A plugin unit.
    Plugin,
    /// An AI process unit.
    Ai,
}

impl CallerKind {
    /// The Core and the backup caller.
    #[must_use]
    pub fn is_core_side(self) -> bool {
        matches!(self, Self::Core | Self::Backup)
    }
}

/// One caller: its own socket, its expected peer identity and its allowlist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    /// The socket is `<name>.sock` in the socket directory.
    pub name: String,
    /// What the caller is.
    pub kind: CallerKind,
    /// The peer uid the socket accepts.
    pub uid: u32,
    /// Exact `host:port` entries reachable on public addresses.
    pub allow: Vec<HostPort>,
    /// Named private destinations: `host:port` and the private range its addresses must fall in.
    pub private: Vec<(HostPort, Prefix)>,
    /// The first TLS ClientHello in each tunnel must carry an SNI equal to the CONNECT host and
    /// no Encrypted Client Hello extension.
    pub sni_check: bool,
}

/// A budget of tunnels per sliding window, shared by every caller that reaches the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetLimit {
    /// Tunnels allowed per window, reserve included.
    pub tunnels: u32,
    /// Window length.
    pub window: Duration,
    /// Part of `tunnels` that only the Core and the backup caller may use.
    pub reserve: u32,
}

/// The whole configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Every caller, one socket each.
    pub callers: Vec<Caller>,
    /// The deployment part of the address policy.
    pub policy: AddressPolicy,
    /// Budgets of named hosts, keyed by canonical hostname (every port counts).
    pub budgets: Vec<(String, BudgetLimit)>,
    /// The budget of every host without its own line.
    pub default_budget: BudgetLimit,
    /// How long a caller may take to send the whole CONNECT header.
    pub header_timeout: Duration,
    /// Connections open at once per caller socket, tunnels included.
    pub caller_connections: usize,
    /// A tunnel with no byte in either direction for this long is closed.
    pub tunnel_idle: Duration,
    /// A tunnel is closed after this long whatever its traffic.
    pub tunnel_lifetime: Duration,
    /// One deadline over every dial attempt of a tunnel.
    pub dial_deadline: Duration,
}

/// Ranges a named private destination may point into: RFC 1918 and unique local. Loopback,
/// link-local and the rest of the refused set stay refused even for the Core.
const NAMEABLE_PRIVATE: &[Prefix] = &[
    Prefix::v4([10, 0, 0, 0], 8),
    Prefix::v4([172, 16, 0, 0], 12),
    Prefix::v4([192, 168, 0, 0], 16),
    Prefix::v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
];

/// Whether every address of `prefix` lies in a range a named private destination may use.
#[must_use]
pub fn is_nameable_private(prefix: &Prefix) -> bool {
    NAMEABLE_PRIVATE.iter().any(|range| range.covers(prefix))
}

/// Whether `ip` lies in a range a named private destination may use; checked again at connect
/// time, so a configuration that bypassed the load check still cannot reach loopback.
#[must_use]
pub fn in_nameable_private(ip: IpAddr) -> bool {
    NAMEABLE_PRIVATE.iter().any(|range| range.contains(ip))
}

fn parse_budget(words: &[&str]) -> Result<BudgetLimit, String> {
    let [tunnels, window, reserve] = words else {
        return Err("expected tunnels=<n> window=<seconds> reserve=<n>".into());
    };
    let number = |word: &str, key: &str| -> Result<u64, String> {
        word.strip_prefix(key)
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| format!("malformed {key}"))
    };
    let tunnels = u32::try_from(number(tunnels, "tunnels=")?).map_err(|e| e.to_string())?;
    let window = number(window, "window=")?;
    let reserve = u32::try_from(number(reserve, "reserve=")?).map_err(|e| e.to_string())?;
    if window == 0 {
        return Err("malformed window".into());
    }
    if reserve >= tunnels {
        return Err("the reserve must leave room for other callers".into());
    }
    Ok(BudgetLimit {
        tunnels,
        window: Duration::from_secs(window),
        reserve,
    })
}

fn positive(text: &str) -> Result<u64, String> {
    text.parse()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| "expected a positive number".to_owned())
}

impl Config {
    /// Parses and validates the configuration text.
    ///
    /// # Errors
    /// Returns the first invalid line, with its number.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut config = Self {
            callers: Vec::new(),
            policy: AddressPolicy::default(),
            budgets: Vec::new(),
            default_budget: BudgetLimit {
                tunnels: 600,
                window: Duration::from_secs(600),
                reserve: 60,
            },
            header_timeout: Duration::from_secs(10),
            caller_connections: 64,
            tunnel_idle: Duration::from_secs(300),
            tunnel_lifetime: Duration::from_secs(3600),
            dial_deadline: Duration::from_secs(10),
        };
        for (index, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            config
                .apply(line)
                .map_err(|e| format!("line {}: {e}: {line}", index + 1))?;
        }
        let mut names = HashSet::new();
        let mut uids = HashSet::new();
        for caller in &config.callers {
            if !names.insert(&caller.name) || !uids.insert(caller.uid) {
                return Err(format!("caller {} reuses a name or uid", caller.name));
            }
        }
        Ok(config)
    }

    fn apply(&mut self, line: &str) -> Result<(), String> {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["caller", name, kind, uid] => {
                let valid_name = !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
                if !valid_name {
                    return Err("caller names are lowercase letters, digits and hyphens".into());
                }
                let kind = match *kind {
                    "kind=core" => CallerKind::Core,
                    "kind=backup" => CallerKind::Backup,
                    "kind=plugin" => CallerKind::Plugin,
                    "kind=ai" => CallerKind::Ai,
                    _ => return Err("unknown caller kind".into()),
                };
                let uid = uid
                    .strip_prefix("uid=")
                    .and_then(|u| u.parse().ok())
                    .ok_or("malformed uid")?;
                self.callers.push(Caller {
                    name: (*name).to_owned(),
                    kind,
                    uid,
                    allow: Vec::new(),
                    private: Vec::new(),
                    sni_check: false,
                });
            }
            ["allow", caller, target] => {
                let target = parse_authority(target).map_err(|e| e.reason().to_owned())?;
                self.caller_mut(caller)?.allow.push(target);
            }
            ["private", caller, target, prefix] => {
                let target = parse_authority(target).map_err(|e| e.reason().to_owned())?;
                let prefix = Prefix::parse(prefix)?;
                if !is_nameable_private(&prefix) {
                    return Err(
                        "a named private destination must lie in RFC 1918 or unique local space"
                            .into(),
                    );
                }
                let caller = self.caller_mut(caller)?;
                if !caller.kind.is_core_side() {
                    return Err("only the Core and the backup caller may hold a named private destination (D105)".into());
                }
                caller.private.push((target, prefix));
            }
            ["sni-check", caller] => self.caller_mut(caller)?.sni_check = true,
            ["blocked", prefix] => self.policy.blocked.push(Prefix::parse(prefix)?),
            ["nat64-prefix", prefix] => {
                let prefix = Prefix::parse(prefix)?;
                if !prefix.is_ipv6() || prefix.prefix_len() != 96 {
                    return Err("a NAT64 prefix is an IPv6 /96".into());
                }
                self.policy.nat64_prefixes.push(prefix);
            }
            ["budget", host, rest @ ..] => {
                let host = parse_hostname(host).map_err(|e| e.reason().to_owned())?;
                self.budgets.push((host, parse_budget(rest)?));
            }
            ["budget-default", rest @ ..] => self.default_budget = parse_budget(rest)?,
            ["header-timeout", seconds] => {
                self.header_timeout = Duration::from_secs(positive(seconds)?);
            }
            ["caller-connections", count] => {
                self.caller_connections =
                    usize::try_from(positive(count)?).map_err(|e| e.to_string())?;
            }
            ["tunnel-idle", seconds] => self.tunnel_idle = Duration::from_secs(positive(seconds)?),
            ["tunnel-lifetime", seconds] => {
                self.tunnel_lifetime = Duration::from_secs(positive(seconds)?);
            }
            ["dial-deadline", seconds] => {
                self.dial_deadline = Duration::from_secs(positive(seconds)?);
            }
            ["documentation-ranges-public"] => {
                if !cfg!(feature = "test-network") {
                    return Err(
                        "documentation-ranges-public needs a build with the test-network feature"
                            .into(),
                    );
                }
                self.policy.documentation_ranges_public = true;
            }
            _ => return Err("unknown directive".into()),
        }
        Ok(())
    }

    fn caller_mut(&mut self, name: &str) -> Result<&mut Caller, String> {
        self.callers
            .iter_mut()
            .find(|c| c.name == name)
            .ok_or_else(|| format!("unknown caller {name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_configuration_parses() {
        let config = Config::parse(
            "# comment\n\
             caller core kind=core uid=2000\n\
             caller plugin-a kind=plugin uid=2001 # trailing comment\n\
             allow plugin-a allowed.test:443\n\
             allow plugin-a ALLOWED6.test:443\n\
             private core push.lan:8443 10.77.0.10/32\n\
             sni-check plugin-a\n\
             blocked 203.0.113.2/32\n\
             nat64-prefix 2a00:64::/96\n\
             budget Budget.test tunnels=5 window=60 reserve=1\n\
             budget-default tunnels=100 window=60 reserve=10\n\
             header-timeout 3\n\
             caller-connections 8\n\
             tunnel-idle 30\n\
             tunnel-lifetime 600\n\
             dial-deadline 4\n",
        )
        .unwrap();
        assert_eq!(config.callers.len(), 2);
        assert_eq!(config.callers[1].allow[1].host, "allowed6.test");
        assert!(config.callers[1].sni_check);
        assert!(!config.callers[0].sni_check);
        assert_eq!(config.callers[0].private[0].0.to_string(), "push.lan:8443");
        assert_eq!(config.budgets[0].0, "budget.test");
        assert_eq!(config.budgets[0].1.reserve, 1);
        assert_eq!(config.default_budget.tunnels, 100);
        assert_eq!(config.policy.nat64_prefixes.len(), 1);
        assert_eq!(config.header_timeout, Duration::from_secs(3));
        assert_eq!(config.caller_connections, 8);
        assert_eq!(config.tunnel_idle, Duration::from_secs(30));
        assert_eq!(config.tunnel_lifetime, Duration::from_secs(600));
        assert_eq!(config.dial_deadline, Duration::from_secs(4));
    }

    #[test]
    fn documentation_ranges_need_the_test_network_feature() {
        let result = Config::parse("documentation-ranges-public\n");
        if cfg!(feature = "test-network") {
            assert!(result.unwrap().policy.documentation_ranges_public);
        } else {
            assert!(result.unwrap_err().contains("test-network feature"));
        }
    }

    #[test]
    fn invalid_configurations_are_refused() {
        let base = "caller core kind=core uid=2000\ncaller p kind=plugin uid=2001\ncaller b kind=backup uid=2003\n";
        let refused = [
            ("private p push.lan:8443 10.77.0.10/32", "D105"),
            ("private core push.lan:8443 127.0.0.1/32", "RFC 1918"),
            ("private core push.lan:8443 169.254.0.0/16", "RFC 1918"),
            ("private core push.lan:8443 0.0.0.0/0", "RFC 1918"),
            ("private core push.lan:8443 10.0.0.0/7", "RFC 1918"),
            ("private core push.lan:8443 fc00::/6", "RFC 1918"),
            ("private core push.lan:8443 fe80::/10", "RFC 1918"),
            ("allow p 203.0.113.10:443", "IP literal"),
            ("allow p allowed.test", "port"),
            ("allow nobody allowed.test:443", "unknown caller"),
            ("caller x kind=root uid=1", "kind"),
            ("caller p kind=plugin uid=9", "reuses"),
            ("caller y kind=plugin uid=2001", "reuses"),
            ("caller Bad kind=plugin uid=9", "lowercase"),
            ("budget x.test tunnels=1 window=0 reserve=0", "window"),
            ("budget x.test tunnels=2 window=60 reserve=2", "reserve"),
            (
                "budget x.test:443 tunnels=2 window=60 reserve=0",
                "hostname",
            ),
            (
                "budget 203.0.113.10 tunnels=2 window=60 reserve=0",
                "hostname",
            ),
            ("budget-default tunnels=2 window=60", "expected tunnels"),
            ("nat64-prefix 2a00:64::/64", "/96"),
            ("nat64-prefix 10.0.0.0/8", "/96"),
            ("caller-connections 0", "positive"),
            ("sni-check nobody", "unknown caller"),
            ("frobnicate", "unknown directive"),
        ];
        for (line, expected) in refused {
            let error = Config::parse(&format!("{base}{line}\n")).unwrap_err();
            assert!(error.contains(expected), "{line}: {error}");
        }
        let accepted =
            Config::parse(&format!("{base}private b push.lan:8443 fd00:77::/64\n")).unwrap();
        assert_eq!(accepted.callers[2].private.len(), 1);
    }
}
