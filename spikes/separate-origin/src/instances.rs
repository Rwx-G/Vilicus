//! The test network's layout, read from one file (`network/instances.txt`) by the PKI, the DNS
//! server, the Gateway and the browser harness, so the instance names exist in one place.
//!
//! Lines (`#` starts a comment):
//! - `ca <label> <description>`: a test certificate authority;
//! - `deployment <name> <ipv4>`: where an instance name resolves: `direct` is the Gateway itself,
//!   any other is a reverse proxy in front of the Gateway's plain listeners;
//! - `server <role> <ipv4>`: another server of the test network (`dns`, `sink`);
//! - `instance <option> <deployment> <name> <ca label>`: one instance name of one naming option,
//!   reached through one deployment, with a certificate from that CA;
//! - `wildcard <suffix> <ca label>`: every name under the suffix resolves to the sink.

use std::net::Ipv4Addr;

/// One instance name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    pub option: String,
    pub deployment: String,
    pub name: String,
    pub ca: String,
}

/// The parsed layout.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layout {
    pub cas: Vec<(String, String)>,
    pub deployments: Vec<(String, Ipv4Addr)>,
    pub servers: Vec<(String, Ipv4Addr)>,
    pub instances: Vec<Instance>,
    pub wildcards: Vec<(String, String)>,
}

/// The deployment where the Gateway terminates TLS itself.
pub const DIRECT: &str = "direct";

impl Layout {
    /// Parses the file's text.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut layout = Self::default();
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let words: Vec<&str> = line.split_whitespace().collect();
            let bad = || format!("bad layout line: {line}");
            let ip = |s: &str| s.parse::<Ipv4Addr>().map_err(|_| bad());
            match words.as_slice() {
                ["ca", label, description @ ..] if !description.is_empty() => {
                    layout.cas.push(((*label).into(), description.join(" ")));
                }
                ["deployment", name, address] => {
                    layout.deployments.push(((*name).into(), ip(address)?));
                }
                ["server", role, address] => layout.servers.push(((*role).into(), ip(address)?)),
                ["instance", option, deployment, name, ca] => layout.instances.push(Instance {
                    option: (*option).into(),
                    deployment: (*deployment).into(),
                    name: (*name).into(),
                    ca: (*ca).into(),
                }),
                ["wildcard", suffix, ca] => layout.wildcards.push(((*suffix).into(), (*ca).into())),
                _ => return Err(bad()),
            }
        }
        layout.check()?;
        Ok(layout)
    }

    fn check(&self) -> Result<(), String> {
        let has_ca = |label: &str| self.cas.iter().any(|(l, _)| l == label);
        for instance in &self.instances {
            if !has_ca(&instance.ca) {
                return Err(format!("{}: unknown CA {}", instance.name, instance.ca));
            }
            if self.deployment_address(&instance.deployment).is_none() {
                return Err(format!(
                    "{}: unknown deployment {}",
                    instance.name, instance.deployment
                ));
            }
        }
        for (suffix, ca) in &self.wildcards {
            if !has_ca(ca) {
                return Err(format!("{suffix}: unknown CA {ca}"));
            }
        }
        if self.wildcards.is_empty() != self.server_address("sink").is_some() {
            return Ok(());
        }
        Err("wildcard names need a sink server, and a sink needs a wildcard".into())
    }

    /// Where a deployment's names resolve.
    pub fn deployment_address(&self, name: &str) -> Option<Ipv4Addr> {
        self.deployments
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, a)| *a)
    }

    /// A server's address.
    pub fn server_address(&self, role: &str) -> Option<Ipv4Addr> {
        self.servers
            .iter()
            .find(|(r, _)| r == role)
            .map(|(_, a)| *a)
    }

    /// Instance names served by the Gateway over TLS itself.
    pub fn direct_names(&self) -> Vec<String> {
        self.names_where(|i| i.deployment == DIRECT)
    }

    /// Instance names served through a reverse proxy.
    pub fn proxied_names(&self) -> Vec<String> {
        self.names_where(|i| i.deployment != DIRECT)
    }

    fn names_where(&self, keep: impl Fn(&Instance) -> bool) -> Vec<String> {
        self.instances
            .iter()
            .filter(|i| keep(i))
            .map(|i| i.name.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "
        ca household Household local CA
        deployment direct 10.0.0.10
        deployment caddy 10.0.0.20
        server sink 10.0.0.30
        instance localca direct vilicus-direct.internal household
        instance localca caddy vilicus-caddy.internal household
        wildcard attacker.example household
    ";

    #[test]
    fn sample_parses_and_splits_direct_from_proxied() {
        let layout = Layout::parse(SAMPLE).unwrap_or_default();
        assert_eq!(layout.direct_names(), ["vilicus-direct.internal"]);
        assert_eq!(layout.proxied_names(), ["vilicus-caddy.internal"]);
        assert_eq!(
            layout.deployment_address("caddy"),
            Some(Ipv4Addr::new(10, 0, 0, 20))
        );
        assert_eq!(layout.cas[0].1, "Household local CA");
    }

    #[test]
    fn unknown_references_are_refused() {
        assert!(
            Layout::parse(&SAMPLE.replace(
                "caddy vilicus-caddy.internal household",
                "caddy vilicus-caddy.internal nope"
            ))
            .is_err()
        );
        assert!(Layout::parse(&SAMPLE.replace("deployment caddy 10.0.0.20", "")).is_err());
        assert!(Layout::parse(&SAMPLE.replace("server sink 10.0.0.30", "")).is_err());
        assert!(Layout::parse("instance a b").is_err());
    }

    #[test]
    fn the_committed_layout_parses() {
        let text = include_str!("../network/instances.txt");
        let layout = Layout::parse(text);
        assert!(layout.is_ok(), "{layout:?}");
        let layout = layout.unwrap_or_default();
        assert!(!layout.direct_names().is_empty());
        assert!(!layout.proxied_names().is_empty());
        assert!(layout.server_address("dns").is_some());
    }
}
