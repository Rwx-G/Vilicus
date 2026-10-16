//! Which resolved addresses the proxy may dial (spine AD-16).
//!
//! The check runs on every address the proxy's own lookup returned, after resolution and before
//! the dial, and the proxy dials only the address this module returns. IPv4 is refused by table;
//! IPv6 is accepted only inside global unicast (`2000::/3`), and the forms that embed an IPv4
//! address (IPv4-mapped, NAT64, 6to4) are judged on the embedded address as well.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An address prefix, such as `10.0.0.0/8` or `fd00::/8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    addr: IpAddr,
    len: u8,
}

impl Prefix {
    /// An IPv4 prefix. Bits past `len` are ignored by [`Prefix::contains`].
    #[must_use]
    pub const fn v4(octets: [u8; 4], len: u8) -> Self {
        Self {
            addr: IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])),
            len,
        }
    }

    /// An IPv6 prefix. Bits past `len` are ignored by [`Prefix::contains`].
    #[must_use]
    pub const fn v6(segments: [u16; 8], len: u8) -> Self {
        let [a, b, c, d, e, f, g, h] = segments;
        Self {
            addr: IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)),
            len,
        }
    }

    /// Parses `address/length`; a bare address is a host prefix.
    ///
    /// ```
    /// use egress_filter::address::Prefix;
    /// let lan = Prefix::parse("10.77.0.0/24").unwrap();
    /// assert!(lan.contains("10.77.0.10".parse().unwrap()));
    /// assert!(!lan.contains("10.78.0.10".parse().unwrap()));
    /// ```
    ///
    /// # Errors
    /// Returns a message when the address or the length is malformed or out of range.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (addr_text, len_text) = match text.split_once('/') {
            Some((addr, len)) => (addr, Some(len)),
            None => (text, None),
        };
        let addr: IpAddr = addr_text
            .parse()
            .map_err(|_| format!("malformed prefix address: {text}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = match len_text {
            Some(len) => len
                .parse::<u8>()
                .ok()
                .filter(|len| *len <= max)
                .ok_or_else(|| format!("malformed prefix length: {text}"))?,
            None => max,
        };
        Ok(Self { addr, len })
    }

    /// Whether `ip` falls inside the prefix. An address of the other family never does.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.len))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }

    /// The prefix length in bits.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    /// Whether this is an IPv6 prefix.
    #[must_use]
    pub fn is_ipv6(&self) -> bool {
        self.addr.is_ipv6()
    }

    /// Whether every address of `other` falls inside this prefix.
    #[must_use]
    pub fn covers(&self, other: &Prefix) -> bool {
        self.len <= other.len && self.contains(other.addr)
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// The deployment-specific part of the address policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddressPolicy {
    /// Refused on top of the fixed tables: the host's own addresses, the household's public
    /// addresses and the WireGuard subnet (AD-16).
    pub blocked: Vec<Prefix>,
    /// Treats the documentation ranges as public. Test networks only: Docker offers no globally
    /// routable addresses, so the spike's simulated internet lives in `203.0.113.0/24`. Nothing
    /// else can be unblocked, and the configuration accepts the switch only in a build with the
    /// `test-network` feature.
    pub documentation_ranges_public: bool,
    /// Network-specific NAT64 prefixes (RFC 6052, `/96` only), judged like `64:ff9b::/96`: on the
    /// IPv4 address in their low 32 bits.
    pub nat64_prefixes: Vec<Prefix>,
}

const REFUSED_V4: &[(Prefix, &str)] = &[
    (Prefix::v4([0, 0, 0, 0], 8), "unspecified or this-network"),
    (Prefix::v4([10, 0, 0, 0], 8), "private (RFC 1918)"),
    (
        Prefix::v4([100, 64, 0, 0], 10),
        "shared address space (CGNAT)",
    ),
    (Prefix::v4([127, 0, 0, 0], 8), "loopback"),
    (Prefix::v4([169, 254, 0, 0], 16), "link-local"),
    (Prefix::v4([172, 16, 0, 0], 12), "private (RFC 1918)"),
    (Prefix::v4([192, 0, 0, 0], 24), "IETF protocol assignments"),
    (Prefix::v4([192, 88, 99, 0], 24), "6to4 relay anycast"),
    (Prefix::v4([192, 168, 0, 0], 16), "private (RFC 1918)"),
    (Prefix::v4([198, 18, 0, 0], 15), "benchmarking"),
    (Prefix::v4([224, 0, 0, 0], 4), "multicast"),
    (Prefix::v4([240, 0, 0, 0], 4), "reserved or broadcast"),
];

const DOCUMENTATION_V4: &[Prefix] = &[
    Prefix::v4([192, 0, 2, 0], 24),
    Prefix::v4([198, 51, 100, 0], 24),
    Prefix::v4([203, 0, 113, 0], 24),
];

const GLOBAL_UNICAST_V6: Prefix = Prefix::v6([0x2000, 0, 0, 0, 0, 0, 0, 0], 3);
const NAT64_WELL_KNOWN: Prefix = Prefix::v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96);
const SIX_TO_FOUR: Prefix = Prefix::v6([0x2002, 0, 0, 0, 0, 0, 0, 0], 16);

/// Outside `2000::/3`, the reason given for a refusal; the first match wins.
const NON_GLOBAL_V6: &[(Prefix, &str)] = &[
    (Prefix::v6([0, 0, 0, 0, 0, 0, 0, 0], 128), "unspecified"),
    (Prefix::v6([0, 0, 0, 0, 0, 0, 0, 1], 128), "loopback"),
    (
        Prefix::v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48),
        "local-use NAT64",
    ),
    (Prefix::v6([0x100, 0, 0, 0, 0, 0, 0, 0], 64), "discard-only"),
    (Prefix::v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7), "unique local"),
    (Prefix::v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10), "link-local"),
    (Prefix::v6([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10), "site-local"),
    (Prefix::v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8), "multicast"),
];

/// Inside `2000::/3`, still refused.
const REFUSED_GLOBAL_V6: &[(Prefix, &str)] = &[(
    Prefix::v6([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
    "IETF protocol assignments (Teredo, benchmarking, ORCHID)",
)];

const DOCUMENTATION_V6: &[Prefix] = &[
    Prefix::v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32),
    Prefix::v6([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
];

/// Why an address was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The address as resolved.
    pub address: IpAddr,
    /// A fixed description of the range that matched.
    pub reason: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is {}", self.address, self.reason)
    }
}

/// Checks one resolved address and returns the address to dial: an IPv4-mapped address is
/// dialled as plain IPv4, everything else as resolved.
///
/// ```
/// use egress_filter::address::{check, AddressPolicy};
/// let policy = AddressPolicy::default();
/// assert!(check("9.9.9.9".parse().unwrap(), &policy).is_ok());
/// assert!(check("::ffff:10.0.0.1".parse().unwrap(), &policy).is_err());
/// ```
///
/// # Errors
/// Returns the refusal when the address, or the IPv4 address it embeds, is internal, special
/// purpose, or blocked by the deployment policy.
pub fn check(address: IpAddr, policy: &AddressPolicy) -> Result<IpAddr, Refusal> {
    let refuse = |reason: String| Refusal { address, reason };
    let (dial, embedded) = match address {
        IpAddr::V4(v4) => (IpAddr::V4(v4), None),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => (IpAddr::V4(v4), None),
            None => (IpAddr::V6(v6), embedded_v4(v6, policy)),
        },
    };
    let own_reason = match dial {
        IpAddr::V4(v4) => v4_reason(v4, policy),
        IpAddr::V6(v6) => v6_reason(v6, policy),
    };
    if let Some(reason) = own_reason {
        return Err(refuse(reason.to_owned()));
    }
    if let Some(v4) = embedded
        && let Some(reason) = v4_reason(v4, policy)
    {
        return Err(refuse(format!("embedding {v4}, which is {reason}")));
    }
    for candidate in [Some(dial), embedded.map(IpAddr::V4)].into_iter().flatten() {
        if let Some(prefix) = policy.blocked.iter().find(|p| p.contains(candidate)) {
            return Err(refuse(format!("blocked by deployment policy ({prefix})")));
        }
    }
    Ok(dial)
}

fn v4_reason(v4: Ipv4Addr, policy: &AddressPolicy) -> Option<&'static str> {
    let ip = IpAddr::V4(v4);
    if let Some((_, reason)) = REFUSED_V4.iter().find(|(p, _)| p.contains(ip)) {
        return Some(reason);
    }
    if !policy.documentation_ranges_public && DOCUMENTATION_V4.iter().any(|p| p.contains(ip)) {
        return Some("documentation");
    }
    None
}

fn v6_reason(v6: Ipv6Addr, policy: &AddressPolicy) -> Option<&'static str> {
    let ip = IpAddr::V6(v6);
    if is_nat64(ip, policy) {
        // Judged on the embedded address by the caller.
        return None;
    }
    if !GLOBAL_UNICAST_V6.contains(ip) {
        return Some(
            NON_GLOBAL_V6
                .iter()
                .find(|(p, _)| p.contains(ip))
                .map_or("not global unicast", |(_, reason)| reason),
        );
    }
    if let Some((_, reason)) = REFUSED_GLOBAL_V6.iter().find(|(p, _)| p.contains(ip)) {
        return Some(reason);
    }
    if !policy.documentation_ranges_public && DOCUMENTATION_V6.iter().any(|p| p.contains(ip)) {
        return Some("documentation");
    }
    None
}

fn is_nat64(ip: IpAddr, policy: &AddressPolicy) -> bool {
    NAT64_WELL_KNOWN.contains(ip) || policy.nat64_prefixes.iter().any(|p| p.contains(ip))
}

/// The IPv4 address carried by a NAT64 (well-known or configured `/96`, low 32 bits) or 6to4
/// (`2002::/16`, bits 16 to 47) address.
fn embedded_v4(v6: Ipv6Addr, policy: &AddressPolicy) -> Option<Ipv4Addr> {
    let ip = IpAddr::V6(v6);
    let bits = u128::from(v6);
    if is_nat64(ip, policy) {
        // Truncation is the point: the low 32 bits are the embedded address.
        #[allow(clippy::cast_possible_truncation)]
        return Some(Ipv4Addr::from(bits as u32));
    }
    if SIX_TO_FOUR.contains(ip) {
        #[allow(clippy::cast_possible_truncation)] // Bits 16 to 47 are the embedded address.
        return Some(Ipv4Addr::from((bits >> 80) as u32));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(text: &str, policy: &AddressPolicy) -> Option<String> {
        check(text.parse().unwrap(), policy).err().map(|r| r.reason)
    }

    /// The first and last address of a prefix.
    fn bounds(prefix: Prefix) -> [IpAddr; 2] {
        match prefix.addr {
            IpAddr::V4(net) => {
                let host_bits = u32::MAX.checked_shr(u32::from(prefix.len)).unwrap_or(0);
                let first = u32::from(net) & !host_bits;
                [first, first | host_bits].map(|a| IpAddr::V4(Ipv4Addr::from(a)))
            }
            IpAddr::V6(net) => {
                let host_bits = u128::MAX.checked_shr(u32::from(prefix.len)).unwrap_or(0);
                let first = u128::from(net) & !host_bits;
                [first, first | host_bits].map(|a| IpAddr::V6(Ipv6Addr::from(a)))
            }
        }
    }

    fn assert_refused_with(address: IpAddr, expected: &str, policy: &AddressPolicy) {
        let reason = check(address, policy).err().map(|r| r.reason);
        assert!(
            reason.as_deref().is_some_and(|r| r.contains(expected)),
            "{address}: expected refusal containing {expected:?}, got {reason:?}"
        );
    }

    #[test]
    fn both_ends_of_every_refused_table_entry_are_refused_with_its_reason() {
        let policy = AddressPolicy::default();
        let tables = REFUSED_V4
            .iter()
            .chain(NON_GLOBAL_V6)
            .chain(REFUSED_GLOBAL_V6);
        for (prefix, reason) in tables {
            for address in bounds(*prefix) {
                assert_refused_with(address, reason, &policy);
            }
        }
        for prefix in DOCUMENTATION_V4.iter().chain(DOCUMENTATION_V6) {
            for address in bounds(*prefix) {
                assert_refused_with(address, "documentation", &policy);
            }
        }
    }

    #[test]
    fn derived_forms_are_judged_on_the_address_they_carry() {
        let policy = AddressPolicy::default();
        for (prefix, reason) in REFUSED_V4 {
            for v4 in bounds(*prefix) {
                let IpAddr::V4(v4) = v4 else { unreachable!() };
                let octets = v4.octets();
                let mapped = IpAddr::V6(v4.to_ipv6_mapped());
                let nat64 = IpAddr::V6(Ipv6Addr::from(
                    u128::from(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0))
                        | u128::from(u32::from(v4)),
                ));
                let six_to_four = IpAddr::V6(Ipv6Addr::new(
                    0x2002,
                    u16::from_be_bytes([octets[0], octets[1]]),
                    u16::from_be_bytes([octets[2], octets[3]]),
                    0,
                    0,
                    0,
                    0,
                    1,
                ));
                assert_refused_with(mapped, reason, &policy);
                assert_refused_with(
                    nat64,
                    &format!("embedding {v4}, which is {reason}"),
                    &policy,
                );
                assert_refused_with(
                    six_to_four,
                    &format!("embedding {v4}, which is {reason}"),
                    &policy,
                );
            }
        }
        assert_refused_with(
            "::10.77.0.10".parse().unwrap(),
            "not global unicast",
            &policy,
        );
        assert_refused_with("4000::1".parse().unwrap(), "not global unicast", &policy);
    }

    #[test]
    fn configured_nat64_prefix_is_judged_like_the_well_known_one() {
        let policy = AddressPolicy {
            nat64_prefixes: vec![Prefix::parse("2a00:64::/96").unwrap()],
            ..AddressPolicy::default()
        };
        assert_refused_with(
            "2a00:64::a4d:a".parse().unwrap(),
            "embedding 10.77.0.10",
            &policy,
        );
        assert_refused_with(
            "2a00:64::7f00:1".parse().unwrap(),
            "embedding 127.0.0.1",
            &policy,
        );
        assert_eq!(
            check("2a00:64::909:909".parse().unwrap(), &policy),
            Ok("2a00:64::909:909".parse().unwrap())
        );
        let unconfigured = AddressPolicy::default();
        assert!(check("2a00:64::a4d:a".parse().unwrap(), &unconfigured).is_ok());
    }

    #[test]
    fn public_addresses_are_dialled_as_resolved_or_unmapped() {
        let policy = AddressPolicy::default();
        let cases = [
            ("9.9.9.9", "9.9.9.9"),
            ("1.1.1.1", "1.1.1.1"),
            ("172.32.0.1", "172.32.0.1"),
            ("100.128.0.1", "100.128.0.1"),
            ("::ffff:9.9.9.9", "9.9.9.9"),
            ("2a00:1450:4007:80e::200e", "2a00:1450:4007:80e::200e"),
            ("64:ff9b::909:909", "64:ff9b::909:909"),
            ("2002:909:909::1", "2002:909:909::1"),
        ];
        for (address, dial) in cases {
            let result = check(address.parse().unwrap(), &policy);
            assert_eq!(result, Ok(dial.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn documentation_override_unblocks_documentation_ranges_only() {
        let policy = AddressPolicy {
            documentation_ranges_public: true,
            ..AddressPolicy::default()
        };
        assert!(refused("203.0.113.10", &policy).is_none());
        assert!(refused("2001:db8:113::10", &policy).is_none());
        for internal in ["10.0.0.1", "127.0.0.1", "fd00::1", "::ffff:10.0.0.1", "::1"] {
            assert!(refused(internal, &policy).is_some(), "{internal}");
        }
    }

    #[test]
    fn deployment_blocks_apply_to_dialled_and_embedded_addresses() {
        let policy = AddressPolicy {
            blocked: vec![
                Prefix::parse("9.9.9.0/24").unwrap(),
                Prefix::parse("2a00:1::/32").unwrap(),
            ],
            ..AddressPolicy::default()
        };
        for address in [
            "9.9.9.9",
            "::ffff:9.9.9.9",
            "64:ff9b::909:909",
            "2002:909:909::1",
            "2a00:1::5",
        ] {
            let reason = refused(address, &policy);
            assert!(
                reason.is_some_and(|r| r.contains("deployment policy")),
                "{address}"
            );
        }
        assert!(refused("8.8.8.8", &policy).is_none());
    }

    #[test]
    fn prefix_parsing_and_bounds() {
        assert!(Prefix::parse("10.0.0.0/33").is_err());
        assert!(Prefix::parse("fd00::/129").is_err());
        assert!(Prefix::parse("10.0.0/8").is_err());
        assert!(Prefix::parse("10.0.0.0/").is_err());
        let all = Prefix::parse("0.0.0.0/0").unwrap();
        assert!(all.contains("255.1.2.3".parse().unwrap()));
        assert!(!all.contains("::1".parse().unwrap()));
        let host = Prefix::parse("10.77.0.10").unwrap();
        assert!(host.contains("10.77.0.10".parse().unwrap()));
        assert!(!host.contains("10.77.0.11".parse().unwrap()));
        assert_eq!(
            Prefix::parse("fd00:77::/64").unwrap().to_string(),
            "fd00:77::/64"
        );
    }
}
