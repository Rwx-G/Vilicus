//! Published Argon2id guidance the parameter floor comes from, and the project's ceiling.
//!
//! - RFC 9106 section 4 gives two recommended options: m = 2 GiB, t = 1, p = 4 when that much
//!   memory is affordable, and m = 64 MiB, t = 3, p = 4 when it is not.
//! - The OWASP Password Storage Cheat Sheet gives a minimum of m = 19 MiB, t = 2, p = 1, and
//!   equivalent trade-offs, all with p = 1.
//!
//! OWASP targets login hashing at server scale, where many hashes run per second. A passphrase
//! KEK protects a wrapper an attacker can copy and attack offline for as long as they like, so
//! the floor is taken from RFC 9106 only.
//!
//! Project choice, not RFC text: a cost meets the floor when it is at least one RFC 9106 option in
//! both memory and passes. Lanes are not part of the floor.

use crate::{Cost, MIB};

/// A published parameter set, kept as data so the run prints what the floor came from.
pub struct PublishedSet {
    pub source: &'static str,
    pub cost: Cost,
    /// Whether this set defines the floor.
    pub floor: bool,
}

pub const PUBLISHED: [PublishedSet; 7] = [
    PublishedSet {
        source: "RFC 9106 s4 option 1",
        cost: Cost::new(2048, 1, 4),
        floor: true,
    },
    PublishedSet {
        source: "RFC 9106 s4 option 2",
        cost: Cost::new(64, 3, 4),
        floor: true,
    },
    PublishedSet {
        source: "OWASP minimum",
        cost: Cost::new(19, 2, 1),
        floor: false,
    },
    PublishedSet {
        source: "OWASP equivalent",
        cost: Cost::new(46, 1, 1),
        floor: false,
    },
    PublishedSet {
        source: "OWASP equivalent",
        cost: Cost::new(12, 3, 1),
        floor: false,
    },
    PublishedSet {
        source: "OWASP equivalent",
        cost: Cost::new(9, 4, 1),
        floor: false,
    },
    PublishedSet {
        source: "OWASP equivalent",
        cost: Cost::new(7, 5, 1),
        floor: false,
    },
];

/// Why a cost falls below the floor, or `None` when it meets it.
pub fn floor_violation(cost: Cost) -> Option<String> {
    let met = PUBLISHED
        .iter()
        .filter(|set| set.floor)
        .any(|set| cost.m_kib >= set.cost.m_kib && cost.t >= set.cost.t);
    (!met).then(|| format!("{cost}: below every RFC 9106 option in memory or passes"))
}

/// Largest memory a wrapper header may ask for: the whole Argon2id memory budget (1 GiB).
pub const CEILING_M_KIB: u32 = 1024 * MIB;
/// Largest memory passes (m times t) a header may ask for, so a header cannot buy a
/// many-second derivation on the reference host.
pub const CEILING_WORK_MIB: u64 = 4096;
/// Largest lane count a header may ask for.
pub const CEILING_P: u32 = 8;

/// Why a cost read from a wrapper header exceeds the ceiling, or `None` when it does not.
/// A header is attacker-writable on disk; the Core refuses it before taking the limiter.
pub fn ceiling_violation(cost: Cost) -> Option<String> {
    if cost.m_kib > CEILING_M_KIB {
        return Some(format!(
            "{cost}: memory above the {} MiB ceiling",
            CEILING_M_KIB / MIB
        ));
    }
    if cost.work_mib() > CEILING_WORK_MIB {
        return Some(format!(
            "{cost}: m*t above the {CEILING_WORK_MIB} MiB ceiling"
        ));
    }
    if cost.p > CEILING_P {
        return Some(format!("{cost}: more than {CEILING_P} lanes"));
    }
    None
}

/// The check the Core runs on a header before it queues a derivation.
pub fn header_violation(cost: Cost) -> Option<String> {
    floor_violation(cost).or_else(|| ceiling_violation(cost))
}
