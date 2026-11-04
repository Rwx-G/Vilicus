//! The Argon2id values of D128 and E12: the cost of a version 1 passphrase wrapper, the floor and
//! the ceiling every wrapper header is held to before its derivation is queued, the limiter every
//! Argon2id derivation of the Core goes through, and the delays of a failed passphrase.
//!
//! Every memory size is in KiB, the unit of RFC 9106 and of the wrapper header (D153), so that no
//! conversion stands between these constants and the derivation.

use std::time::Duration;

/// KiB in one MiB.
const MIB: u32 = 1024;

/// The Argon2 version of every Argon2id derivation of the Core: 0x13 (RFC 9106). A header that
/// names another is refused, never read as it.
pub const ARGON2ID_VERSION: u32 = 0x13;

/// m of a version 1 passphrase wrapper: 384 MiB, in KiB. Provisional: the reference-host run of E12
/// picks m from {256, 384, 512} MiB and replaces this value; a VM or emulation run never does
/// (D128, gate E12-5).
pub const PASSPHRASE_ARGON2ID_MEMORY_KIB: u32 = 384 * MIB;

/// t of a version 1 passphrase wrapper (D128).
pub const PASSPHRASE_ARGON2ID_PASSES: u32 = 3;

/// p of a version 1 passphrase wrapper: one lane per reference-host core, as both RFC 9106
/// options have it (D128). The lanes run in order on one thread (D129, no `parallel` feature).
pub const PASSPHRASE_ARGON2ID_LANES: u32 = 4;

/// Bytes of the random salt of each passphrase wrapper, from the operating system's generator
/// (D128).
pub const PASSPHRASE_SALT_LEN: usize = 16;

/// Bytes of a passphrase KEK: the AES-256-GCM key of the wrap (D128, spine AD-18).
pub const PASSPHRASE_KEK_LEN: usize = 32;

/// The longest passphrase the Core derives from, in bytes of UTF-8 as received: a longer one is
/// refused before the limiter (`doc/qa/argon2-review.md`, U6). Its NFC form is at most three
/// times as long (UAX #15, section 13), which the derivation's buffer holds.
pub const PASSPHRASE_MAX_LEN: usize = 1024;

/// The two recommended options of RFC 9106 section 4, as (m in KiB, t): 2 GiB with one pass, and
/// 64 MiB with three. A cost meets the floor when it is at least one of them in both memory and
/// passes, a project rule (D128); lanes are not part of it.
pub const ARGON2ID_FLOOR_OPTIONS: [(u32, u32); 2] = [(2048 * MIB, 1), (64 * MIB, 3)];

/// The largest m a header may ask for, in KiB: 1 GiB, the whole memory budget (D128).
pub const ARGON2ID_MAX_MEMORY_KIB: u32 = 1024 * MIB;

/// The largest m times t a header may ask for, in KiB: 4 GiB (D128).
pub const ARGON2ID_MAX_WORK_KIB: u64 = 4096 * MIB as u64;

/// The most lanes a header may ask for (D128).
pub const ARGON2ID_MAX_LANES: u32 = 8;

/// The most Argon2id derivations the Core runs at once, passphrase, backup secret and admin
/// recovery code together (D128).
pub const ARGON2ID_CONCURRENCY_LIMIT: usize = 2;

/// The most Argon2id working memory the Core holds at once, in KiB, across the derivations the
/// limiter admits: 1 GiB (D128). Each derivation's buffer is locked (Story 4.4), so the Core's
/// `LimitMEMLOCK` covers this budget beside the key pool.
pub const ARGON2ID_MEMORY_BUDGET_KIB: u64 = 1024 * MIB as u64;

/// How long a derivation request may wait for the limiter before it is refused as retryable: two
/// unlock targets (D128, story 1.8). The time it waited is never returned to the client.
pub const ARGON2ID_QUEUE_WAIT: Duration = Duration::from_secs(4);

/// The delay before a member's next passphrase attempt after the first failed one; each further
/// failure doubles it, up to [`PASSPHRASE_BACKOFF_MAX`], and a successful unlock resets it (D128,
/// `[ASSUMPTION]`).
pub const PASSPHRASE_BACKOFF_BASE: Duration = Duration::from_secs(1);

/// The longest delay between a member's passphrase attempts (D128, `[ASSUMPTION]`).
pub const PASSPHRASE_BACKOFF_MAX: Duration = Duration::from_secs(5 * 60);

/// Whether a cost of m KiB and t passes meets the floor: at least one option of
/// [`ARGON2ID_FLOOR_OPTIONS`] in both memory and passes.
pub const fn argon2id_meets_floor(memory_kib: u32, passes: u32) -> bool {
    let mut index = 0;
    while index < ARGON2ID_FLOOR_OPTIONS.len() {
        let (floor_memory, floor_passes) = ARGON2ID_FLOOR_OPTIONS[index];
        if memory_kib >= floor_memory && passes >= floor_passes {
            return true;
        }
        index += 1;
    }
    false
}

/// Whether a cost of m KiB, t passes and p lanes is within the ceiling: m at most
/// [`ARGON2ID_MAX_MEMORY_KIB`], m times t at most [`ARGON2ID_MAX_WORK_KIB`], p at most
/// [`ARGON2ID_MAX_LANES`].
pub const fn argon2id_within_ceiling(memory_kib: u32, passes: u32, lanes: u32) -> bool {
    memory_kib <= ARGON2ID_MAX_MEMORY_KIB
        && (memory_kib as u64) * (passes as u64) <= ARGON2ID_MAX_WORK_KIB
        && lanes <= ARGON2ID_MAX_LANES
}

// D128: the working memory of the derivations the limiter admits never exceeds the budget, at
// most 1 GiB, held over the constants and the ceiling. The budget bounds the sum of what runs at
// once: a header at the ceiling runs alone, and the current cost runs at the concurrency limit.
const _: () = assert!(ARGON2ID_MEMORY_BUDGET_KIB <= 1024 * MIB as u64);
const _: () = assert!(ARGON2ID_MAX_MEMORY_KIB as u64 <= ARGON2ID_MEMORY_BUDGET_KIB);
const _: () = assert!(
    ARGON2ID_CONCURRENCY_LIMIT as u64 * PASSPHRASE_ARGON2ID_MEMORY_KIB as u64
        <= ARGON2ID_MEMORY_BUDGET_KIB
);
const _: () = assert!(ARGON2ID_CONCURRENCY_LIMIT > 0);
// The version 1 cost is one the Core accepts from a header.
const _: () = assert!(argon2id_meets_floor(
    PASSPHRASE_ARGON2ID_MEMORY_KIB,
    PASSPHRASE_ARGON2ID_PASSES
));
const _: () = assert!(argon2id_within_ceiling(
    PASSPHRASE_ARGON2ID_MEMORY_KIB,
    PASSPHRASE_ARGON2ID_PASSES,
    PASSPHRASE_ARGON2ID_LANES
));
const _: () = assert!(PASSPHRASE_BACKOFF_BASE.as_nanos() <= PASSPHRASE_BACKOFF_MAX.as_nanos());

#[cfg(test)]
mod tests {
    use super::*;

    /// Each RFC 9106 option meets the floor and one pass less, or one KiB less, does not; the
    /// OWASP sets of story 1.8, sized for login hashing, meet none.
    #[test]
    fn the_floor_is_an_rfc_option_in_both_memory_and_passes() {
        for (memory, passes) in ARGON2ID_FLOOR_OPTIONS {
            assert!(argon2id_meets_floor(memory, passes), "{memory} {passes}");
            assert!(
                !argon2id_meets_floor(memory - 1, passes),
                "{memory} less one"
            );
            assert!(
                !argon2id_meets_floor(memory, passes - 1),
                "{passes} less one"
            );
        }
        let smallest = ARGON2ID_FLOOR_OPTIONS
            .iter()
            .map(|&(memory, _)| memory)
            .min()
            .expect("an option");
        assert!(!argon2id_meets_floor(smallest - 1, u32::MAX));
        // Above the smaller option in memory, below it in passes: 1 GiB at t = 2.
        assert!(!argon2id_meets_floor(1024 * MIB, 2));
        for (memory, passes) in [(19 * MIB, 2), (46 * MIB, 1), (12 * MIB, 3), (9 * MIB, 4)] {
            assert!(
                !argon2id_meets_floor(memory, passes),
                "OWASP {memory} {passes}"
            );
        }
    }

    /// One KiB more, one pass of work more, or one lane more than the ceiling is refused.
    #[test]
    fn the_ceiling_bounds_memory_work_and_lanes() {
        assert!(argon2id_within_ceiling(
            ARGON2ID_MAX_MEMORY_KIB,
            4,
            ARGON2ID_MAX_LANES
        ));
        assert!(!argon2id_within_ceiling(ARGON2ID_MAX_MEMORY_KIB + 1, 1, 1));
        assert!(!argon2id_within_ceiling(ARGON2ID_MAX_MEMORY_KIB, 5, 1));
        assert!(!argon2id_within_ceiling(64 * MIB, u32::MAX, 1));
        assert!(!argon2id_within_ceiling(
            64 * MIB,
            3,
            ARGON2ID_MAX_LANES + 1
        ));
    }
}
