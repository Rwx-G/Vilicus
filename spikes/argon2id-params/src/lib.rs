//! Spike E12 (story 1.8): Argon2id parameters for passphrase unlock on the reference host.
//!
//! The library holds the pieces the benchmark and the tests share: the published parameter
//! floor, one KEK derivation as the Core would run it, the global concurrency limit, and the
//! statistics. `main.rs` runs the measurements and prints the PASS/FAIL lines.

pub mod derive;
pub mod guidance;
pub mod limiter;
pub mod stats;

/// One mebibyte expressed in the KiB unit Argon2 counts memory in.
pub const MIB: u32 = 1024;

/// Argon2id cost parameters as they would be stored in a wrapper header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cost {
    /// Memory in KiB (Argon2 `m`).
    pub m_kib: u32,
    /// Passes over memory (Argon2 `t`).
    pub t: u32,
    /// Lanes (Argon2 `p`). Part of the hash definition: changing it changes the KEK.
    pub p: u32,
}

impl Cost {
    pub const fn new(m_mib: u32, t: u32, p: u32) -> Self {
        Self {
            m_kib: m_mib * MIB,
            t,
            p,
        }
    }

    pub const fn m_mib(&self) -> u32 {
        self.m_kib / MIB
    }

    /// Memory passes in MiB, the work measure published guidance trades memory against.
    pub const fn work_mib(&self) -> u64 {
        self.m_mib() as u64 * self.t as u64
    }
}

impl std::fmt::Display for Cost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "m={} MiB t={} p={}", self.m_mib(), self.t, self.p)
    }
}

/// The parameters this spike recommends as the V0.1 named constants (story 1.8 Result).
pub mod recommended {
    use super::Cost;

    /// Argon2id cost of the passphrase KEK written into a new wrapper header: the set the
    /// selection rule in `main.rs` (`candidates`) picks; the `selection_matches_constant` check
    /// fails when it picks another.
    pub const COST: Cost = Cost::new(384, 3, 4);
    /// Worker threads of the dedicated Argon2id pool, so one derivation never takes every core
    /// of the 4-core reference host away from the home rule engine and the writer threads.
    pub const POOL_THREADS: usize = 2;
    /// Global concurrency limit on passphrase derivations (FR-11): one at a time.
    pub const CONCURRENT_DERIVATIONS: usize = 1;
    /// Longest a request waits for its turn before it is refused as retryable.
    pub const MAX_QUEUE_WAIT_MS: u64 = 4_000;
}

/// FR-11 target: an unlock derivation completes under this, on the reference host.
pub const UNLOCK_TARGET_MS: f64 = 2_000.0;

/// Argon2id memory across the derivations the limiter admits never exceeds this many MiB: an
/// eighth of the reference host's RAM, leaving the rest to the Core, SQLCipher page caches and
/// the OS. It holds only if every Argon2id call of the Core goes through the one limiter.
pub const MEMORY_BUDGET_MIB: u32 = 1024;

const _: () = assert!(
    recommended::CONCURRENT_DERIVATIONS as u32 * recommended::COST.m_mib() <= MEMORY_BUDGET_MIB,
    "the recommended cost and limit exceed the Argon2id memory budget"
);
const _: () = assert!(
    recommended::CONCURRENT_DERIVATIONS as u32 * (guidance::CEILING_M_KIB / MIB)
        <= MEMORY_BUDGET_MIB,
    "a header at the memory ceiling would exceed the budget under the limit"
);

#[derive(Debug)]
pub enum UnlockError {
    /// The wrapper header asks for a cost outside [floor, ceiling]; refused before queuing.
    Header(String),
    /// The request could not start within the queue wait bound; retryable.
    Refused(limiter::Refused),
    Derive(String),
}

/// One passphrase unlock as the Core runs it: check the header's cost, take a slot of the global
/// limit, derive on the dedicated pool.
pub fn unlock(
    limiter: &limiter::Limiter,
    pool: &derive::Pool,
    cost: Cost,
    passphrase: &[u8],
    salt: &[u8],
) -> Result<zeroize::Zeroizing<[u8; derive::KEK_LEN]>, UnlockError> {
    if let Some(violation) = guidance::header_violation(cost) {
        return Err(UnlockError::Header(violation));
    }
    let _permit = limiter.acquire().map_err(UnlockError::Refused)?;
    pool.derive(cost, passphrase, salt)
        .map_err(UnlockError::Derive)
}

/// Peak resident memory of this process in KiB (`VmHWM`), Linux only.
pub fn peak_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
}
