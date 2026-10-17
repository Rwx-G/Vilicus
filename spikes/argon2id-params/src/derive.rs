//! One passphrase KEK derivation, as the Core would run it on its dedicated Argon2id pool.

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use rayon::{ThreadPool, ThreadPoolBuilder};
use zeroize::{Zeroize, Zeroizing};

use crate::Cost;

/// Length of the derived KEK: a 256-bit AES-256-GCM key (AD-18).
pub const KEK_LEN: usize = 32;

/// A dedicated pool for Argon2id lanes. `argon2`'s `parallel` feature computes lanes with rayon;
/// running the derivation inside this pool caps the cores it can take, whatever `p` is.
pub struct Pool {
    pool: ThreadPool,
    threads: usize,
}

impl Pool {
    pub fn new(threads: usize) -> Result<Self, String> {
        let pool = ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("argon2id-{i}"))
            .build()
            .map_err(|e| format!("building a {threads}-thread pool: {e}"))?;
        Ok(Self { pool, threads })
    }

    pub fn threads(&self) -> usize {
        self.threads
    }

    /// The thread count rayon reports from inside this pool, the one `parallel` lane work sees.
    pub fn threads_inside(&self) -> usize {
        self.pool.install(rayon::current_num_threads)
    }

    /// Derives the KEK from `passphrase` and a per-wrapper `salt` (key-management.md,
    /// "Passphrase wrapping details"), in a block buffer this function owns and wipes.
    ///
    /// The crate's own `hash_password_into` frees its blocks without wiping them, even with the
    /// `zeroize` feature (argon2 0.6.0 `block.rs`, `Drop for Blocks`), so the buffer is ours.
    pub fn derive(
        &self,
        cost: Cost,
        passphrase: &[u8],
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; KEK_LEN]>, String> {
        let mut memory = vec![Block::new(); cost.m_kib as usize];
        self.derive_with_memory(cost, passphrase, salt, &mut memory)
    }

    /// Derives into the caller's `memory` (at least `m` blocks of 1 KiB) and wipes it before
    /// returning, on success and on error alike.
    pub fn derive_with_memory(
        &self,
        cost: Cost,
        passphrase: &[u8],
        salt: &[u8],
        memory: &mut [Block],
    ) -> Result<Zeroizing<[u8; KEK_LEN]>, String> {
        let params = Params::new(cost.m_kib, cost.t, cost.p, Some(KEK_LEN))
            .map_err(|e| format!("{cost}: {e}"))?;
        let available = memory.len();
        let blocks = memory
            .get_mut(..params.block_count())
            .ok_or_else(|| format!("{cost}: buffer of {available} blocks too small"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut kek = Zeroizing::new([0u8; KEK_LEN]);
        let result = self.pool.install(|| {
            argon2.hash_password_into_with_memory(passphrase, salt, kek.as_mut(), &mut *blocks)
        });
        blocks.iter_mut().for_each(Zeroize::zeroize);
        result.map_err(|e| format!("{cost}: {e}"))?;
        Ok(kek)
    }

    /// Times one derivation with a fixed test passphrase and salt, allocation and wipe included.
    pub fn time(&self, cost: Cost) -> Result<Duration, String> {
        let started = Instant::now();
        self.derive(cost, b"correct horse battery staple", &[0x5a; 16])?;
        Ok(started.elapsed())
    }
}
