//! Argon2id, for the passphrase KEK of a member DEK wrapper (Story 4.4, D128, D129), from the
//! `argon2` crate under the exception D129 makes to D28 and the usage rules of
//! `doc/qa/argon2-review.md`. The crate is not audited; it rests on that internal review, the
//! vectors of the tests and the cross-tests of `oracles/argon2id` (D129).
//!
//! - **U1**: `argon2` `=0.6.0` with its `zeroize` feature alone, declared by this crate only;
//!   `ci/primitive_sources.toml` forbids its other features, so `hash_password_into`, which frees
//!   its blocks unwiped, is not compiled, and rayon is not in the tree.
//! - **U2**: every derivation calls `hash_password_into_with_memory` with exactly
//!   [`CheckedCost::block_count`] blocks of a [`WorkingMemory`], locked, never formatted, logged or
//!   copied, and wiped on drop, so success, error and unwind all wipe it (finding F1).
//! - **U3**: the whole derivation, the passphrase's encoding included, runs inside one guarded
//!   call of the key memory, which writes the KEK into a slot of the pool and scrubs the stack and
//!   the vector registers when it returns.
//! - **U4**: the crate's `Params` are built in one place, from a [`CheckedCost`]: the named
//!   constants of `vilicus-types`, or a header that passed the floor and the ceiling before it was
//!   queued, every cost in KiB and the output 32 bytes. Every crate error is one refusal.
//! - **U5**: the context is Argon2id, version 0x13, with no secret, no associated data and no key
//!   id; a header's Argon2 version is checked by the wrapper format, never mapped through the
//!   crate's types.
//! - **U6**: the passphrase is the Core's, normalised to NFC; it is encoded as UTF-8 into the
//!   working memory's own buffer, wiped with it, and refused above
//!   [`PASSPHRASE_MAX_LEN`] bytes before the limiter. A salt is
//!   [`PASSPHRASE_SALT_LEN`] bytes of the operating system's generator ([`passphrase_salt`]).
//!
//! Every derivation is admitted by the one limiter of D128 ([`admit_derivation`]) and needs its
//! permit.
//!
//! A wipe of the pool and a derivation in progress: the crate has no step between which the pool
//! could be checked, so a derivation that is running when the pool is wiped runs to its end,
//! past the wipe's [`WIPE_WAIT`](crate::WIPE_WAIT) when it is longer. Its result is discarded,
//! the call returns [`KeyMemoryError::Wiped`](crate::KeyMemoryError::Wiped), never a KEK, and its
//! KEK slot and working memory are wiped when they are dropped; the overwrite of the pool may race
//! with its last write into its slot, as for any late call (D154).

use argon2::{Algorithm, Argon2, Params, Version};
use vilicus_types::{
    PASSPHRASE_ARGON2ID_LANES, PASSPHRASE_ARGON2ID_MEMORY_KIB, PASSPHRASE_ARGON2ID_PASSES,
    PASSPHRASE_KEK_LEN, PASSPHRASE_MAX_LEN, PASSPHRASE_SALT_LEN, argon2id_meets_floor,
    argon2id_within_ceiling,
};

use crate::error::CryptoError;
use crate::key::{KEY_LEN, Slot, SymmetricKey};
use crate::memory::{WorkingMemory, os_random};
use crate::wrapper::Argon2idParams;

mod limiter;
#[cfg(any(test, feature = "testing"))]
pub mod test_runtime;

pub use limiter::{Admission, DerivationPermit, admit_derivation};

#[cfg(test)]
pub(crate) mod tests;

const _: () = assert!(PASSPHRASE_KEK_LEN == KEY_LEN);

/// Bytes of the passphrase buffer of a derivation's working memory: the NFC form of a passphrase
/// of [`PASSPHRASE_MAX_LEN`] bytes is at most three times as long (UAX #15, section 13).
pub(crate) const PASSPHRASE_BUFFER_LEN: usize = 3 * PASSPHRASE_MAX_LEN;

impl Argon2idParams {
    /// The cost of a version 1 passphrase wrapper (D128): the named constants of `vilicus-types`.
    pub const PASSPHRASE_V1: Self = Self {
        memory_kib: PASSPHRASE_ARGON2ID_MEMORY_KIB,
        passes: PASSPHRASE_ARGON2ID_PASSES,
        lanes: PASSPHRASE_ARGON2ID_LANES,
    };
}

/// An Argon2id cost the Core derives with: at least the floor and at most the ceiling of D128,
/// and one the `argon2` crate accepts. A header's cost becomes one before its derivation is
/// queued, so a header outside them never takes a place in the limiter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedCost {
    params: Argon2idParams,
    block_count: usize,
}

impl CheckedCost {
    /// `params` checked against the floor and the ceiling of D128 (`vilicus-types`), then against
    /// the crate's own bounds; any refusal is [`CryptoError::Argon2idCost`].
    ///
    /// ```
    /// use vilicus_crypto::{Argon2idParams, CheckedCost, CryptoError};
    ///
    /// let current = CheckedCost::new(Argon2idParams::PASSPHRASE_V1)?;
    /// assert_eq!(current.params(), Argon2idParams::PASSPHRASE_V1);
    /// let below_the_floor = Argon2idParams { memory_kib: 19 * 1024, passes: 2, lanes: 1 };
    /// assert!(matches!(
    ///     CheckedCost::new(below_the_floor),
    ///     Err(CryptoError::Argon2idCost { .. })
    /// ));
    /// # Ok::<(), CryptoError>(())
    /// ```
    pub fn new(params: Argon2idParams) -> Result<Self, CryptoError> {
        let Argon2idParams {
            memory_kib,
            passes,
            lanes,
        } = params;
        if !argon2id_meets_floor(memory_kib, passes)
            || !argon2id_within_ceiling(memory_kib, passes, lanes)
        {
            return Err(refused(params));
        }
        Self::accepted_by_the_crate(params)
    }

    /// `params` checked against the crate's bounds only: below the floor, for the tests' vectors
    /// and cross-tests, never for a header.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn below_the_floor(params: Argon2idParams) -> Result<Self, CryptoError> {
        Self::accepted_by_the_crate(params)
    }

    fn accepted_by_the_crate(params: Argon2idParams) -> Result<Self, CryptoError> {
        Ok(Self {
            params,
            block_count: argon2_params(params)?.block_count(),
        })
    }

    /// The cost as it is written in a wrapper header.
    pub fn params(&self) -> Argon2idParams {
        self.params
    }

    /// The blocks of 1 KiB a derivation of this cost uses: m rounded down to a multiple of four
    /// times p (RFC 9106 section 3.2), and its working memory.
    pub fn block_count(&self) -> usize {
        self.block_count
    }

    /// The KiB of working memory the limiter counts for a derivation of this cost: its blocks.
    fn working_memory_kib(&self) -> u64 {
        self.block_count as u64
    }
}

fn refused(params: Argon2idParams) -> CryptoError {
    CryptoError::Argon2idCost {
        memory_kib: params.memory_kib,
        passes: params.passes,
        lanes: params.lanes,
    }
}

/// The crate's parameters of `params`, every cost in KiB and a 32-byte output (U4): the one place
/// they are built.
fn argon2_params(params: Argon2idParams) -> Result<Params, CryptoError> {
    Params::new(
        params.memory_kib,
        params.passes,
        params.lanes,
        Some(PASSPHRASE_KEK_LEN),
    )
    .map_err(|_| refused(params))
}

/// A new salt for a passphrase wrapper: [`PASSPHRASE_SALT_LEN`] bytes of the operating system's
/// generator (U6).
pub fn passphrase_salt() -> Result<[u8; PASSPHRASE_SALT_LEN], CryptoError> {
    let mut salt = [0; PASSPHRASE_SALT_LEN];
    os_random(&mut salt)?;
    Ok(salt)
}

/// Derives the passphrase KEK of `cost` and `salt` from `passphrase`, the characters of the
/// member's passphrase in NFC, under `permit`, the limiter's admission of a derivation of that
/// cost, into a new key of the pool. Runs for as long as Argon2id does: on a thread of the blocking
/// pool, never on an async worker (D128).
///
/// Refused: a permit of another cost ([`CryptoError::PermitMismatch`]); an NFC form longer than the
/// derivation's buffer ([`CryptoError::PassphraseTooLong`]); working memory `mlock` refuses
/// ([`KeyMemoryError::WorkingMemoryLock`](crate::KeyMemoryError::WorkingMemoryLock)); a wiped
/// pool, even one wiped while the derivation ran. The working memory is wiped whatever the outcome.
pub fn derive_passphrase_kek(
    permit: &DerivationPermit<'_>,
    cost: &CheckedCost,
    passphrase: impl IntoIterator<Item = char>,
    salt: &[u8; PASSPHRASE_SALT_LEN],
) -> Result<SymmetricKey, CryptoError> {
    permit.check(cost)?;
    derive_into(Slot::new()?, cost, passphrase, salt)
}

/// Argon2id of `passphrase`, UTF-8 encoded, with `cost` and `salt`, into `kek`: the derivation of
/// U2, U3 and U5, whatever the caller.
pub(crate) fn derive_into(
    mut kek: Slot,
    cost: &CheckedCost,
    passphrase: impl IntoIterator<Item = char>,
    salt: &[u8],
) -> Result<SymmetricKey, CryptoError> {
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2_params(cost.params)?,
    );
    let mut memory = WorkingMemory::new(cost.block_count, PASSPHRASE_BUFFER_LEN)?;
    let (blocks, buffer) = memory.split();
    kek.with_key_mut(|out| {
        let len = encode_utf8(passphrase, buffer)?;
        #[cfg(test)]
        tests::hooks::during_derivation();
        argon2
            .hash_password_into_with_memory(&buffer[..len], salt, out, blocks)
            .map_err(|_| CryptoError::Argon2id)
    })??;
    drop(memory);
    Ok(SymmetricKey::from_slot(kek))
}

/// Writes `characters` as UTF-8 at the start of `buffer` and returns how many bytes they took;
/// [`CryptoError::PassphraseTooLong`] when they do not fit.
fn encode_utf8(
    characters: impl IntoIterator<Item = char>,
    buffer: &mut [u8],
) -> Result<usize, CryptoError> {
    let mut len = 0;
    for character in characters {
        let end = len + character.len_utf8();
        let Some(destination) = buffer.get_mut(len..end) else {
            return Err(CryptoError::PassphraseTooLong);
        };
        character.encode_utf8(destination);
        len = end;
    }
    Ok(len)
}

/// Argon2id of `passphrase`'s characters with any cost the crate accepts, the floor not checked,
/// and any salt, through the derivation the Core runs: for the vectors, the cross-tests and the
/// key memory harness.
#[cfg(feature = "testing")]
pub fn derive_below_the_floor(
    params: Argon2idParams,
    passphrase: &str,
    salt: &[u8],
) -> Result<SymmetricKey, CryptoError> {
    let cost = CheckedCost::below_the_floor(params)?;
    derive_into(Slot::new()?, &cost, passphrase.chars(), salt)
}
