//! Passphrase unlock (FR-11, AD-9, D128; Story 4.4): a member's passphrase opens their DEK through
//! an Argon2id KEK, only once their first factor has succeeded, through the one limiter of the
//! Core's Argon2id derivations, one request in flight per member, and with a growing delay after
//! each failed passphrase.
//!
//! An unlock runs in four steps:
//!
//! 1. [`prepare`]: refused without a successful first factor
//!    ([`UnlockRefused::NoFirstFactor`]), while the member has another request in flight or is in
//!    their delay, for a passphrase longer than
//!    [`PASSPHRASE_MAX_LEN`](vilicus_types::PASSPHRASE_MAX_LEN), and for a wrapper header whose
//!    cost is outside the floor and the ceiling or whose salt is not 16 bytes. Nothing is
//!    queued and no Argon2id runs before all of these pass.
//! 2. [`Prepared::admission`], awaited on an async worker: the limiter's admission, or a retryable
//!    refusal after `ARGON2ID_QUEUE_WAIT`; no thread waits in the queue.
//! 3. [`Prepared::unlock`], on a thread of the blocking pool: the derivation over the passphrase
//!    normalised to NFC, then the DEK opened. A wrong passphrase starts the member's delay.
//! 4. When the header's cost is not the current one, [`Unlocked::rewrap`] under a second
//!    admission: the wrapper rewritten at the current cost, so that an unlock at an older cost
//!    costs two derivations (D128).
//!
//! Story 5.1 composes the steps on the Core's runtime; no first factor exists before the passkey
//! login of story 7.6 and the host path of story 9.4, so no product path starts an unlock yet.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use unicode_normalization::UnicodeNormalization;
use vilicus_crypto::{
    Admission, Argon2idParams, CheckedCost, CryptoError, DerivationPermit, Kdf, KekDerivation,
    MemberDek, Wrapper, admit_derivation, derive_passphrase_kek, passphrase_salt,
};
use vilicus_storage::{DekWrapperRow, KekKind, WrapperChange};
use vilicus_types::{
    Id, PASSPHRASE_BACKOFF_BASE, PASSPHRASE_BACKOFF_MAX, PASSPHRASE_MAX_LEN, PASSPHRASE_SALT_LEN,
    UtcMillis,
};

use crate::keys::{KeyError, Wrappers};

#[cfg(test)]
mod tests;

/// The first factor an unlock request carries, once it succeeded: a passkey login (story 7.6) or
/// the host CLI path (story 9.4). Only those paths make one, so only tests make one before them.
pub struct FirstFactor {
    kind: FirstFactorKind,
}

/// How the first factor succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FirstFactorKind {
    /// A passkey login in the web client.
    PasskeyLogin,
    /// The member at the host's console, through the admin socket.
    HostCli,
}

impl FirstFactor {
    /// How this first factor succeeded.
    pub fn kind(&self) -> FirstFactorKind {
        self.kind
    }

    /// A first factor for the tests, which run before the paths that make one exist.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_tests(kind: FirstFactorKind) -> Self {
        Self { kind }
    }
}

/// Why an unlock was refused before any Argon2id ran, or why it did not open the DEK.
#[derive(Debug)]
#[non_exhaustive]
pub enum UnlockRefused {
    /// The request carries no successful first factor (AD-9).
    NoFirstFactor,
    /// The member has another unlock in flight (D128).
    InFlight,
    /// The member's delay after a failed passphrase has not passed (D128).
    Backoff,
    /// The passphrase is longer than `PASSPHRASE_MAX_LEN` bytes.
    PassphraseTooLong,
    /// The member has no passphrase wrapper.
    NoPassphraseWrapper,
    /// The passphrase wrapper is not derived by Argon2id, or its salt is not 16 bytes.
    NotAPassphraseWrapper,
    /// The wrapper header's cost is below the floor or above the ceiling (D128).
    Cost(CryptoError),
    /// The limiter admitted no derivation in time: retryable, and the time waited is not said.
    Busy,
    /// The passphrase did not open the DEK. The member's delay starts or doubles.
    WrongPassphrase,
    /// A key operation failed.
    Crypto(CryptoError),
    /// `wrappers.db` was refused or failed.
    Keys(KeyError),
}

impl fmt::Display for UnlockRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFirstFactor => formatter.write_str("no successful first factor"),
            Self::InFlight => formatter.write_str("another unlock of this member is in flight"),
            Self::Backoff => formatter.write_str("too soon after a failed passphrase"),
            Self::PassphraseTooLong => formatter.write_str("the passphrase is too long"),
            Self::NoPassphraseWrapper => formatter.write_str("the member has no passphrase"),
            Self::NotAPassphraseWrapper => {
                formatter.write_str("the passphrase wrapper is not an Argon2id wrapper")
            }
            Self::Cost(error) | Self::Crypto(error) => write!(formatter, "{error}"),
            Self::Busy => formatter.write_str("no unlock could start in time: retry later"),
            Self::WrongPassphrase => formatter.write_str("the passphrase did not open the key"),
            Self::Keys(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for UnlockRefused {}

impl From<KeyError> for UnlockRefused {
    fn from(error: KeyError) -> Self {
        Self::Keys(error)
    }
}

impl From<CryptoError> for UnlockRefused {
    fn from(error: CryptoError) -> Self {
        match error {
            CryptoError::Argon2idBusy => Self::Busy,
            other => Self::Crypto(other),
        }
    }
}

/// What the gate keeps of a member between their unlock requests.
#[derive(Default)]
struct MemberState {
    in_flight: bool,
    /// Failed passphrases since the last successful unlock.
    failures: u32,
    /// When the member may try again.
    retry_at: Option<Instant>,
}

/// The per-member state of passphrase unlocks: one request in flight per member, and the delay
/// after a failed passphrase (D128).
#[derive(Default)]
pub struct UnlockGate {
    members: Mutex<HashMap<Id, MemberState>>,
}

impl UnlockGate {
    /// A gate with no member state.
    pub fn new() -> Self {
        Self::default()
    }

    fn members(&self) -> MutexGuard<'_, HashMap<Id, MemberState>> {
        self.members.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Admits a request of `member` at `now`, carrying `first_factor`: refused without one, while
    /// another of the member's requests is in flight, and before the member's delay has passed.
    /// The ticket marks the request in flight until it is dropped.
    pub fn begin(
        &self,
        member: Id,
        first_factor: Option<&FirstFactor>,
        now: Instant,
    ) -> Result<UnlockTicket<'_>, UnlockRefused> {
        if first_factor.is_none() {
            return Err(UnlockRefused::NoFirstFactor);
        }
        let mut members = self.members();
        let state = members.entry(member).or_default();
        if state.in_flight {
            return Err(UnlockRefused::InFlight);
        }
        if state.retry_at.is_some_and(|retry_at| now < retry_at) {
            return Err(UnlockRefused::Backoff);
        }
        state.in_flight = true;
        Ok(UnlockTicket { gate: self, member })
    }
}

/// The delay after the `failures`-th failed passphrase in a row: the base, doubled for each
/// failure after the first, at most the maximum.
pub fn backoff_after(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(31);
    PASSPHRASE_BACKOFF_BASE
        .saturating_mul(1 << doublings)
        .min(PASSPHRASE_BACKOFF_MAX)
}

/// One member's unlock request in flight; the member's next request is refused while it lives.
pub struct UnlockTicket<'g> {
    gate: &'g UnlockGate,
    member: Id,
}

impl UnlockTicket<'_> {
    /// The member of the request.
    pub fn member(&self) -> Id {
        self.member
    }

    fn record(&self, opened: bool, now: Instant) {
        let mut members = self.gate.members();
        let state = members.entry(self.member).or_default();
        if opened {
            state.failures = 0;
            state.retry_at = None;
        } else {
            state.failures = state.failures.saturating_add(1);
            state.retry_at = Some(now + backoff_after(state.failures));
        }
    }
}

impl Drop for UnlockTicket<'_> {
    fn drop(&mut self) {
        if let Some(state) = self.gate.members().get_mut(&self.member) {
            state.in_flight = false;
        }
    }
}

/// An unlock that passed every check made before the queue: its ticket, the member's passphrase
/// wrapper and the cost and salt its header states.
pub struct Prepared<'g> {
    ticket: UnlockTicket<'g>,
    row: DekWrapperRow,
    wrapper: Wrapper,
    cost: CheckedCost,
    salt: [u8; PASSPHRASE_SALT_LEN],
}

/// Step 1: checks a passphrase unlock of `member`, received at `now` with `first_factor`, before
/// anything is queued: the first factor, the member's request in flight and delay, the
/// passphrase's length, then the member's own passphrase wrapper in `wrappers` and its header,
/// whose cost must be within the floor and the ceiling and whose salt must be 16 bytes.
pub fn prepare<'g>(
    gate: &'g UnlockGate,
    member: Id,
    first_factor: Option<&FirstFactor>,
    passphrase: &str,
    wrappers: &Wrappers,
    now: Instant,
) -> Result<Prepared<'g>, UnlockRefused> {
    let ticket = gate.begin(member, first_factor, now)?;
    if passphrase.len() > PASSPHRASE_MAX_LEN {
        return Err(UnlockRefused::PassphraseTooLong);
    }
    let row = wrappers
        .own_dek_wrapper(member, KekKind::Passphrase)?
        .ok_or(UnlockRefused::NoPassphraseWrapper)?;
    let wrapper = Wrapper::from_bytes(&row.wrapper).map_err(KeyError::Format)?;
    let Kdf::Argon2id(params) = wrapper.kdf() else {
        return Err(UnlockRefused::NotAPassphraseWrapper);
    };
    let salt: [u8; PASSPHRASE_SALT_LEN] = wrapper
        .kek_reference()
        .try_into()
        .map_err(|_| UnlockRefused::NotAPassphraseWrapper)?;
    let cost = CheckedCost::new(params).map_err(UnlockRefused::Cost)?;
    Ok(Prepared {
        ticket,
        row,
        wrapper,
        cost,
        salt,
    })
}

impl<'g> Prepared<'g> {
    /// Step 2: the limiter's admission of this unlock's derivation, with `sleep`, the runtime's
    /// timer, for the wait bound.
    pub fn admission<T: Future<Output = ()>>(
        &self,
        sleep: impl FnOnce(Duration) -> T,
    ) -> Admission<'static, T> {
        admit_derivation(&self.cost, sleep)
    }

    /// The cost the header states, which the derivation uses.
    pub fn cost(&self) -> CheckedCost {
        self.cost
    }

    /// Step 3, on a thread of the blocking pool: the KEK derived from `passphrase`, normalised to
    /// NFC, under `permit`, then the member's DEK opened with it. A passphrase that does not open
    /// it is [`UnlockRefused::WrongPassphrase`] and starts or doubles the member's delay from
    /// `now`; a success clears it.
    pub fn unlock(
        self,
        permit: &DerivationPermit<'_>,
        passphrase: &str,
        now: Instant,
    ) -> Result<Unlocked<'g>, UnlockRefused> {
        let kek = derive_passphrase_kek(permit, &self.cost, passphrase.nfc(), &self.salt)?;
        let opened = MemberDek::unwrap(&self.wrapper, &kek, self.row.member, self.row.dek_version);
        drop(kek);
        match opened {
            Ok(dek) => {
                self.ticket.record(true, now);
                Ok(Unlocked {
                    ticket: self.ticket,
                    dek,
                    outdated: self.cost.params() != Argon2idParams::PASSPHRASE_V1,
                })
            }
            Err(CryptoError::Open) => {
                self.ticket.record(false, now);
                Err(UnlockRefused::WrongPassphrase)
            }
            Err(other) => Err(other.into()),
        }
    }
}

/// A member's DEK opened by their passphrase; the request stays in flight while this lives.
pub struct Unlocked<'g> {
    ticket: UnlockTicket<'g>,
    dek: MemberDek,
    outdated: bool,
}

impl Unlocked<'_> {
    /// The member's DEK.
    pub fn dek(&self) -> &MemberDek {
        &self.dek
    }

    /// The DEK, ending the request.
    pub fn into_dek(self) -> MemberDek {
        self.dek
    }

    /// Whether the wrapper was written at another cost than the current one, and is rewritten at
    /// this unlock (step 4).
    pub fn needs_rewrap(&self) -> bool {
        self.outdated
    }

    /// The member of the unlock.
    pub fn member(&self) -> Id {
        self.ticket.member()
    }

    /// Step 4, on a thread of the blocking pool, under `permit`, an admission of the current cost:
    /// the change that rewrites the member's passphrase wrapper at the current cost under a new
    /// salt, made at `created_at` with the id `wrapper_id`. The caller writes it into
    /// `wrappers.db` with the household key's set key.
    pub fn rewrap(
        &self,
        permit: &DerivationPermit<'_>,
        passphrase: &str,
        created_at: UtcMillis,
        wrapper_id: Id,
    ) -> Result<WrapperChange, UnlockRefused> {
        passphrase_wrapper_change(permit, &self.dek, passphrase, created_at, wrapper_id)
    }
}

/// The current cost of a passphrase wrapper, the version 1 cost of D128, as the limiter admits it:
/// for the admission of a wrapper's write (enrollment, a passphrase change, a rewrap).
pub fn current_cost() -> Result<CheckedCost, CryptoError> {
    CheckedCost::new(Argon2idParams::PASSPHRASE_V1)
}

/// The change that writes `dek`'s passphrase wrapper at the current cost (AC5 of story 4.4):
/// Argon2id version 0x13 with the constants of `vilicus-types`, a new 16-byte salt of the operating
/// system's generator and a 32-byte KEK, over `passphrase` normalised to NFC and encoded as UTF-8,
/// under `permit`, an admission of [`current_cost`]. The KEK is used for the wrap and dropped.
pub fn passphrase_wrapper_change(
    permit: &DerivationPermit<'_>,
    dek: &MemberDek,
    passphrase: &str,
    created_at: UtcMillis,
    wrapper_id: Id,
) -> Result<WrapperChange, UnlockRefused> {
    if passphrase.len() > PASSPHRASE_MAX_LEN {
        return Err(UnlockRefused::PassphraseTooLong);
    }
    let cost = current_cost()?;
    let salt = passphrase_salt()?;
    let kek = derive_passphrase_kek(permit, &cost, passphrase.nfc(), &salt)?;
    Ok(Wrappers::dek_wrapper_change(
        dek,
        KekKind::Passphrase,
        &kek,
        Kdf::Argon2id(cost.params()),
        KekDerivation::Direct,
        salt.to_vec(),
        created_at,
        wrapper_id,
    )?)
}
