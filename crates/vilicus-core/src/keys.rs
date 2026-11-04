//! The key hierarchy at work in the Core (spine AD-4, AD-5, `doc/key-management.md` section 2):
//! each module file keyed from its partition's root at the key epoch its sidecar names, the key
//! text lent from the locked pool for the call that keys each connection, and `wrappers.db`
//! authenticated as a whole (gate AD36-1).
//!
//! A module receives none of this: its code is handed the record port of its call, over a handle
//! the Core opened in the module's own partition, never a key, a key text or a path to one.
//!
//! The Core itself names a role key only as the type it is: `vilicus_crypto::Key` reaches no key
//! bytes, and no derivation from an arbitrary key is exported, so the Core cannot derive one
//! role's key from another's (story 4.3 review, M1). Each check below is a pair, so that the
//! failing half can fail for one reason only: the first compiles, the second differs from it by
//! the one call or name that must not exist outside `vilicus-crypto`. Rustdoc does not check the
//! error code of a `compile_fail` test on stable; the pair is what pins the reason.
//!
//! ```
//! fn leak<K: vilicus_crypto::Key>(_key: &K) -> &vilicus_crypto::SymmetricKey {
//!     todo!()
//! }
//! ```
//!
//! ```compile_fail
//! fn leak<K: vilicus_crypto::Key>(key: &K) -> &vilicus_crypto::SymmetricKey {
//!     key.symmetric()
//! }
//! ```
//!
//! ```
//! use vilicus_crypto::Label as _;
//! ```
//!
//! ```compile_fail
//! use vilicus_crypto::derive_key as _;
//! ```

use core::fmt;
use std::path::Path;

use vilicus_crypto::{
    CryptoError, FileKey, Kdf, KekDerivation, MemberDek, PartitionRoot, SymmetricKey, WrapParams,
    Wrapper, WrapperError, WrapperSetKey, WrapperSetMac,
};
use vilicus_storage::{
    DekWrapperRow, FileKeying, Handle, KekKind, KeyEpoch, ModuleFile, PublicKeyRow, Role,
    WrapperChange, WrapperSet, WrapperSnapshot, WrapperStore, WrapperWrite, Write,
};
use vilicus_types::{Id, Partition, UtcMillis};

/// Why the Core did not key a file, or refused `wrappers.db`.
#[derive(Debug)]
#[non_exhaustive]
pub enum KeyError {
    /// The key was derived for another partition than the file's.
    OtherPartition {
        /// The partition of the key's root.
        key: Partition,
        /// The partition the file belongs to.
        file: Partition,
    },
    /// The key was derived for another module than the file's.
    OtherModule,
    /// The file's sidecar names another key epoch than the key's: the key of that epoch is the
    /// one that opens it.
    OtherEpoch {
        /// The epoch the key was derived for.
        key: KeyEpoch,
        /// The epoch the sidecar names.
        file: KeyEpoch,
    },
    /// `wrappers.db` holds an older counter than the copy `core.db` keeps: an older file, or one
    /// whose counter was lowered, was put in its place.
    RolledBack {
        /// The counter `wrappers.db` holds.
        wrappers: u64,
        /// The copy `core.db` keeps.
        core: u64,
    },
    /// `wrappers.db` holds records but no MAC, or a MAC at counter 0: no write of the Core leaves
    /// that state.
    Unsealed,
    /// The MAC of the `wrappers.db` record set does not verify: a record was deleted, added or
    /// edited, or the counter changed, since the Core last wrote it.
    SetMac(CryptoError),
    /// A stored value of `wrappers.db` is not one this Core reads.
    Format(WrapperError),
    /// A key operation failed.
    Crypto(CryptoError),
    /// The storage layer failed.
    Storage(vilicus_storage::Error),
}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherPartition { key, file } => write!(
                formatter,
                "a key of partition {key} cannot key a file of partition {file}"
            ),
            Self::OtherModule => formatter.write_str("the key was derived for another module"),
            Self::OtherEpoch { key, file } => write!(
                formatter,
                "the key is of epoch ({key}), the file's sidecar names ({file})"
            ),
            Self::RolledBack { wrappers, core } => write!(
                formatter,
                "wrappers.db holds counter {wrappers}, older than core.db's copy {core}"
            ),
            Self::Unsealed => formatter.write_str("wrappers.db holds records but no MAC"),
            Self::SetMac(error) => write!(formatter, "the wrappers.db set MAC: {error}"),
            Self::Format(error) => write!(formatter, "a wrappers.db value: {error}"),
            Self::Crypto(error) => write!(formatter, "{error}"),
            Self::Storage(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<vilicus_storage::Error> for KeyError {
    fn from(error: vilicus_storage::Error) -> Self {
        Self::Storage(error)
    }
}

impl From<CryptoError> for KeyError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

/// The key epoch a file key was derived for.
pub fn epoch_of(key: &FileKey) -> KeyEpoch {
    KeyEpoch {
        partition_root_version: key.partition_root_version(),
        generation: key.generation(),
    }
}

/// The key of `file` under `root` at the epoch its sidecar names (AD-5): HKDF-SHA-256 under
/// `vilicus/v1/db/` with the module, the partition and the epoch. Refused when the root opens
/// another partition, or when the sidecar names another version of the root, whose key this root
/// is not.
pub fn file_key(root: &impl PartitionRoot, file: &ModuleFile) -> Result<FileKey, KeyError> {
    if root.partition() != file.partition() {
        return Err(KeyError::OtherPartition {
            key: root.partition(),
            file: file.partition(),
        });
    }
    let epoch = vilicus_storage::read_epoch(file)?;
    let key = root.file_key(file.module(), epoch.generation)?;
    if epoch.partition_root_version != root.version() {
        return Err(KeyError::OtherEpoch {
            key: epoch_of(&key),
            file: epoch,
        });
    }
    Ok(key)
}

/// A file key lent to the storage layer: the key text `vilicus-crypto` writes in a slot of the
/// locked pool's text class and lends under the guard of a key operation, for the one call that
/// keys a connection (D154). A key memory that refuses the text is
/// [`vilicus_storage::Error::KeyUnavailable`].
pub struct KeyText<'k> {
    key: &'k FileKey,
}

impl<'k> KeyText<'k> {
    /// The key text of `key` for `file`: refused unless `key` was derived for `file`'s module and
    /// partition. The epoch is checked when the file opens ([`open_file`]) or is created
    /// ([`create_file`]).
    pub fn for_file(key: &'k FileKey, file: &ModuleFile) -> Result<Self, KeyError> {
        if key.partition() != file.partition() {
            return Err(KeyError::OtherPartition {
                key: key.partition(),
                file: file.partition(),
            });
        }
        if key.module() != file.module() {
            return Err(KeyError::OtherModule);
        }
        Ok(Self { key })
    }
}

impl FileKeying for KeyText<'_> {
    fn lend_key_text(
        &self,
        key_with: &mut dyn FnMut(&[u8]) -> vilicus_storage::Result<()>,
    ) -> vilicus_storage::Result<()> {
        self.key
            .with_sqlcipher_key_text(|text| key_with(text))
            .map_err(|_| vilicus_storage::Error::KeyUnavailable)?
    }
}

/// Opens `file` in role `R` with `key`: the key text is lent for the call that keys the connection,
/// and the file's epoch, the sidecar's as checked against `_meta`, must be the one `key` was
/// derived for, or the handle is closed and the open refused ([`KeyError::OtherEpoch`]).
pub fn open_file<R: Role>(file: &ModuleFile, key: &FileKey) -> Result<Handle<R>, KeyError> {
    let handle = vilicus_storage::open::<R>(file, &KeyText::for_file(key, file)?)?;
    if handle.epoch() != epoch_of(key) {
        let found = handle.epoch();
        handle.close()?;
        return Err(KeyError::OtherEpoch {
            key: epoch_of(key),
            file: found,
        });
    }
    Ok(handle)
}

/// Creates `file` under `key`, at the epoch `key` was derived for, written in the sidecar and in
/// `_meta` (AD-5).
pub fn create_file(file: &ModuleFile, key: &FileKey) -> Result<Handle<Write>, KeyError> {
    Ok(vilicus_storage::create(
        file,
        &KeyText::for_file(key, file)?,
        epoch_of(key),
    )?)
}

/// Re-keys the file of `handle` under `key`, at the epoch `key` was derived for, written in the
/// sidecar and in `_meta` ([`Handle::rekey`]).
pub fn rekey_file(handle: &mut Handle<Write>, key: &FileKey) -> Result<(), KeyError> {
    let keying = KeyText::for_file(key, handle.file())?;
    Ok(handle.rekey(&keying, epoch_of(key))?)
}

/// What the cross-check of the `wrappers.db` counter with the copy `core.db` keeps found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterCheck {
    /// The counters agree.
    Matches,
    /// `core.db` keeps no copy: it, or the instance key that opens it, is lost. Member DEKs still
    /// unwrap from `wrappers.db` (AD-4); the set MAC is then the only check of the set.
    Unchecked,
    /// `wrappers.db` is ahead of the copy, its set MAC verified: by one, a write whose copy a
    /// crash kept from `core.db`; by more, a `core.db` rolled back. The Core then updates its copy.
    Ahead {
        /// By how many writes.
        by: u64,
    },
}

/// The cross-check of `counter`, the one of `wrappers.db`, with `core_copy`, `core.db`'s copy.
fn counter_check(counter: u64, core_copy: Option<u64>) -> Result<CounterCheck, KeyError> {
    match core_copy {
        None => Ok(CounterCheck::Unchecked),
        Some(core) if counter < core => Err(KeyError::RolledBack {
            wrappers: counter,
            core,
        }),
        Some(core) if counter == core => Ok(CounterCheck::Matches),
        Some(core) => Ok(CounterCheck::Ahead { by: counter - core }),
    }
}

/// Checks `set`'s MAC under `set_key`: a fresh file, at counter 0 with no MAC, holds no DEK
/// wrapper and no public key; any other state holds a MAC that verifies over its counter and every
/// record, the schema's included.
fn verify_set(set: &WrapperSet, set_key: &WrapperSetKey) -> Result<(), KeyError> {
    match (set.counter, &set.mac) {
        (0, None) if !set.holds_member_records => Ok(()),
        (0, _) | (_, None) => Err(KeyError::Unsealed),
        (counter, Some(stored)) => {
            let mac = WrapperSetMac::from_bytes(stored).map_err(KeyError::Format)?;
            set_key
                .verify(&mac, counter, &set.record_slices())
                .map_err(KeyError::SetMac)
        }
    }
}

/// Opens `row`'s wrapper with `kek` as its member's DEK of its version.
fn unwrap_row(row: &DekWrapperRow, kek: &SymmetricKey) -> Result<MemberDek, KeyError> {
    let wrapper = Wrapper::from_bytes(&row.wrapper).map_err(KeyError::Format)?;
    Ok(MemberDek::unwrap(
        &wrapper,
        kek,
        row.member,
        row.dek_version,
    )?)
}

/// `wrappers.db`, opened by the Core: its record set authenticated by a monotonic counter, the MAC
/// of the set under a key derived from the household key, and the cross-check of the counter with
/// `core.db` (gate AD36-1, owner approval).
///
/// Its records are read through [`Verified`] only, once the set's MAC and counter are checked,
/// with one exception: the unlocking member's own DEK wrapper
/// ([`unwrap_own_dek`](Self::unwrap_own_dek)), read before the Core holds the household key that
/// checks the set, since the household key is reached only through that DEK. Nothing the Core
/// does with that DEK before the check reaches another record of the set.
pub struct Wrappers {
    store: WrapperStore,
}

impl fmt::Debug for Wrappers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Wrappers")
            .field("store", &self.store)
            .finish()
    }
}

/// `wrappers.db`'s record set, its MAC verified and its counter cross-checked, all read in one
/// transaction: the records the Core reads, which are those the check covered.
#[derive(Debug)]
pub struct Verified {
    snapshot: WrapperSnapshot,
    counter_check: CounterCheck,
}

impl Verified {
    /// The counter the set verified at.
    pub fn counter(&self) -> u64 {
        self.snapshot.set.counter
    }

    /// What the cross-check with `core.db`'s copy found.
    pub fn counter_check(&self) -> CounterCheck {
        self.counter_check
    }

    /// Unwraps `member`'s DEK from its wrapper under `kind` with `kek`; `None` when the member
    /// has no wrapper of that kind.
    pub fn unwrap_member_dek(
        &self,
        member: Id,
        kind: KekKind,
        kek: &SymmetricKey,
    ) -> Result<Option<MemberDek>, KeyError> {
        self.snapshot
            .dek_wrappers
            .iter()
            .find(|row| row.member == member && row.kek == kind)
            .map(|row| unwrap_row(row, kek))
            .transpose()
    }

    /// Every member public key of the set.
    pub fn public_keys(&self) -> &[PublicKeyRow] {
        &self.snapshot.public_keys
    }
}

impl Wrappers {
    /// Creates `wrappers.db` in `directory`, empty, at counter 0.
    pub fn create(directory: &Path) -> Result<Self, KeyError> {
        Ok(Self {
            store: vilicus_storage::create_wrappers(directory)?,
        })
    }

    /// Opens `wrappers.db` in `directory`; nothing of the instance is needed.
    pub fn open(directory: &Path) -> Result<Self, KeyError> {
        Ok(Self {
            store: vilicus_storage::open_wrappers(directory)?,
        })
    }

    /// The set and its rows, read in one transaction, its MAC verified under `set_key`, the
    /// household key's, then its counter cross-checked with `core_copy`, the copy `core.db` keeps
    /// (`None` when `core.db` or the instance key is lost): an older counter is
    /// [`KeyError::RolledBack`], even under a MAC that holds for it.
    pub fn open_verified(
        &self,
        set_key: &WrapperSetKey,
        core_copy: Option<u64>,
    ) -> Result<Verified, KeyError> {
        let snapshot = self.store.snapshot()?;
        verify_set(&snapshot.set, set_key)?;
        let counter_check = counter_check(snapshot.set.counter, core_copy)?;
        Ok(Verified {
            snapshot,
            counter_check,
        })
    }

    /// Unwraps the unlocking member's own DEK from its wrapper under `kind` with `kek`, before the
    /// set is verified: no key of the instance and nothing of `core.db` is needed (AD-4,
    /// `doc/architecture.md` section 5.2). The one read outside [`Verified`] (the type's
    /// documentation); `None` when the member has no wrapper of that kind.
    pub fn unwrap_own_dek(
        &self,
        member: Id,
        kind: KekKind,
        kek: &SymmetricKey,
    ) -> Result<Option<MemberDek>, KeyError> {
        self.store
            .own_dek_wrapper(member, kind)?
            .map(|row| unwrap_row(&row, kek))
            .transpose()
    }

    /// The unlocking member's own DEK wrapper under `kind`, as stored, before the set is verified:
    /// the same one read as [`unwrap_own_dek`](Self::unwrap_own_dek)'s, for a passphrase unlock
    /// that checks its header's cost before it derives the KEK (story 4.4). `None` when the member
    /// has no wrapper of that kind.
    pub fn own_dek_wrapper(
        &self,
        member: Id,
        kind: KekKind,
    ) -> Result<Option<DekWrapperRow>, KeyError> {
        Ok(self.store.own_dek_wrapper(member, kind)?)
    }

    /// Applies `changes` in one transaction that first verifies the set as it is under
    /// `verify_key`, so a write never seals a set changed behind the Core's back, then raises the
    /// counter and seals the new set under `seal_key`: the same key for a write, the next household
    /// key version's for the rewrite of a rotation. Returns the new counter, which the Core then
    /// copies into `core.db`, with the failure of the checkpoint after the commit, if any: the
    /// write is durable either way.
    pub fn write(
        &mut self,
        verify_key: &WrapperSetKey,
        seal_key: &WrapperSetKey,
        changes: &[WrapperChange],
    ) -> Result<WrapperWrite, KeyError> {
        self.store.write(
            changes,
            |set| verify_set(set, verify_key),
            |counter, records| Ok(seal_key.seal(counter, records)?.to_bytes().to_vec()),
        )
    }

    /// The change that writes `dek`'s wrapper under `kek`, a KEK of kind `kind` obtained as `kdf`
    /// and `kek_derivation` state, with the salt or credential reference `kek_reference`, made at
    /// `created_at` with the id `wrapper_id`.
    #[allow(clippy::too_many_arguments)] // Each is a field of the wrapper or of its row.
    pub fn dek_wrapper_change(
        dek: &MemberDek,
        kind: KekKind,
        kek: &SymmetricKey,
        kdf: Kdf,
        kek_derivation: KekDerivation,
        kek_reference: Vec<u8>,
        created_at: UtcMillis,
        wrapper_id: Id,
    ) -> Result<WrapperChange, KeyError> {
        let params = WrapParams::new(kdf, kek_derivation, kek_reference, created_at, wrapper_id)?;
        Ok(WrapperChange::PutDekWrapper(DekWrapperRow {
            member: dek.member(),
            kek: kind,
            dek_version: dek.version(),
            wrapper: dek.wrap(kek, params)?.to_bytes(),
        }))
    }

    /// Closes `wrappers.db`.
    pub fn close(self) -> Result<(), KeyError> {
        Ok(self.store.close()?)
    }
}

#[cfg(test)]
mod tests;
