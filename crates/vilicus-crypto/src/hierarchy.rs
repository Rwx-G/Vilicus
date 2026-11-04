//! The key hierarchy (`doc/key-management.md` section 2, spine AD-4 and AD-5): one type per role
//! a key plays, and every derivation from one role to another, each under its versioned label.
//!
//! The roles and their derivations are declared once, in [`DERIVATIONS`]; each derivation of the
//! code is made through [`derive_child!`], which refuses at build time a parent whose role its
//! registry entry does not name. The child role an entry names is checked by the tests, which run
//! every entry and read the role of the key it produced (`every_derivation_produces_its_child`).
//! A key's bytes never leave the crate: [`Key`] names a key type, and its key is reachable only
//! with a [`Token`](sealed::Token) that the crate alone can make. A module file's key derives from its partition's root only,
//! with the module, the partition and the key epoch in its context, so no key of one file opens
//! another, and no key the instance key reaches opens a personal or household file (D3, D9).

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

use vilicus_types::{Id, ModuleName, Partition};

use crate::derive::{Label, derive_key};
use crate::error::CryptoError;
use crate::key::{Slot, SymmetricKey};
use crate::wrapper::{WrapParams, Wrapper};
use crate::wrapper_set::WrapperSetKey;

/// The kinds of partition a file key belongs to (AD-5, AD-37).
// Public in a private module: the sealed trait of the key types names it, and nothing outside the
// crate can.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartitionKind {
    /// A member's personal partition, under the member's DEK.
    Personal,
    /// The household partition, under the household key.
    Household,
    /// The home partition, under the home partition root.
    Home,
}

impl PartitionKind {
    #[cfg(test)]
    pub(crate) const fn of(partition: Partition) -> Self {
        match partition {
            Partition::Member(_) => Self::Personal,
            Partition::Household => Self::Household,
            Partition::Home => Self::Home,
        }
    }

    const fn is(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::Personal, Self::Personal)
                | (Self::Household, Self::Household)
                | (Self::Home, Self::Home)
        )
    }
}

/// The role a key plays in the hierarchy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The instance key, from the Core's systemd credential (D9).
    InstanceKey,
    /// The audit key, from the audit writer's credential (D114).
    AuditKey,
    /// A member's DEK, the root of their personal partition (D4).
    MemberDek,
    /// The household key, the root of the household partition.
    HouseholdKey,
    /// The root of the home partition, derived from the instance key (D53).
    HomePartitionRoot,
    /// The SQLCipher key of `core.db`, derived from the instance key (D9).
    CoreMetadataKey,
    /// The SQLCipher key of `audit.db`, derived from the audit key (D114).
    AuditDatabaseKey,
    /// The SQLCipher key of one module file of a partition of the given kind (D3).
    FileKey(PartitionKind),
    /// The MAC key of the `wrappers.db` record set, derived from the household key.
    WrapperSetKey,
}

impl Role {
    pub(crate) const fn is(self, other: Self) -> bool {
        match (self, other) {
            (Self::FileKey(kind), Self::FileKey(other)) => kind.is(other),
            (Self::InstanceKey, Self::InstanceKey)
            | (Self::AuditKey, Self::AuditKey)
            | (Self::MemberDek, Self::MemberDek)
            | (Self::HouseholdKey, Self::HouseholdKey)
            | (Self::HomePartitionRoot, Self::HomePartitionRoot)
            | (Self::CoreMetadataKey, Self::CoreMetadataKey)
            | (Self::AuditDatabaseKey, Self::AuditDatabaseKey)
            | (Self::WrapperSetKey, Self::WrapperSetKey) => true,
            _ => false,
        }
    }
}

/// One derivation of the hierarchy: HKDF-SHA-256 from a key of role `parent` under `label` (with
/// the context its call gives), into a key of role `child`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Derivation {
    pub(crate) label: Label,
    pub(crate) parent: Role,
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "the child role is the tests' to check against the produced key"
        )
    )]
    pub(crate) child: Role,
}

/// The label of every module file key: the module, the partition and the key epoch follow it in
/// the context (`doc/key-management.md` section 2, `vilicus/v1/db/<module>/<partition>/<generation>`).
const FILE_KEY_LABEL: Label = crate::label!("vilicus/v1/db/");

/// The home partition root, from the instance key (D53).
pub(crate) const HOME_PARTITION_ROOT: Derivation = Derivation {
    label: crate::label!("vilicus/v1/partition/home"),
    parent: Role::InstanceKey,
    child: Role::HomePartitionRoot,
};

/// The key of `core.db`, from the instance key (D9).
pub(crate) const CORE_METADATA_KEY: Derivation = Derivation {
    label: crate::label!("vilicus/v1/core/db"),
    parent: Role::InstanceKey,
    child: Role::CoreMetadataKey,
};

/// The key of `audit.db`, from the audit key (D114).
pub(crate) const AUDIT_DATABASE_KEY: Derivation = Derivation {
    label: crate::label!("vilicus/v1/audit/db"),
    parent: Role::AuditKey,
    child: Role::AuditDatabaseKey,
};

/// The key of a module file of a member's personal partition, from the member's DEK.
pub(crate) const PERSONAL_FILE_KEY: Derivation = Derivation {
    label: FILE_KEY_LABEL,
    parent: Role::MemberDek,
    child: Role::FileKey(PartitionKind::Personal),
};

/// The key of a module file of the household partition, from the household key.
pub(crate) const HOUSEHOLD_FILE_KEY: Derivation = Derivation {
    label: FILE_KEY_LABEL,
    parent: Role::HouseholdKey,
    child: Role::FileKey(PartitionKind::Household),
};

/// The key of a module file of the home partition, from the home partition root.
pub(crate) const HOME_FILE_KEY: Derivation = Derivation {
    label: FILE_KEY_LABEL,
    parent: Role::HomePartitionRoot,
    child: Role::FileKey(PartitionKind::Home),
};

/// The MAC key of the `wrappers.db` record set, from the household key, with its version in the
/// context (gate AD36-1).
pub(crate) const WRAPPER_SET_KEY: Derivation = Derivation {
    label: crate::label!("vilicus/v1/hk/wrappers-set-mac/"),
    parent: Role::HouseholdKey,
    child: Role::WrapperSetKey,
};

/// Every derivation of the hierarchy. `every_derivation_is_registered` fails on a `Derivation`
/// of the source that is not here; the tests read it, and each derivation of the code is checked
/// against its own entry when the crate is built ([`derive_child!`]).
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the registry is read by the tests; the build checks each entry"
    )
)]
pub(crate) const DERIVATIONS: [Derivation; 7] = [
    HOME_PARTITION_ROOT,
    CORE_METADATA_KEY,
    AUDIT_DATABASE_KEY,
    PERSONAL_FILE_KEY,
    HOUSEHOLD_FILE_KEY,
    HOME_FILE_KEY,
    WRAPPER_SET_KEY,
];

/// The purpose a member DEK wrapper is bound to; its context is the member and the DEK version.
pub(crate) const MEMBER_DEK_WRAP: Label = crate::label!("vilicus/v1/wrap/member-dek");

pub(crate) mod sealed {
    use super::Role;
    use crate::key::SymmetricKey;

    /// What a call to [`HoldsKey::symmetric`] needs: a value only this crate makes, so that a key
    /// type's key is unreachable outside it, even through a generic bound on [`Key`](super::Key)
    /// (story 4.3 review, M1).
    pub struct Token(());

    /// The token of the crate's own calls.
    pub(crate) const fn token() -> Token {
        Token(())
    }

    /// A key type of the hierarchy: its role and the key it holds, private to the crate.
    pub trait HoldsKey {
        /// The role of every key of this type, as a parent of [`DERIVATIONS`](super::DERIVATIONS);
        /// `None` for a type that is no parent there.
        const ROLE: Option<Role>;

        /// The key, for the crate's own operations.
        fn symmetric(&self, token: Token) -> &SymmetricKey;
    }
}

use sealed::{HoldsKey, Token, token};

/// A key type of the crate: [`SymmetricKey`] and every role of the hierarchy. Sealed: only this
/// crate defines key types (spine AD-4), and only it reaches the key a type holds, so a role key
/// cannot be handed to an operation of another role outside the crate.
pub trait Key: HoldsKey {}

impl<K: HoldsKey> Key for K {}

impl HoldsKey for SymmetricKey {
    const ROLE: Option<Role> = None;

    fn symmetric(&self, _: Token) -> &SymmetricKey {
        self
    }
}

const fn has_role(declared: Option<Role>, role: Role) -> bool {
    match declared {
        Some(declared) => declared.is(role),
        None => false,
    }
}

/// The key derived from `$parent`, a `$parent_type`, under `$derivation` and `$context`. The build
/// fails when `$derivation` names another parent role than `$parent_type`'s; the child role the
/// entry names is the tests' to check (the module documentation).
macro_rules! derive_child {
    ($parent:expr, $parent_type:ty, $derivation:expr, $context:expr) => {{
        const {
            assert!(
                has_role(<$parent_type as HoldsKey>::ROLE, $derivation.parent),
                "a derivation from a parent role its registry entry does not name"
            );
        };
        derive_key(
            HoldsKey::symmetric($parent, token()),
            $derivation.label,
            $context,
        )
    }};
}

/// Reads a 256-bit key from the credential file at `path` straight into a slot of the pool, so
/// that no other copy of it exists in the process: the file must hold exactly 32 bytes.
fn key_from_credential(path: &Path) -> Result<SymmetricKey, CryptoError> {
    let errno = |error: std::io::Error| CryptoError::Credential {
        errno: error.raw_os_error().unwrap_or(0),
    };
    let mut file = File::open(path).map_err(errno)?;
    let mut slot = Slot::new()?;
    slot.with_key_mut(|bytes| file.read_exact(bytes))?
        .map_err(|error| match error.kind() {
            ErrorKind::UnexpectedEof => CryptoError::CredentialLength,
            _ => errno(error),
        })?;
    let mut past_the_key = [0_u8; 1];
    match file.read(&mut past_the_key) {
        Ok(0) => Ok(SymmetricKey::from_slot(slot)),
        Ok(_) => Err(CryptoError::CredentialLength),
        Err(error) => Err(errno(error)),
    }
}

/// The instance key (D9): the root of the home partition and the key of `core.db`'s metadata.
/// Nothing derived from it opens a personal or household partition file. Not `Clone`, `Debug` or
/// `Display`; its slot is wiped when it is dropped.
pub struct InstanceKey {
    key: SymmetricKey,
    version: u32,
}

impl HoldsKey for InstanceKey {
    const ROLE: Option<Role> = Some(Role::InstanceKey);

    fn symmetric(&self, _: Token) -> &SymmetricKey {
        &self.key
    }
}

impl InstanceKey {
    /// The instance key of version `version`, read from the Core's systemd credential at `path`
    /// straight into a slot of the locked pool, after the Core's start order
    /// ([`start_key_memory`](crate::start_key_memory)): [`CryptoError::KeyMemory`] while no pool
    /// is locked, [`CryptoError::Credential`] when the file cannot be read, and
    /// [`CryptoError::CredentialLength`] unless it holds exactly 32 bytes.
    pub fn from_credential(path: &Path, version: u32) -> Result<Self, CryptoError> {
        Ok(Self {
            key: key_from_credential(path)?,
            version,
        })
    }

    /// The version of the instance key, which its home partition root carries.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The root of the home partition, `vilicus/v1/partition/home` (D53): it carries the instance
    /// key's version.
    pub fn home_partition_root(&self) -> Result<HomePartitionRoot, CryptoError> {
        let key = derive_child!(self, Self, HOME_PARTITION_ROOT, &[])?;
        Ok(HomePartitionRoot {
            key,
            version: self.version,
        })
    }

    /// The SQLCipher key of `core.db`, `vilicus/v1/core/db` (D9).
    pub fn core_metadata_key(&self) -> Result<DatabaseKey, CryptoError> {
        let key = derive_child!(self, Self, CORE_METADATA_KEY, &[])?;
        Ok(DatabaseKey {
            key,
            database: Database::CoreMetadata,
        })
    }
}

/// The audit key (D114): the key of `audit.db`, and later of the audit log's HMAC chain and the
/// backup manifest's MAC. Not `Clone`, `Debug` or `Display`; its slot is wiped when it is dropped.
pub struct AuditKey {
    key: SymmetricKey,
}

impl HoldsKey for AuditKey {
    const ROLE: Option<Role> = Some(Role::AuditKey);

    fn symmetric(&self, _: Token) -> &SymmetricKey {
        &self.key
    }
}

impl AuditKey {
    /// The audit key, read from the audit writer's credential at `path` as
    /// [`InstanceKey::from_credential`] reads the instance key.
    pub fn from_credential(path: &Path) -> Result<Self, CryptoError> {
        Ok(Self {
            key: key_from_credential(path)?,
        })
    }

    /// The SQLCipher key of `audit.db`, `vilicus/v1/audit/db` (D114).
    pub fn database_key(&self) -> Result<DatabaseKey, CryptoError> {
        let key = derive_child!(self, Self, AUDIT_DATABASE_KEY, &[])?;
        Ok(DatabaseKey {
            key,
            database: Database::Audit,
        })
    }
}

/// A partition root (`doc/key-management.md` section 2): the member DEK of a personal partition,
/// the household key, or the home partition root. The key of each module file of its partition
/// derives from it ([`file_key`](Self::file_key)). Sealed: the roots are this crate's types.
pub trait PartitionRoot: HoldsKey {
    /// The partition this root opens.
    fn partition(&self) -> Partition;

    /// The version of this root, the first half of a file's key epoch.
    fn version(&self) -> u32;

    /// The SQLCipher key of `module`'s file of this root's partition at `generation`, derived with
    /// HKDF-SHA-256 under `vilicus/v1/db/`, the context being the module's name, the partition (a
    /// kind byte, then the member id for a personal partition), this root's version and the
    /// generation, each a `u32` big-endian. No other module, partition, root version or generation
    /// derives the same key.
    ///
    /// ```
    /// use vilicus_crypto::{MemberDek, PartitionRoot};
    /// use vilicus_types::{ModuleName, Partition};
    /// # vilicus_crypto::harden_process()?;
    /// # vilicus_crypto::lock_key_memory()?;
    /// let member = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f".parse()?;
    /// let dek = MemberDek::generate(member, 1)?;
    /// let key = dek.file_key(&ModuleName::from_static("tasks"), 0)?;
    /// assert_eq!(key.partition(), Partition::Member(member));
    /// assert_eq!((key.partition_root_version(), key.generation()), (1, 0));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn file_key(&self, module: &ModuleName, generation: u32) -> Result<FileKey, CryptoError>;
}

/// The parts of a module file key's context after the module's name: the partition, encoded as a
/// kind byte then, for a personal partition, the member id (the first `len` bytes of the array),
/// the root version and the generation.
fn file_key_context(
    partition: Partition,
    version: u32,
    generation: u32,
) -> ([u8; 17], usize, [u8; 4], [u8; 4]) {
    let mut encoded = [0_u8; 17];
    let len = match partition {
        Partition::Household => {
            encoded[0] = 0x01;
            1
        }
        Partition::Home => {
            encoded[0] = 0x02;
            1
        }
        Partition::Member(member) => {
            encoded[0] = 0x03;
            encoded[1..].copy_from_slice(&member.to_bytes());
            17
        }
    };
    (
        encoded,
        len,
        version.to_be_bytes(),
        generation.to_be_bytes(),
    )
}

/// The file key of `$root`, a `$root_type`, under `$derivation`, for `$module` at `$generation`.
macro_rules! file_key_of {
    ($root:expr, $root_type:ty, $derivation:expr, $module:expr, $generation:expr) => {{
        let partition = $root.partition();
        let version = $root.version();
        let (encoded, len, version_bytes, generation_bytes) =
            file_key_context(partition, version, $generation);
        let key = derive_child!(
            $root,
            $root_type,
            $derivation,
            &[
                $module.as_str().as_bytes(),
                &encoded[..len],
                &version_bytes,
                &generation_bytes
            ]
        )?;
        Ok(FileKey {
            key,
            module: $module.clone(),
            partition,
            partition_root_version: version,
            generation: $generation,
        })
    }};
}

/// A member's DEK (D4): the root of their personal partition, wrapped once per KEK in
/// `wrappers.db`. Not `Clone`, `Debug` or `Display`; its slot is wiped when it is dropped.
pub struct MemberDek {
    key: SymmetricKey,
    member: Id,
    version: u32,
}

impl HoldsKey for MemberDek {
    const ROLE: Option<Role> = Some(Role::MemberDek);

    fn symmetric(&self, _: Token) -> &SymmetricKey {
        &self.key
    }
}

impl MemberDek {
    /// A new DEK of version `version` for `member`, drawn from the CSPRNG of aws-lc-rs into a slot
    /// of the locked pool (`doc/key-management.md` section 3, step 4).
    pub fn generate(member: Id, version: u32) -> Result<Self, CryptoError> {
        Ok(Self {
            key: SymmetricKey::generate()?,
            member,
            version,
        })
    }

    #[cfg(feature = "testing")]
    pub(crate) fn from_key(key: SymmetricKey, member: Id, version: u32) -> Self {
        Self {
            key,
            member,
            version,
        }
    }

    /// The member whose personal partition this DEK opens.
    pub fn member(&self) -> Id {
        self.member
    }

    /// The context of the member's DEK wrappers: the member id, then the DEK version as a `u32`
    /// big-endian.
    fn wrap_context(member: Id, version: u32) -> [u8; 20] {
        let mut context = [0_u8; 20];
        context[..16].copy_from_slice(&member.to_bytes());
        context[16..].copy_from_slice(&version.to_be_bytes());
        context
    }

    /// Wraps this DEK under `kek` with `params`, for the purpose `vilicus/v1/wrap/member-dek`, bound
    /// to the member and the DEK version: a wrapper opens only as this member's DEK of this version.
    pub fn wrap(&self, kek: &SymmetricKey, params: WrapParams) -> Result<Wrapper, CryptoError> {
        Wrapper::wrap_key(
            kek,
            &self.key,
            MEMBER_DEK_WRAP,
            params,
            &Self::wrap_context(self.member, self.version),
        )
    }

    /// Opens `wrapper` with `kek` as `member`'s DEK of version `version`: a wrong KEK, another
    /// member or version, or an edited wrapper is [`CryptoError::Open`].
    pub fn unwrap(
        wrapper: &Wrapper,
        kek: &SymmetricKey,
        member: Id,
        version: u32,
    ) -> Result<Self, CryptoError> {
        let key = wrapper.unwrap_key(kek, MEMBER_DEK_WRAP, &Self::wrap_context(member, version))?;
        Ok(Self {
            key,
            member,
            version,
        })
    }
}

impl PartitionRoot for MemberDek {
    fn partition(&self) -> Partition {
        Partition::Member(self.member)
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn file_key(&self, module: &ModuleName, generation: u32) -> Result<FileKey, CryptoError> {
        file_key_of!(self, Self, PERSONAL_FILE_KEY, module, generation)
    }
}

/// The household key (HK): the root of the household partition, versioned. It is created and
/// wrapped to each adult with HPKE by the household key's own path (Story 4.6), which no public
/// constructor here stands in for. Not `Clone`, `Debug` or `Display`; its slot is wiped when it is
/// dropped.
pub struct HouseholdKey {
    key: SymmetricKey,
    version: u32,
}

impl HoldsKey for HouseholdKey {
    const ROLE: Option<Role> = Some(Role::HouseholdKey);

    fn symmetric(&self, _: Token) -> &SymmetricKey {
        &self.key
    }
}

impl HouseholdKey {
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn from_key(key: SymmetricKey, version: u32) -> Self {
        Self { key, version }
    }

    /// The MAC key of the `wrappers.db` record set under this household key,
    /// `vilicus/v1/hk/wrappers-set-mac/` with the household key version in its context (gate
    /// AD36-1).
    pub fn wrapper_set_key(&self) -> Result<WrapperSetKey, CryptoError> {
        let key = derive_child!(self, Self, WRAPPER_SET_KEY, &[&self.version.to_be_bytes()])?;
        Ok(WrapperSetKey::from_key(key, self.version))
    }
}

impl PartitionRoot for HouseholdKey {
    fn partition(&self) -> Partition {
        Partition::Household
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn file_key(&self, module: &ModuleName, generation: u32) -> Result<FileKey, CryptoError> {
        file_key_of!(self, Self, HOUSEHOLD_FILE_KEY, module, generation)
    }
}

/// The root of the home partition (D53), derived from the instance key, so the house runs while
/// every member is locked. Not `Clone`, `Debug` or `Display`; its slot is wiped when it is dropped.
pub struct HomePartitionRoot {
    key: SymmetricKey,
    version: u32,
}

impl HoldsKey for HomePartitionRoot {
    const ROLE: Option<Role> = Some(Role::HomePartitionRoot);

    fn symmetric(&self, _: Token) -> &SymmetricKey {
        &self.key
    }
}

impl PartitionRoot for HomePartitionRoot {
    fn partition(&self) -> Partition {
        Partition::Home
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn file_key(&self, module: &ModuleName, generation: u32) -> Result<FileKey, CryptoError> {
        file_key_of!(self, Self, HOME_FILE_KEY, module, generation)
    }
}

/// The SQLCipher key of one module file, `<module>.<partition>.db`, at one key epoch (D3, AD-5):
/// what the Core keys the file's connections with, through
/// [`with_sqlcipher_key_text`](Self::with_sqlcipher_key_text). Not `Clone`, `Debug` or `Display`;
/// its slot is wiped when it is dropped.
pub struct FileKey {
    key: SymmetricKey,
    module: ModuleName,
    partition: Partition,
    partition_root_version: u32,
    generation: u32,
}

impl HoldsKey for FileKey {
    const ROLE: Option<Role> = None;

    fn symmetric(&self, _: Token) -> &SymmetricKey {
        &self.key
    }
}

impl FileKey {
    /// The module whose file this key opens.
    pub fn module(&self) -> &ModuleName {
        &self.module
    }

    /// The partition whose file this key opens.
    pub fn partition(&self) -> Partition {
        self.partition
    }

    /// The version of the partition root this key derives from: the first half of its key epoch.
    pub fn partition_root_version(&self) -> u32 {
        self.partition_root_version
    }

    /// The file generation this key derives for: the second half of its key epoch.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    #[cfg(test)]
    pub(crate) fn role(&self) -> Role {
        Role::FileKey(PartitionKind::of(self.partition))
    }

    /// Lends SQLCipher's raw key text of this key to `operation`, as
    /// [`SymmetricKey::with_sqlcipher_key_text`] does.
    pub fn with_sqlcipher_key_text<R>(
        &self,
        operation: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, CryptoError> {
        self.key.with_sqlcipher_key_text(operation)
    }
}

/// The Core databases that are not module files, each keyed from a key of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Database {
    /// `core.db`, under the instance key (D9).
    CoreMetadata,
    /// `audit.db`, under the audit key (D114).
    Audit,
}

/// The SQLCipher key of `core.db` or `audit.db`. Not `Clone`, `Debug` or `Display`; its slot is
/// wiped when it is dropped.
pub struct DatabaseKey {
    key: SymmetricKey,
    database: Database,
}

impl HoldsKey for DatabaseKey {
    const ROLE: Option<Role> = None;

    fn symmetric(&self, _: Token) -> &SymmetricKey {
        &self.key
    }
}

impl DatabaseKey {
    /// The database this key opens.
    pub fn database(&self) -> Database {
        self.database
    }

    /// Lends SQLCipher's raw key text of this key to `operation`, as
    /// [`SymmetricKey::with_sqlcipher_key_text`] does.
    pub fn with_sqlcipher_key_text<R>(
        &self,
        operation: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, CryptoError> {
        self.key.with_sqlcipher_key_text(operation)
    }
}

#[cfg(test)]
mod tests;
