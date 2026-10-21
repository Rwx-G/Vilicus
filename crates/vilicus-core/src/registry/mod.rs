//! The module registry (FR-22, AD-9): the modules compiled into the binary, with their schema,
//! migrations, record kinds, tools and event topics, the checks that hold every module file to
//! its declaration, and the capability matrix check that holds every tool to its row of
//! `doc/capability-matrix.md` ([`CapabilityMatrix`]). Each consumer of an event consumes a topic
//! a registered module emits, whose access list names the consumer's module (D20): the registry
//! is where the access lists of every topic decide which consumers its events reach.
//!
//! A [`Registry`] is built from a `'static` list of [`ModuleDeclaration`]s by a `const fn`, so a
//! binary builds it in a `const` item from the declarations it names at build time, and a
//! declaration the registry refuses stops the build. It has no method that adds a module once it
//! is built. Nothing stops code from calling the `const fn` at run time on a list it leaked, as
//! the tests do: the guarantee is that the binary's registry is a `const` item, which a review of
//! the binary sees, not a property of the type.
//!
//! ```
//! use vilicus_core::registry::Registry;
//! use vilicus_module_api::ModuleDeclaration;
//!
//! const NOTES: ModuleDeclaration = ModuleDeclaration {
//!     name: "notes",
//!     tables: &[],
//!     fts5_tables: &[],
//!     migrations: &[],
//!     matrix_sections: &[],
//!     topics: &[],
//!     consumers: &[],
//!     tools: &[],
//!     queries: &[],
//! };
//! const REGISTRY: Registry = match Registry::new(&[&NOTES]) {
//!     Ok(registry) => registry,
//!     Err(error) => panic!("{}", error.rule()),
//! };
//! assert_eq!(REGISTRY.modules().len(), 1);
//! ```
//!
//! The declaration rules themselves are `vilicus-module-api`'s; the registry adds the
//! comparison of each declaration with the schema its migrations produce in a file, in the
//! build-time test ([`Registry::verify_migrations`]) and whenever the Core opens a file. Opening
//! a file is the Core's alone: no crate outside it gets a handle, whose raw SQL would skip the
//! validation of every write (FR-58).
//!
//! ```compile_fail,E0624
//! fn open(
//!     registry: &vilicus_core::registry::Registry,
//!     file: &vilicus_storage::ModuleFile,
//! ) {
//!     let _ = registry.open::<vilicus_storage::Write>(file, &[0; 32]);
//! }
//! ```

mod fts5;
mod matrix;
mod migrate;
mod schema;
mod sql;

#[cfg(test)]
mod tests;

use core::fmt;
use std::path::Path;

use vilicus_module_api::{Consumer, DeclarationError, ModuleDeclaration, Topic};
use vilicus_storage::maintenance::SchemaVersions;
use vilicus_storage::{
    CORE_SCHEMA_VERSION, FrozenMigration, Handle, Inspect, KeyEpoch, Migration, MigrationTrack,
    ModuleFile, Partition, Read,
};
use vilicus_types::ModuleName;

use crate::alert::InstanceAdminAlert;

pub use matrix::{
    CapabilityMatrix, MatrixCheckError, MatrixDifference, MatrixEntry, MatrixError, MatrixSection,
    RegisteredTool, RowClass, RowTier,
};
#[cfg(test)]
pub(crate) use migrate::migration_code;
pub use migrate::{FileMigration, FileToMigrate, MigrationError, MigrationRunError};
pub use schema::SchemaError;

/// The modules compiled into the binary.
#[derive(Clone, Copy, Debug)]
pub struct Registry {
    modules: &'static [&'static ModuleDeclaration],
}

/// Why a registry cannot be built from its modules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// A module's declaration breaks a rule of the module contract.
    Declaration {
        /// The module, as it names itself.
        module: &'static str,
        /// The rule broken.
        error: DeclarationError,
    },
    /// Two modules share a name, so they would share files.
    DuplicateModule {
        /// The name.
        module: &'static str,
    },
    /// Two modules claim one capability matrix section, so neither alone answers for its rows.
    DuplicateMatrixSection {
        /// The second module that claims it.
        module: &'static str,
        /// The section.
        section: &'static str,
    },
    /// A consumer consumes a topic no registered module emits.
    UnknownTopic {
        /// The consumer's module.
        module: &'static str,
        /// The topic.
        topic: &'static str,
    },
    /// A consumer consumes a topic whose access list does not name its module (D20).
    ConsumerNotAllowed {
        /// The consumer's module.
        module: &'static str,
        /// The topic.
        topic: &'static str,
    },
}

impl RegistryError {
    /// The rule broken, without the names: the message a `const` registry stops the build with.
    pub const fn rule(self) -> &'static str {
        match self {
            Self::Declaration { error, .. } => error.rule(),
            Self::DuplicateModule { .. } => "two modules share a name",
            Self::DuplicateMatrixSection { .. } => "two modules claim a capability matrix section",
            Self::UnknownTopic { .. } => "a consumer consumes a topic no module emits",
            Self::ConsumerNotAllowed { .. } => {
                "a consumer consumes a topic whose access list does not name its module"
            }
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Declaration { module, error } => write!(formatter, "module {module}: {error}"),
            Self::DuplicateModule { module } => {
                write!(formatter, "{}: {module}", self.rule())
            }
            Self::DuplicateMatrixSection { module, section } => {
                write!(formatter, "{}: {module} (section {section})", self.rule())
            }
            Self::UnknownTopic { module, topic } | Self::ConsumerNotAllowed { module, topic } => {
                write!(formatter, "{}: {module} ({topic})", self.rule())
            }
        }
    }
}

impl std::error::Error for RegistryError {}

/// Why the Core refuses a module file.
#[derive(Debug)]
#[non_exhaustive]
pub enum FileError {
    /// The file belongs to no registered module.
    UnregisteredModule(ModuleName),
    /// The storage layer failed to open or read the file.
    Storage(vilicus_storage::Error),
    /// The file's Core track is older than the Core's code: its Core migrations are pending, and
    /// run before the module's (AD-26).
    CoreMigrationPending {
        /// The Core schema version of the file.
        found: u32,
        /// The version the Core's migrations bring a file to.
        latest: u32,
    },
    /// The file's Core track is newer than the Core's code (D21).
    CoreNewerThanCode {
        /// The Core schema version of the file.
        found: u32,
        /// The version the Core's migrations bring a file to.
        latest: u32,
    },
    /// The file's module schema is older than the module's code: its migrations are pending
    /// (AD-23, AD-54 `migrating`).
    MigrationPending {
        /// The schema version of the file.
        found: u32,
        /// The version the module's last migration brings a file to.
        latest: u32,
    },
    /// The file's module schema is newer than the module's code (D21, AD-54 `newer than code`).
    NewerThanCode {
        /// The schema version of the file.
        found: u32,
        /// The version the module's last migration brings a file to.
        latest: u32,
    },
    /// The file's schema differs from the module's declaration (AD-9).
    Schema(SchemaError),
    /// A migration was changed after it was frozen (AD-23, D21): its SQL no longer has the
    /// digest its frozen hash states, or the file ran a migration of that version whose frozen
    /// hash differs from the code's. No migration runs and the file is not opened.
    ChangedMigration {
        /// The track.
        track: MigrationTrack,
        /// The version.
        version: u32,
    },
}

impl fmt::Display for FileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnregisteredModule(module) => {
                write!(formatter, "module {module} is not registered")
            }
            Self::Storage(error) => write!(formatter, "{error}"),
            Self::CoreMigrationPending { found, latest } => write!(
                formatter,
                "the file's Core tables are at version {found}, the Core at {latest}: \
                 Core migrations pending"
            ),
            Self::CoreNewerThanCode { found, latest } => write!(
                formatter,
                "the file's Core tables are at version {found}, newer than the Core's {latest}"
            ),
            Self::MigrationPending { found, latest } => write!(
                formatter,
                "the file is at schema version {found}, its module at {latest}: migrations pending"
            ),
            Self::NewerThanCode { found, latest } => write!(
                formatter,
                "the file is at schema version {found}, newer than its module's {latest}"
            ),
            Self::Schema(error) => write!(formatter, "the file's schema differs: {error}"),
            Self::ChangedMigration { track, version } => write!(
                formatter,
                "{track} migration {version} differs from its frozen hash or from the one the \
                 file ran"
            ),
        }
    }
}

impl FileError {
    /// The instance admin alert of a refusal that stops the module for `file`'s partition until
    /// a forward release: a file newer than the code (D21, AD-54 `newer than code`). Other
    /// refusals are pending work or a defect of the file, reported by the migration runner.
    pub fn admin_alert(&self, file: &ModuleFile) -> Option<InstanceAdminAlert> {
        match *self {
            Self::CoreNewerThanCode { found, latest } => Some(InstanceAdminAlert::newer_than_code(
                file,
                MigrationTrack::Core,
                found,
                latest,
            )),
            Self::NewerThanCode { found, latest } => Some(InstanceAdminAlert::newer_than_code(
                file,
                MigrationTrack::Module,
                found,
                latest,
            )),
            _ => None,
        }
    }
}

impl std::error::Error for FileError {}

impl From<vilicus_storage::Error> for FileError {
    fn from(error: vilicus_storage::Error) -> Self {
        match error {
            vilicus_storage::Error::MigrationChanged { track, version } => {
                Self::ChangedMigration { track, version }
            }
            other => Self::Storage(other),
        }
    }
}

/// A module whose migrations do not produce its declared schema, found by
/// [`Registry::verify_migrations`].
#[derive(Debug)]
pub struct VerifyError {
    /// The module.
    pub module: &'static str,
    /// What failed.
    pub error: FileError,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "module {}: {}", self.module, self.error)
    }
}

impl std::error::Error for VerifyError {}

/// The key epoch of the scratch files the build-time test and the write path fuzz test build.
const VERIFY_EPOCH: KeyEpoch = KeyEpoch {
    partition_root_version: 1,
    generation: 0,
};

impl Registry {
    /// The registry of `modules`: every declaration is checked against the rules of the module
    /// contract, module names are unique and no two modules claim one capability matrix section.
    /// `const`, so a binary builds its registry in a `const` item and a refusal is a build error.
    pub const fn new(
        modules: &'static [&'static ModuleDeclaration],
    ) -> Result<Self, RegistryError> {
        let mut index = 0;
        while index < modules.len() {
            let module = modules[index];
            if let Err(error) = module.validate() {
                return Err(RegistryError::Declaration {
                    module: module.name,
                    error,
                });
            }
            let mut other = index + 1;
            while other < modules.len() {
                if same(module.name, modules[other].name) {
                    return Err(RegistryError::DuplicateModule {
                        module: module.name,
                    });
                }
                if let Some(section) = shared_section(module, modules[other]) {
                    return Err(RegistryError::DuplicateMatrixSection {
                        module: modules[other].name,
                        section,
                    });
                }
                other += 1;
            }
            index += 1;
        }
        index = 0;
        while index < modules.len() {
            let module = modules[index];
            let mut consumer = 0;
            while consumer < module.consumers.len() {
                if let Err(error) = check_consumer(modules, module, &module.consumers[consumer]) {
                    return Err(error);
                }
                consumer += 1;
            }
            index += 1;
        }
        Ok(Self { modules })
    }

    /// The topic named `name`, with the module that emits it.
    pub fn topic(&self, name: &str) -> Option<(&'static ModuleDeclaration, &'static Topic)> {
        self.modules
            .iter()
            .find_map(|&module| module.topic(name).map(|topic| (module, topic)))
    }

    /// The consumers the events of `topic`, emitted by `emitter`, reach: the consumer of the topic
    /// of each module its access list names, in the order of that list (D20). Empty when the
    /// emitter no longer declares the topic.
    pub fn receivers(
        &self,
        emitter: &ModuleDeclaration,
        topic: &str,
    ) -> Vec<(&'static ModuleDeclaration, &'static Consumer)> {
        let Some(declared) = emitter.topic(topic) else {
            return Vec::new();
        };
        declared
            .consumers
            .iter()
            .filter_map(|name| {
                self.modules
                    .iter()
                    .find(|module| module.name == *name)
                    .and_then(|&module| {
                        module.consumer_of(topic).map(|consumer| (module, consumer))
                    })
            })
            .collect()
    }

    /// The registry's tool table: every tool of every module, in declaration order. The
    /// capability matrix check compares it with `doc/capability-matrix.md`.
    pub fn tools(&self) -> impl Iterator<Item = RegisteredTool> + '_ {
        self.modules.iter().flat_map(|&module| {
            module
                .tools
                .iter()
                .map(move |tool| RegisteredTool { module, tool })
        })
    }

    /// The registered modules: each one's tables (record kinds with their data types and
    /// fields), FTS5 tables and migrations.
    pub const fn modules(&self) -> &'static [&'static ModuleDeclaration] {
        self.modules
    }

    /// The registered module named `name`.
    pub fn module(&self, name: &ModuleName) -> Option<&'static ModuleDeclaration> {
        self.modules
            .iter()
            .copied()
            .find(|module| module.name == name.as_str())
    }

    /// Opens `file` in role `R` with its raw `key`, after checking it against its module's
    /// declaration (AD-9): the module is registered, the file's Core tables are at the Core's
    /// schema version and its module schema at the module's latest version (AD-26), the frozen
    /// hashes it recorded for both tracks are the code's (AD-23, D21), and its schema is the
    /// declared one. Each refusal is a typed
    /// [`FileError`]; the handle is closed before the error is returned. Crate-private: a handle
    /// executes raw SQL, so outside the Core it would write around field validation.
    pub(crate) fn open<R: Inspect>(
        &self,
        file: &ModuleFile,
        key: &[u8; 32],
    ) -> Result<Handle<R>, FileError> {
        let module = self
            .module(file.module())
            .ok_or_else(|| FileError::UnregisteredModule(file.module().clone()))?;
        let handle = vilicus_storage::open::<R>(file, key)?;
        check(module, &handle)?;
        Ok(handle)
    }

    /// The build-time test of AD-9: for each module, checks the SHA-256 of each migration's SQL
    /// against its frozen hash, builds a new file under `directory` with `key`, applies the
    /// module's migrations in order through the migration runner, then opens it as the Core opens
    /// every file, comparing the migrated schema with the declaration.
    /// `directory` holds no file of these modules beforehand; the files stay there.
    pub fn verify_migrations(&self, directory: &Path, key: &[u8; 32]) -> Result<(), VerifyError> {
        for module in self.modules {
            verify_module(self, module, directory, key).map_err(|error| VerifyError {
                module: module.name,
                error,
            })?;
        }
        Ok(())
    }
}

fn verify_module(
    registry: &Registry,
    module: &'static ModuleDeclaration,
    directory: &Path,
    key: &[u8; 32],
) -> Result<(), FileError> {
    let file = create_migrated(module, directory, key)?;
    registry.open::<Read>(&file, key)?.close()?;
    Ok(())
}

/// Creates `module`'s file in the household partition under `directory` with `key`, which brings
/// its Core track to the Core's version, and applies the module's migrations in order through
/// the migration runner (Core first, then module, AD-26): the scratch file of the build-time test
/// and of the write path fuzz test.
pub(crate) fn create_migrated(
    module: &'static ModuleDeclaration,
    directory: &Path,
    key: &[u8; 32],
) -> Result<ModuleFile, FileError> {
    let file = ModuleFile::new(
        directory,
        ModuleName::from_static(module.name),
        Partition::Household,
    );
    let migrations = frozen_migrations(module)?;
    vilicus_storage::create(&file, key, VERIFY_EPOCH)?.close()?;
    let mut migration = vilicus_storage::open::<Migration>(&file, key)?;
    migration.apply_module_migrations(&migrations)?;
    migration.close()?;
    Ok(file)
}

/// The module's migrations as the runner takes them, once the check of AD-23 and D21 passed:
/// the SQL of each of the Core's own migrations, then of each of the module's, has the SHA-256
/// its frozen hash states. The first that does not is [`FileError::ChangedMigration`]: a
/// migration edited after it was frozen never runs.
pub(crate) fn frozen_migrations(
    module: &'static ModuleDeclaration,
) -> Result<Vec<FrozenMigration<'static>>, FileError> {
    let core = vilicus_storage::core_migrations();
    let module_migrations: Vec<FrozenMigration<'static>> = module
        .migrations
        .iter()
        .map(|migration| FrozenMigration {
            sql: migration.sql,
            sha256: migration.sha256,
        })
        .collect();
    for (track, migrations) in [
        (MigrationTrack::Core, core),
        (MigrationTrack::Module, module_migrations.as_slice()),
    ] {
        for (version, migration) in (1..).zip(migrations) {
            if vilicus_crypto::sha256(migration.sql.as_bytes()) != migration.sha256 {
                return Err(FileError::ChangedMigration { track, version });
            }
        }
    }
    Ok(module_migrations)
}

/// Refuses a file at `versions` whose record of frozen hashes, for either track, is not that of
/// the code's migrations up to those versions (AD-23, D21): the Core's own for the Core track,
/// `module`'s for the module track. The versions are within the code's.
pub(crate) fn check_recorded_tracks<R: Inspect>(
    handle: &Handle<R>,
    module: &ModuleDeclaration,
    versions: SchemaVersions,
) -> Result<(), FileError> {
    let core: Vec<[u8; 32]> = vilicus_storage::core_migrations()
        .iter()
        .take(versions.core as usize)
        .map(|migration| migration.sha256)
        .collect();
    check_recorded(handle, MigrationTrack::Core, &core)?;
    let module: Vec<[u8; 32]> = module
        .migrations
        .iter()
        .take(versions.module as usize)
        .map(|migration| migration.sha256)
        .collect();
    check_recorded(handle, MigrationTrack::Module, &module)
}

/// Refuses a file whose record of `track` is not the frozen hashes of `migrations`: the first
/// version that differs, or that one side holds and the other does not.
fn check_recorded<R: Inspect>(
    handle: &Handle<R>,
    track: MigrationTrack,
    migrations: &[[u8; 32]],
) -> Result<(), FileError> {
    let recorded = handle.migration_hashes(track)?;
    match (1..)
        .zip(migrations.iter().map(Some).chain([None]))
        .zip(recorded.iter().map(Some).chain([None]))
        .find_map(|((version, frozen), record)| (frozen != record).then_some(version))
    {
        None => Ok(()),
        Some(version) => Err(FileError::ChangedMigration { track, version }),
    }
}

/// The checks of `Registry::open` on an open handle.
fn check<R: Inspect>(module: &ModuleDeclaration, handle: &Handle<R>) -> Result<(), FileError> {
    let core = handle.schema_version(MigrationTrack::Core)?;
    if core < CORE_SCHEMA_VERSION {
        return Err(FileError::CoreMigrationPending {
            found: core,
            latest: CORE_SCHEMA_VERSION,
        });
    }
    if core > CORE_SCHEMA_VERSION {
        return Err(FileError::CoreNewerThanCode {
            found: core,
            latest: CORE_SCHEMA_VERSION,
        });
    }
    let found = handle.schema_version(MigrationTrack::Module)?;
    let latest = module.latest_version();
    if found < latest {
        return Err(FileError::MigrationPending { found, latest });
    }
    if found > latest {
        return Err(FileError::NewerThanCode { found, latest });
    }
    check_recorded_tracks(
        handle,
        module,
        SchemaVersions {
            core,
            module: found,
        },
    )?;
    let snapshot = schema::Snapshot::read(handle, module)?;
    schema::compare(module, &snapshot).map_err(FileError::Schema)
}

/// `sql` as a migration of a test declaration, frozen with the SHA-256 of its text.
#[cfg(test)]
pub(crate) fn frozen(sql: &'static str) -> vilicus_module_api::Migration {
    vilicus_module_api::Migration {
        sql,
        sha256: vilicus_crypto::sha256(sql.as_bytes()),
    }
}

/// Refuses `consumer` of `module` unless a module of `modules` emits its topic and that topic's
/// access list names `module` (D20).
const fn check_consumer(
    modules: &[&'static ModuleDeclaration],
    module: &'static ModuleDeclaration,
    consumer: &'static Consumer,
) -> Result<(), RegistryError> {
    let mut index = 0;
    while index < modules.len() {
        let emitter = modules[index];
        let mut topic = 0;
        while topic < emitter.topics.len() {
            let declared = &emitter.topics[topic];
            if same(declared.name, consumer.topic) {
                let mut entry = 0;
                while entry < declared.consumers.len() {
                    if same(declared.consumers[entry], module.name) {
                        return Ok(());
                    }
                    entry += 1;
                }
                return Err(RegistryError::ConsumerNotAllowed {
                    module: module.name,
                    topic: consumer.topic,
                });
            }
            topic += 1;
        }
        index += 1;
    }
    Err(RegistryError::UnknownTopic {
        module: module.name,
        topic: consumer.topic,
    })
}

/// A capability matrix section both modules claim.
const fn shared_section(
    module: &ModuleDeclaration,
    other: &ModuleDeclaration,
) -> Option<&'static str> {
    let mut index = 0;
    while index < module.matrix_sections.len() {
        let mut candidate = 0;
        while candidate < other.matrix_sections.len() {
            if same(
                module.matrix_sections[index],
                other.matrix_sections[candidate],
            ) {
                return Some(module.matrix_sections[index]);
            }
            candidate += 1;
        }
        index += 1;
    }
    None
}

const fn same(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}
