//! The module registry (FR-22, AD-9): the modules compiled into the binary, with their schema,
//! migrations, record kinds and tools, the checks that hold every module file to its declaration,
//! and the capability matrix check that holds every tool to its row of
//! `doc/capability-matrix.md` ([`CapabilityMatrix`]).
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
//!     tools: &[],
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
//! build-time test ([`Registry::verify_migrations`]) and whenever the Core opens a file
//! ([`Registry::open`]).

mod fts5;
mod matrix;
mod schema;
mod sql;

#[cfg(test)]
mod tests;

use core::fmt;
use std::path::Path;

use vilicus_module_api::{DeclarationError, ModuleDeclaration};
use vilicus_storage::{
    Handle, Inspect, KeyEpoch, Migration, MigrationTrack, ModuleFile, Partition, Read,
};
use vilicus_types::ModuleName;

pub use matrix::{
    CapabilityMatrix, MatrixCheckError, MatrixDifference, MatrixEntry, MatrixError, MatrixSection,
    RegisteredTool, RowClass, RowTier,
};
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
}

impl RegistryError {
    /// The rule broken, without the names: the message a `const` registry stops the build with.
    pub const fn rule(self) -> &'static str {
        match self {
            Self::Declaration { error, .. } => error.rule(),
            Self::DuplicateModule { .. } => "two modules share a name",
            Self::DuplicateMatrixSection { .. } => "two modules claim a capability matrix section",
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
}

impl fmt::Display for FileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnregisteredModule(module) => {
                write!(formatter, "module {module} is not registered")
            }
            Self::Storage(error) => write!(formatter, "{error}"),
            Self::MigrationPending { found, latest } => write!(
                formatter,
                "the file is at schema version {found}, its module at {latest}: migrations pending"
            ),
            Self::NewerThanCode { found, latest } => write!(
                formatter,
                "the file is at schema version {found}, newer than its module's {latest}"
            ),
            Self::Schema(error) => write!(formatter, "the file's schema differs: {error}"),
        }
    }
}

impl std::error::Error for FileError {}

impl From<vilicus_storage::Error> for FileError {
    fn from(error: vilicus_storage::Error) -> Self {
        Self::Storage(error)
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

/// The key epoch of the scratch files [`Registry::verify_migrations`] and
/// [`Registry::fuzz_write_paths`] build.
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
        Ok(Self { modules })
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
    /// declaration (AD-9): the module is registered, the file's module schema is at the module's
    /// latest version, and its schema is the declared one. Each refusal is a typed
    /// [`FileError`]; the handle is closed before the error is returned.
    pub fn open<R: Inspect>(
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

    /// The build-time test of AD-9: for each module, builds a new file under `directory` with
    /// `key`, applies the module's migrations in order through the migration runner, then opens
    /// it through [`open`](Self::open), which compares the migrated schema with the declaration.
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

/// Creates `module`'s file in the household partition under `directory` with `key`, and applies
/// its migrations in order through the migration runner: the scratch file of the build-time
/// test and of the write path fuzz test.
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
    vilicus_storage::create(&file, key, VERIFY_EPOCH)?.close()?;
    let mut migration = vilicus_storage::open::<Migration>(&file, key)?;
    let mut version = 0;
    for step in module.migrations {
        version += 1;
        migration.apply_versioned_migration(MigrationTrack::Module, version, step.sql)?;
    }
    migration.close()?;
    Ok(file)
}

/// The checks of [`Registry::open`] on an open handle.
fn check<R: Inspect>(module: &ModuleDeclaration, handle: &Handle<R>) -> Result<(), FileError> {
    let found = handle.schema_version(MigrationTrack::Module)?;
    let latest = module.latest_version();
    if found < latest {
        return Err(FileError::MigrationPending { found, latest });
    }
    if found > latest {
        return Err(FileError::NewerThanCode { found, latest });
    }
    let snapshot = schema::Snapshot::read(handle, module)?;
    schema::compare(module, &snapshot).map_err(FileError::Schema)
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
