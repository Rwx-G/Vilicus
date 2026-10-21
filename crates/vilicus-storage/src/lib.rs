//! SQLCipher handles, the SQLite authorizer and the migrations runner of Vilicus.
//!
//! A dependency of `vilicus-core` only: modules reach their file through the typed record API
//! and read handles the Core gives them, never through this crate (`doc/architecture-spine.md`,
//! AD-3, AD-5, AD-9 and AD-23). Unsafe code is allowed here for the SQLite calls D140 names,
//! per block and with a `// SAFETY:` comment, all in one private module.
//!
//! One SQLCipher file per module per partition, `<module>.<partition>.db`, keyed with its raw
//! 256-bit key ([`ModuleFile`], [`open`], [`create`]). Every connection is set up before its
//! authorizer goes on and reads every setting back ([`Settings`]); a [`Handle`] then runs in one
//! role, [`Read`] (`SELECT` only), [`Write`] (rows only) or [`Migration`] (closed outside
//! [`Handle::apply_versioned_migration`], which records each track's schema version in `_meta`). Read and write handles also read the file's [`Schema`],
//! which the module registry compares with its declarations. Copies and VACUUM run on the Core
//! maintenance path ([`maintenance`]). SQLCipher is compiled by this crate's build script from
//! the amalgamation in `sqlcipher/` (D143).

mod authorizer;
mod error;
mod ffi;
mod file;
mod handle;
pub mod maintenance;
mod schema;

pub use authorizer::CORE_TABLES;
pub use error::{Error, Result, is_refusal};
pub use file::{KeyEpoch, ModuleFile, Partition, read_epoch};
pub use handle::{
    BUSY_TIMEOUT, Handle, Inspect, JOURNAL_SIZE_LIMIT, Migration, MigrationTrack, Read, Role,
    RoleKind, Settings, Write, create, open,
};
pub use schema::{
    ColumnInfo, ForeignKey, IndexColumn, IndexInfo, Schema, SchemaObject, TableInfo, TableKind,
};

#[cfg(test)]
mod tests;
