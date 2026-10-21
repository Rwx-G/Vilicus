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
//! [`Handle::apply_module_migrations`] and [`Handle::apply_core_migrations`], which record each
//! track's schema version in `_meta` and the frozen hash of each migration in `_migrations`,
//! [`FrozenMigration`]).
//! Read and write handles also read the file's [`Schema`], which the module registry compares
//! with its declarations, and the confirmed labels of its reviewed vocabularies, which a write
//! handle records in the Core table `_vocabulary` (D104). Copies and VACUUM run on the Core
//! maintenance path ([`maintenance`]). SQLCipher is compiled by this crate's build script from
//! the amalgamation in `sqlcipher/` (D143).
//!
//! The Core tables of a file ([`CORE_TABLES`]) other than `_meta` are made by the Core migration
//! track, before the module's (AD-26). A write handle writes their rows with the Core's own
//! statements only: the journal of each record a call changes and its retention purge
//! ([`JournalEntry`], [`Handle::purge_journal`]), effect intents and their outcomes
//! ([`EffectIntent`], AD-28), events and link requests with the state of each event's delivery
//! to each consumer, its dead letters and the outbox's retention purge ([`EventIntent`],
//! [`LinkIntent`], [`Handle::purge_outbox`], AD-10, AD-29), consumed events, and wrapped record
//! keys, whose destruction shreds a record ([`Handle::destroy_wrapped_record_key`], D132).

mod authorizer;
mod core_schema;
mod error;
mod event;
mod ffi;
mod file;
mod handle;
mod journal;
pub mod maintenance;
mod migration;
mod migration_copy;
mod outbox;
mod record_key;
mod schema;

pub use authorizer::{CORE_PRIVATE_TABLES, CORE_TABLES};
pub use core_schema::{CORE_SCHEMA_VERSION, core_migrations};
pub use error::{Error, Result, is_refusal};
pub use event::{
    DeadLetter, DeliveryRow, DeliveryState, EventIntent, EventRow, LinkIntent, LinkRow,
    OutboxPurge, OutboxRow, OutboxState,
};
pub use file::{KeyEpoch, ModuleFile, Partition, read_epoch};
pub use handle::{
    BUSY_TIMEOUT, CHECKPOINT_ATTEMPTS, Handle, Inspect, JOURNAL_SIZE_LIMIT, Migration,
    MigrationTrack, Read, Role, RoleKind, Settings, Write, create, open,
};
pub use journal::{AuthorityKind, CallKey, JournalEntry, JournalPurge, JournalRow};
pub use migration::FrozenMigration;
pub use outbox::{EffectIntent, EffectRow, EffectState};
pub use record_key::Shredded;
pub use schema::{
    ColumnInfo, ForeignKey, IndexColumn, IndexInfo, Schema, SchemaObject, TableInfo, TableKind,
};

/// A value in one of SQLite's storage classes, as [`Handle::execute_values`] binds it and
/// [`Handle::query_values`] reads it back.
pub use rusqlite::types::Value as SqlValue;

#[cfg(test)]
mod tests;
