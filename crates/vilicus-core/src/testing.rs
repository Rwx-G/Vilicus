//! What the testbed's tests name of the storage layer, which no crate but the Core may depend on
//! (AD-3, D140): the files they create and bring up, the identity of a call's journal and outbox
//! rows, and the states those rows stand in. Compiled with the `testing` feature only, which
//! ci/check_packaging.py refuses in a release artefact (D102).
//!
//! It opens no file: the testbed's tests reach a module file's handles through the Core's own
//! paths, a partition's bring-up ([`bring_up`](crate::startup::bring_up)), as the gates that run
//! against it need.

pub use vilicus_storage::{
    CORE_SCHEMA_VERSION, CallKey, DeliveryState, EffectState, Error as StorageError, KeyEpoch,
    MigrationTrack, ModuleFile, OutboxState, Partition, SqlValue,
};

/// Creates `file`, a new module file whose Core track is at the Core's version and whose module
/// track has run nothing, keyed with `key` at `epoch`, and closes it: what a partition's bring-up
/// then migrates to its module's versions.
pub fn create_module_file(
    file: &ModuleFile,
    key: &[u8; 32],
    epoch: KeyEpoch,
) -> Result<(), StorageError> {
    vilicus_storage::create(file, key, epoch)?.close()
}
