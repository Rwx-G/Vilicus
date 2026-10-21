//! Wrapped record keys and crypto-shredding (`doc/architecture.md` section 5.1, D132, E17).
//!
//! A record whose deletion must be real is encrypted under a key of its own, kept wrapped in the
//! Core table `_record_keys` of the same file; deleting the record destroys that key. The table is
//! the Core's: module SQL can neither read nor copy a wrapped key, and no journal image holds
//! one, since the journal images only the module's own tables, so the destroyed key survives
//! nowhere in the file, its journal included (D132: wrapped record keys are never journaled).
//! Destroying it is a delete under `secure_delete` = ON followed by a TRUNCATE checkpoint,
//! retried until the WAL is empty.
//!
//! The storage layer holds the wrapped form only, opaque bytes; the record key and its wrapping
//! are `vilicus-crypto`'s (AD-4, AD-18).

use rusqlite::OptionalExtension;
use vilicus_types::Id;

use crate::error::{Error, Result};
use crate::handle::{self, Handle, Write};

/// What the destruction of a wrapped record key did: whether it deleted a key row, and the
/// TRUNCATE checkpoint attempts until the WAL was empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shredded {
    /// True when this call deleted the key row; false when the record had no key left, as after
    /// a shredding whose checkpoint failed and that this call finished.
    pub key_deleted: bool,
    /// The checkpoint attempts, from 1.
    pub checkpoint_attempts: u32,
}

impl Handle<Write> {
    /// Stores `wrapped`, the wrapped key of the record `record`, in `_record_keys`, inside the
    /// caller's transaction when one is open. An empty key is refused with
    /// [`Error::InvalidWrappedKey`], and a record that already has a key fails on the table's
    /// primary key: a record's key is never replaced.
    pub fn store_wrapped_record_key(&self, record: Id, wrapped: &[u8]) -> Result<()> {
        if wrapped.is_empty() {
            return Err(Error::InvalidWrappedKey);
        }
        self.under_core_policy(|connection| {
            connection.execute(
                "INSERT INTO _record_keys (record_id, wrapped_key) VALUES (?1, ?2)",
                rusqlite::params![record.to_bytes(), wrapped],
            )?;
            Ok(())
        })
    }

    /// The wrapped key of the record `record`, if it has one that was not destroyed.
    pub fn wrapped_record_key(&self, record: Id) -> Result<Option<Vec<u8>>> {
        self.under_core_policy(|connection| {
            Ok(connection
                .query_row(
                    "SELECT wrapped_key FROM _record_keys WHERE record_id = ?1",
                    [record.to_bytes()],
                    |row| row.get(0),
                )
                .optional()?)
        })
    }

    /// Shreds the record `record` (D132, E17): deletes its wrapped key under `secure_delete` = ON
    /// in a transaction of its own, then checkpoints the WAL in TRUNCATE mode until a checkpoint
    /// reports not busy and the WAL is empty, so no byte of the key remains in the file or its
    /// WAL. The record's own row, its ciphertext, stays: without the key it cannot be read.
    ///
    /// A reader holding a snapshot past every attempt fails it with
    /// [`Error::DeletedNotCheckpointed`], the key deleted but possibly still in the WAL; calling
    /// it again finishes the checkpoint, the record having no key left
    /// ([`Shredded::key_deleted`] false), so a shredding is repeated until it succeeds. It refuses
    /// to run inside an open transaction ([`Error::TransactionOpen`]): its delete must commit
    /// before the checkpoint can remove it.
    pub fn destroy_wrapped_record_key(&self, record: Id) -> Result<Shredded> {
        self.require_no_transaction()?;
        let deleted = self.under_core_policy(|connection| {
            let mut deleted = 0;
            handle::in_transaction(connection, || {
                deleted = connection.execute(
                    "DELETE FROM _record_keys WHERE record_id = ?1",
                    [record.to_bytes()],
                )?;
                Ok(())
            })?;
            Ok(deleted)
        })?;
        let checkpoint_attempts = handle::checkpoint_after_delete(self, deleted)?;
        Ok(Shredded {
            key_deleted: deleted > 0,
            checkpoint_attempts,
        })
    }
}
