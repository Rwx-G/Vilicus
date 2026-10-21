//! The write journal of a module file (AD-26, AD-28, FR-29): one `_journal` row per record a
//! call changed, written by the Core in the transaction of the write, read back to deduplicate a
//! repeated call, and deleted by the retention purge under `secure_delete` = ON followed by a
//! TRUNCATE checkpoint (D113, D132).
//!
//! Every statement here is one of the Core's own, run under [`Policy::Core`](crate::authorizer),
//! which module SQL never runs under; module SQL can neither write nor read `_journal`. The
//! storage layer stores the images and the inputs as the Core encoded them: it neither builds
//! nor reads them.

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, Row};
use vilicus_types::{CallId, Id, Principal, Rev, Source, UtcMillis};

use crate::error::{Error, Result};
use crate::handle::{self, Handle, Write};

/// The key a call is deduplicated by (AD-26, AD-28): its principal, the `source` its records
/// carry, which names who acts within the principal's kind (the member of a `Member` or `Cli`
/// call, the task of an `AiTask` call, the rule of a `Rule` call), and the `call_id` its caller
/// generated. Two calls of one key are one call. The sources of one principal kind are separate
/// spaces: a plugin's `plugin(id)` and `import(id)` calls, or an AI task's `ai_task(id)` and
/// `scheduled_task(id)` calls, never deduplicate each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallKey<'a> {
    /// The principal.
    pub principal: Principal,
    /// The `source` the call's records carry.
    pub source: &'a Source,
    /// The id the caller gave the call (AD-28, AD-39).
    pub call_id: CallId,
}

impl CallKey<'_> {
    fn bound(&self) -> [SqlValue; 3] {
        [
            SqlValue::Text(self.principal.as_str().to_owned()),
            SqlValue::Text(self.source.to_string()),
            SqlValue::Blob(self.call_id.to_bytes().to_vec()),
        ]
    }
}

/// Whether a member made or approved the journaled writes (AD-6, D70): what the digest and undo
/// read of a call besides its principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthorityKind {
    /// The member's own action (`Member`, `Cli`).
    OwnAction,
    /// A member's approval of an `AiTask` or `Plugin` request.
    Approved,
    /// No member made or approved the writes.
    Unapproved,
}

impl AuthorityKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 3] = [Self::OwnAction, Self::Approved, Self::Unapproved];

    /// The stored form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnAction => "own_action",
            Self::Approved => "approved",
            Self::Unapproved => "unapproved",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == name)
    }
}

/// One record a call changed, as the Core journals it.
#[derive(Clone, Copy, Debug)]
pub struct JournalEntry<'a> {
    /// The call.
    pub call: CallKey<'a>,
    /// The hash of the call's request, when the pipeline gives one: a later call of the same key
    /// with another hash is refused rather than deduplicated.
    pub request_hash: Option<&'a [u8]>,
    /// Whether a member made or approved the call.
    pub authority: AuthorityKind,
    /// The member who made or approved the call, or the one it acts for.
    pub member: Option<Id>,
    /// The position of this change among the call's changes, from 0.
    pub change_index: u32,
    /// The module table of the record.
    pub table: &'a str,
    /// The record.
    pub record: Id,
    /// Its revision before the write; `None` for an insert.
    pub rev_before: Option<Rev>,
    /// Its revision after the write; `None` for a delete.
    pub rev_after: Option<Rev>,
    /// Its row before the write, as the Core encoded it; `None` for an insert.
    pub image_before: Option<&'a [u8]>,
    /// Its row after the write, as the Core encoded it; `None` for a delete.
    pub image_after: Option<&'a [u8]>,
    /// The provenance of the write's inputs, as the Core encoded it.
    pub inputs: &'a [u8],
    /// The time of the write.
    pub created_at: UtcMillis,
}

/// A `_journal` row read back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalRow {
    /// The row's position in the file's journal, in commit order.
    pub seq: i64,
    /// The hash of the call's request, if the call carried one.
    pub request_hash: Option<Vec<u8>>,
    /// Whether a member made or approved the call.
    pub authority: AuthorityKind,
    /// The member who made or approved the call, or the one it acts for.
    pub member: Option<Id>,
    /// The position of this change among the call's changes.
    pub change_index: u32,
    /// The module table of the record.
    pub table: String,
    /// The record.
    pub record: Id,
    /// Its revision before the write.
    pub rev_before: Option<Rev>,
    /// Its revision after the write.
    pub rev_after: Option<Rev>,
    /// Its encoded row before the write.
    pub image_before: Option<Vec<u8>>,
    /// Its encoded row after the write.
    pub image_after: Option<Vec<u8>>,
    /// The encoded provenance of the write's inputs.
    pub inputs: Vec<u8>,
    /// The time of the write.
    pub created_at: UtcMillis,
}

/// What a retention purge did: the rows it deleted, and the TRUNCATE checkpoint attempts it took
/// until the WAL was empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalPurge {
    /// The `_journal` rows deleted.
    pub deleted: usize,
    /// The checkpoint attempts, from 1; more than 1 when a reader kept the first one busy.
    pub checkpoint_attempts: u32,
}

fn id_value(id: Id) -> SqlValue {
    SqlValue::Blob(id.to_bytes().to_vec())
}

fn optional_id(id: Option<Id>) -> SqlValue {
    id.map_or(SqlValue::Null, id_value)
}

fn optional_rev(rev: Option<Rev>) -> SqlValue {
    rev.map_or(SqlValue::Null, |rev| SqlValue::Integer(rev.get()))
}

fn optional_blob(bytes: Option<&[u8]>) -> SqlValue {
    bytes.map_or(SqlValue::Null, |bytes| SqlValue::Blob(bytes.to_vec()))
}

/// The error of a stored value of `column` of the Core table `table` outside its stored form.
pub(crate) fn malformed(table: &'static str, column: &'static str) -> Error {
    Error::MalformedCoreRow { table, column }
}

pub(crate) fn read_id(
    row: &Row<'_>,
    index: usize,
    table: &'static str,
    column: &'static str,
) -> Result<Id> {
    read_optional_id(row, index, table, column)?.ok_or(malformed(table, column))
}

pub(crate) fn read_optional_id(
    row: &Row<'_>,
    index: usize,
    table: &'static str,
    column: &'static str,
) -> Result<Option<Id>> {
    match row.get::<_, SqlValue>(index)? {
        SqlValue::Null => Ok(None),
        SqlValue::Blob(bytes) => <[u8; 16]>::try_from(bytes.as_slice())
            .ok()
            .and_then(|bytes| Id::from_bytes(bytes).ok())
            .map(Some)
            .ok_or(malformed(table, column)),
        _ => Err(malformed(table, column)),
    }
}

pub(crate) fn read_time(
    row: &Row<'_>,
    index: usize,
    table: &'static str,
    column: &'static str,
) -> Result<UtcMillis> {
    UtcMillis::from_millis(row.get(index)?).map_err(|_| malformed(table, column))
}

fn read_rev(row: &Row<'_>, index: usize, column: &'static str) -> Result<Option<Rev>> {
    match row.get::<_, Option<i64>>(index)? {
        None => Ok(None),
        Some(value) => Rev::new(value)
            .map(Some)
            .ok_or(malformed("_journal", column)),
    }
}

fn journal_row(row: &Row<'_>) -> Result<JournalRow> {
    let authority: String = row.get(1)?;
    Ok(JournalRow {
        seq: row.get(0)?,
        request_hash: row.get(12)?,
        authority: AuthorityKind::from_name(&authority)
            .ok_or(malformed("_journal", "authority"))?,
        member: read_optional_id(row, 2, "_journal", "member")?,
        change_index: u32::try_from(row.get::<_, i64>(3)?)
            .map_err(|_| malformed("_journal", "change_index"))?,
        table: row.get(4)?,
        record: read_id(row, 5, "_journal", "record_id")?,
        rev_before: read_rev(row, 6, "rev_before")?,
        rev_after: read_rev(row, 7, "rev_after")?,
        image_before: row.get(8)?,
        image_after: row.get(9)?,
        inputs: row.get(10)?,
        created_at: read_time(row, 11, "_journal", "created_at")?,
    })
}

/// Refuses a Core row that must join the transaction of the writes it belongs to when no
/// transaction is open: written on its own, it would commit apart from them.
pub(crate) fn require_transaction(connection: &Connection) -> Result<()> {
    if connection.is_autocommit() {
        Err(Error::NoTransaction)
    } else {
        Ok(())
    }
}

impl Handle<Write> {
    /// Appends `entry` to `_journal`, inside the write transaction the caller holds, which
    /// journals the write it describes: a journal row never commits without its write, nor a
    /// write without its row (AD-26). Fails with [`Error::NoTransaction`] outside a transaction.
    pub fn append_journal(&self, entry: &JournalEntry<'_>) -> Result<()> {
        self.under_core_policy(|connection| {
            require_transaction(connection)?;
            let [principal, source, call_id] = entry.call.bound();
            connection.execute(
                "INSERT INTO _journal (call_id, principal, source, authority, member, \
                 change_index, record_table, record_id, rev_before, rev_after, image_before, \
                 image_after, inputs, created_at, request_hash) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                rusqlite::params_from_iter([
                    call_id,
                    principal,
                    source,
                    SqlValue::Text(entry.authority.as_str().to_owned()),
                    optional_id(entry.member),
                    SqlValue::Integer(i64::from(entry.change_index)),
                    SqlValue::Text(entry.table.to_owned()),
                    id_value(entry.record),
                    optional_rev(entry.rev_before),
                    optional_rev(entry.rev_after),
                    optional_blob(entry.image_before),
                    optional_blob(entry.image_after),
                    SqlValue::Blob(entry.inputs.to_vec()),
                    SqlValue::Integer(entry.created_at.as_millis()),
                    optional_blob(entry.request_hash),
                ]),
            )?;
            Ok(())
        })
    }

    /// The journal rows of the call `key`, in the order of its changes; empty when no call of
    /// that key wrote in this file. Run inside the write transaction of a new call, it is the
    /// check AD-26 requires before the call's code runs.
    pub fn journaled_call(&self, key: &CallKey<'_>) -> Result<Vec<JournalRow>> {
        self.under_core_policy(|connection| {
            let mut statement = connection.prepare(
                "SELECT seq, authority, member, change_index, record_table, record_id, \
                 rev_before, rev_after, image_before, image_after, inputs, created_at, \
                 request_hash \
                 FROM _journal WHERE principal = ?1 AND source = ?2 AND call_id = ?3 \
                 ORDER BY change_index",
            )?;
            let mut rows = statement.query(rusqlite::params_from_iter(key.bound()))?;
            let mut journal = Vec::new();
            while let Some(row) = rows.next()? {
                journal.push(journal_row(row)?);
            }
            Ok(journal)
        })
    }

    /// The retention purge of the journal (FR-29, D113, D132): deletes every row written before
    /// `cutoff` in one `DELETE FROM _journal WHERE created_at < cutoff`, in a transaction of its
    /// own, then checkpoints the WAL in TRUNCATE mode, retried until a checkpoint reports not
    /// busy and the WAL is empty, so the deleted rows leave the file and the WAL. The cutoff is
    /// the Core's, by partition kind, never a module's.
    ///
    /// The connection runs with `secure_delete` = ON, read back at open, so the delete
    /// overwrites the rows' cells and freed pages. A reader that holds a snapshot keeps the
    /// checkpoint busy; once the attempts are spent the purge fails with
    /// [`Error::CheckpointIncomplete`], its rows deleted but possibly still in the WAL, and the
    /// next purge, or [`checkpoint_truncate`](Self::checkpoint_truncate), checkpoints again.
    pub fn purge_journal(&self, cutoff: UtcMillis) -> Result<JournalPurge> {
        let deleted = self.under_core_policy(|connection| {
            let mut deleted = 0;
            handle::in_transaction(connection, || {
                deleted = connection.execute(
                    "DELETE FROM _journal WHERE created_at < ?1",
                    [cutoff.as_millis()],
                )?;
                Ok(())
            })?;
            Ok(deleted)
        })?;
        let checkpoint_attempts = handle::checkpoint_until_empty(self.file(), self.connection())?;
        Ok(JournalPurge {
            deleted,
            checkpoint_attempts,
        })
    }
}
