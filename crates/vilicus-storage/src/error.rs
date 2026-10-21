//! The storage layer's typed errors, and the classification of an authorizer refusal (D126).

use core::fmt;
use std::path::PathBuf;

use crate::file::KeyEpoch;
use crate::handle::MigrationTrack;
use crate::outbox::EffectState;

/// Prefix of the message SQLite gives when the authorizer denies a function call.
const DENIED_FUNCTION_MESSAGE: &str = "not authorized to use function: ";

/// The message SQLite gives when the authorizer callback returns something other than allow,
/// deny or ignore; `rusqlite` returns such a code when the callback panics. The statement did not
/// run, so it counts as a refusal: the authorizer fails closed.
const AUTHORIZER_MALFUNCTION_MESSAGE: &str = "authorizer malfunction";

/// True when the authorizer refused the statement behind `error`.
///
/// SQLite reports most denials as `SQLITE_AUTH`, but a denied function call as plain
/// `SQLITE_ERROR` with its own message, and an authorizer that malfunctioned as `SQLITE_ERROR`
/// too; `rusqlite` reports a prepare error that SQLite can locate in the SQL text as
/// `Error::SqlInputError`, whose code `sqlite_error_code` does not return (Story 1.7, finding 2).
/// Every shape is read here.
pub fn is_refusal(error: &rusqlite::Error) -> bool {
    let (failure, message) = match error {
        rusqlite::Error::SqliteFailure(failure, message) => (failure, message.as_deref()),
        rusqlite::Error::SqlInputError { error, msg, .. } => (error, Some(msg.as_str())),
        _ => return false,
    };
    failure.code == rusqlite::ErrorCode::AuthorizationForStatementDenied
        || (failure.extended_code == rusqlite::ffi::SQLITE_ERROR
            && message.is_some_and(|text| {
                text.starts_with(DENIED_FUNCTION_MESSAGE) || text == AUTHORIZER_MALFUNCTION_MESSAGE
            }))
}

/// A failure of the storage layer.
///
/// Neither `Display` nor `Debug` prints SQL text, which `rusqlite` includes in some of its
/// errors and which may hold values; the logging convention allows identifiers only. For the
/// same reason `source` does not hand out the `rusqlite` error.
#[non_exhaustive]
pub enum Error {
    /// The connection's authorizer refused the statement.
    Refused(rusqlite::Error),
    /// The key does not open the file. Nothing of the file's content was read.
    WrongKey,
    /// A setting read back after the connection setup differs from the one set (D127).
    SetupMismatch {
        /// The pragma or connection option.
        setting: &'static str,
        /// What the setup requires.
        expected: String,
        /// What the connection reports.
        found: String,
    },
    /// The sidecar `<file>.epoch` and the file's `_meta` table hold different key epochs (AD-5).
    EpochMismatch {
        /// The epoch of the sidecar.
        sidecar: KeyEpoch,
        /// The epoch of `_meta`.
        file: KeyEpoch,
    },
    /// The file has no sidecar `<file>.epoch`, so the key epoch to derive its key is unknown.
    EpochSidecarMissing(PathBuf),
    /// A pending sidecar `<file>.epoch.next` is in place: a change of key epoch was interrupted.
    /// The file is opened by neither epoch until the Core resolves it (Story 3.1, Implementation
    /// Notes, the recovery rule).
    EpochTransitionPending {
        /// The epoch of `<file>.epoch`.
        current: KeyEpoch,
        /// The epoch of `<file>.epoch.next`.
        pending: KeyEpoch,
    },
    /// A sidecar is in place but no file, and no interrupted `create` explains it.
    EpochSidecarWithoutFile(PathBuf),
    /// A sidecar cannot be parsed.
    MalformedEpoch(PathBuf),
    /// The file's `_meta` table lacks the key epoch.
    MissingEpoch,
    /// The target of `create`, a copy or a backup is already in place.
    AlreadyExists(PathBuf),
    /// A TRUNCATE checkpoint stayed busy, or left WAL content, after every retry (D132).
    CheckpointIncomplete {
        /// Frames in the WAL at the last attempt.
        log: i32,
        /// Frames copied back at the last attempt.
        checkpointed: i32,
    },
    /// A versioned migration is not the next one of its track: migrations apply forward only, one
    /// version after the other (AD-23, D21).
    MigrationOutOfOrder {
        /// The track of the migration.
        track: MigrationTrack,
        /// The schema version `_meta` holds for that track.
        current: u32,
        /// The version of the migration refused.
        version: u32,
    },
    /// The schema version `_meta` holds for a track is not a version number.
    MalformedSchemaVersion(MigrationTrack),
    /// The frozen hashes a file recorded for a track differ from those of the migrations given
    /// for the versions it is at: a migration the file ran was changed since, or the record is
    /// missing or longer (AD-23, D21). Nothing runs on such a file.
    MigrationChanged {
        /// The track.
        track: MigrationTrack,
        /// The first version whose record differs, is missing or is beyond the migrations.
        version: u32,
    },
    /// The file's module track is at a version beyond the migrations given: a file newer than
    /// the code (D21).
    NewerThanMigrations {
        /// The track.
        track: MigrationTrack,
        /// The schema version of the file.
        found: u32,
        /// The last version of the migrations given.
        latest: u32,
    },
    /// A migration failed and was rolled back: its SQL, refused or failing, or the record of its
    /// version. Nothing of it was written.
    MigrationFailed {
        /// The track.
        track: MigrationTrack,
        /// The version the migration would have brought the track to.
        version: u32,
        /// Why it failed.
        cause: Box<Error>,
    },
    /// The file's Core track is not at the version this code expects: a module migration waits
    /// for the Core's (Core first, AD-26), and a file newer than the code is not migrated back.
    CoreSchemaNotCurrent {
        /// The Core schema version of the file.
        found: u32,
        /// The version the Core's migrations bring a file to.
        latest: u32,
    },
    /// A Core row that must commit with the writes it belongs to (a journal row, an effect
    /// intent, a consumed event) was written outside a transaction.
    NoTransaction,
    /// A row of a Core table holds a value outside its stored form.
    MalformedCoreRow {
        /// The Core table.
        table: &'static str,
        /// The column.
        column: &'static str,
    },
    /// An effect intent without an effect name or an idempotency key (AD-28).
    InvalidEffectIntent,
    /// An effect intent of a name and idempotency key the file holds for another payload or
    /// another caller: one key names one effect (AD-28).
    EffectConflict,
    /// No effect intent of that id is in the file.
    EffectNotFound,
    /// An outcome was recorded for an effect intent that is not pending.
    EffectNotPending {
        /// The intent's state.
        state: EffectState,
    },
    /// A retry was asked for an effect intent that did not fail: an `unknown` one is never
    /// retried blindly (AD-28).
    EffectNotRetryable {
        /// The intent's state.
        state: EffectState,
    },
    /// An empty wrapped record key.
    InvalidWrappedKey,
    /// A deletion that must be real committed, but its TRUNCATE checkpoint stayed busy, or left
    /// WAL content, after every retry (D132): the rows are gone from the tables and may still be
    /// in the WAL until the next checkpoint.
    DeletedNotCheckpointed {
        /// The rows the deletion removed.
        deleted: usize,
        /// Frames in the WAL at the last attempt.
        log: i32,
        /// Frames copied back at the last attempt.
        checkpointed: i32,
    },
    /// A Core operation that runs its own transaction was called inside an open one.
    TransactionOpen,
    /// A label to confirm is outside the form of reviewed-vocabulary labels (D104).
    InvalidVocabularyLabel,
    /// A file copy was asked for while the WAL still holds content (AD-23).
    WalNotEmpty(PathBuf),
    /// The file or its WAL changed while it was being copied, or between its copy and the swap
    /// of a migration, or a connection is still open on it: its WAL or shared-memory file exists
    /// once the copy closed its own.
    CopyRaced(PathBuf),
    /// A file already has the most cold copies it may keep, none of them covered by a verified
    /// backup, so a migration, which leaves one more, does not start (AD-23).
    ColdCopiesFull {
        /// The cold copies kept.
        kept: usize,
    },
    /// Any other SQLite failure.
    Sqlite(rusqlite::Error),
    /// A file system failure on the file, its sidecar or its directory.
    Io(std::io::Error),
}

impl Error {
    /// True for a statement the authorizer refused, a failed migration's included.
    pub fn is_refusal(&self) -> bool {
        match self {
            Self::Refused(_) => true,
            Self::MigrationFailed { cause, .. } => cause.is_refusal(),
            _ => false,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        if is_refusal(&error) {
            Self::Refused(error)
        } else {
            Self::Sqlite(error)
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(error) => write!(
                formatter,
                "refused by the connection authorizer: {}",
                Summary(error)
            ),
            Self::WrongKey => formatter.write_str("the key does not open the file"),
            Self::SetupMismatch {
                setting,
                expected,
                found,
            } => write!(
                formatter,
                "connection setup: {setting} is {found}, expected {expected}"
            ),
            Self::EpochMismatch { sidecar, file } => write!(
                formatter,
                "key epoch of the sidecar ({sidecar}) differs from the file's _meta ({file})"
            ),
            Self::EpochSidecarMissing(path) => {
                write!(formatter, "key epoch sidecar {} is missing", path.display())
            }
            Self::EpochTransitionPending { current, pending } => write!(
                formatter,
                "a change of key epoch from ({current}) to ({pending}) was interrupted"
            ),
            Self::EpochSidecarWithoutFile(path) => write!(
                formatter,
                "key epoch sidecar {} has no database file",
                path.display()
            ),
            Self::MalformedEpoch(path) => {
                write!(formatter, "malformed key epoch sidecar {}", path.display())
            }
            Self::MissingEpoch => formatter.write_str("the file's _meta table holds no key epoch"),
            Self::AlreadyExists(path) => write!(formatter, "{} already exists", path.display()),
            Self::CheckpointIncomplete { log, checkpointed } => write!(
                formatter,
                "TRUNCATE checkpoint incomplete after every retry ({checkpointed} of {log} frames)"
            ),
            Self::MigrationOutOfOrder {
                track,
                current,
                version,
            } => write!(
                formatter,
                "{track} migration {version} does not follow schema version {current}"
            ),
            Self::MalformedSchemaVersion(track) => {
                write!(
                    formatter,
                    "the {track} schema version in _meta is malformed"
                )
            }
            Self::MigrationChanged { track, version } => write!(
                formatter,
                "{track} migration {version} differs from the one the file recorded"
            ),
            Self::NewerThanMigrations {
                track,
                found,
                latest,
            } => write!(
                formatter,
                "the file's {track} schema is at version {found}, beyond the last migration {latest}"
            ),
            Self::MigrationFailed {
                track,
                version,
                cause,
            } => write!(formatter, "{track} migration {version} failed: {cause}"),
            Self::CoreSchemaNotCurrent { found, latest } => write!(
                formatter,
                "the file's Core schema is at version {found}, the Core's at {latest}"
            ),
            Self::NoTransaction => {
                formatter.write_str("a Core row that joins a write transaction was written alone")
            }
            Self::MalformedCoreRow { table, column } => {
                write!(formatter, "{table}.{column} holds a malformed value")
            }
            Self::InvalidEffectIntent => {
                formatter.write_str("an effect intent needs an effect name and an idempotency key")
            }
            Self::EffectConflict => formatter
                .write_str("an effect intent of that name and key exists for another request"),
            Self::EffectNotFound => formatter.write_str("no such effect intent"),
            Self::EffectNotPending { state } => {
                write!(formatter, "the effect intent is {state}, not pending")
            }
            Self::EffectNotRetryable { state } => {
                write!(formatter, "an effect intent that is {state} is not retried")
            }
            Self::InvalidWrappedKey => formatter.write_str("an empty wrapped record key"),
            Self::DeletedNotCheckpointed {
                deleted,
                log,
                checkpointed,
            } => write!(
                formatter,
                "{deleted} rows deleted, their TRUNCATE checkpoint incomplete after every retry \
                 ({checkpointed} of {log} frames)"
            ),
            Self::TransactionOpen => {
                formatter.write_str("a Core operation with its own transaction inside another")
            }
            Self::InvalidVocabularyLabel => {
                formatter.write_str("a label outside the form of reviewed-vocabulary labels")
            }
            Self::WalNotEmpty(path) => write!(formatter, "{} holds WAL content", path.display()),
            Self::CopyRaced(path) => write!(
                formatter,
                "{} changed while it was copied, or a connection is open on it",
                path.display()
            ),
            Self::ColdCopiesFull { kept } => write!(
                formatter,
                "{kept} cold copies are kept, none covered by a verified backup"
            ),
            Self::Sqlite(error) => write!(formatter, "SQLite: {}", Summary(error)),
            Self::Io(error) => write!(formatter, "file system: {error}"),
        }
    }
}

impl fmt::Debug for Error {
    /// The variant name and its `Display` text, so a `{:?}` in a log line prints no SQL either.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Refused(_) => "Refused",
            Self::WrongKey => "WrongKey",
            Self::SetupMismatch { .. } => "SetupMismatch",
            Self::EpochMismatch { .. } => "EpochMismatch",
            Self::EpochSidecarMissing(_) => "EpochSidecarMissing",
            Self::EpochTransitionPending { .. } => "EpochTransitionPending",
            Self::EpochSidecarWithoutFile(_) => "EpochSidecarWithoutFile",
            Self::MalformedEpoch(_) => "MalformedEpoch",
            Self::MissingEpoch => "MissingEpoch",
            Self::AlreadyExists(_) => "AlreadyExists",
            Self::CheckpointIncomplete { .. } => "CheckpointIncomplete",
            Self::MigrationOutOfOrder { .. } => "MigrationOutOfOrder",
            Self::MalformedSchemaVersion(_) => "MalformedSchemaVersion",
            Self::MigrationChanged { .. } => "MigrationChanged",
            Self::NewerThanMigrations { .. } => "NewerThanMigrations",
            Self::MigrationFailed { .. } => "MigrationFailed",
            Self::CoreSchemaNotCurrent { .. } => "CoreSchemaNotCurrent",
            Self::NoTransaction => "NoTransaction",
            Self::MalformedCoreRow { .. } => "MalformedCoreRow",
            Self::InvalidEffectIntent => "InvalidEffectIntent",
            Self::EffectConflict => "EffectConflict",
            Self::EffectNotFound => "EffectNotFound",
            Self::EffectNotPending { .. } => "EffectNotPending",
            Self::EffectNotRetryable { .. } => "EffectNotRetryable",
            Self::InvalidWrappedKey => "InvalidWrappedKey",
            Self::DeletedNotCheckpointed { .. } => "DeletedNotCheckpointed",
            Self::TransactionOpen => "TransactionOpen",
            Self::InvalidVocabularyLabel => "InvalidVocabularyLabel",
            Self::WalNotEmpty(_) => "WalNotEmpty",
            Self::CopyRaced(_) => "CopyRaced",
            Self::ColdCopiesFull { .. } => "ColdCopiesFull",
            Self::Sqlite(_) => "Sqlite",
            Self::Io(_) => "Io",
        };
        write!(formatter, "{variant}({self})")
    }
}

/// A SQLite error without the SQL text: `rusqlite` prints the whole statement of an
/// `SqlInputError`, which may hold values.
struct Summary<'a>(&'a rusqlite::Error);

impl fmt::Display for Summary<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            rusqlite::Error::SqlInputError {
                error, msg, offset, ..
            } => write!(
                formatter,
                "{msg} (code {}, at offset {offset})",
                error.extended_code
            ),
            other => write!(formatter, "{other}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// The result type of the storage layer.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    fn input_error(message: &str, code: i32) -> rusqlite::Error {
        rusqlite::Error::SqlInputError {
            error: rusqlite::ffi::Error::new(code),
            msg: message.to_owned(),
            sql: "SELECT secret_value FROM t WHERE v = 'sensitive'".to_owned(),
            offset: 7,
        }
    }

    #[test]
    fn neither_display_nor_debug_prints_the_sql_text() {
        for error in [
            Error::from(input_error(
                "no such column: secret_value",
                rusqlite::ffi::SQLITE_ERROR,
            )),
            Error::from(input_error(
                "not authorized to use function: x",
                rusqlite::ffi::SQLITE_ERROR,
            )),
        ] {
            let shown = format!("{error} {error:?}");
            assert!(!shown.contains("sensitive"), "{shown}");
            assert!(std::error::Error::source(&error).is_none());
        }
    }

    /// Item of the review: an authorizer that malfunctioned (a panicking callback) fails closed
    /// and is classified with the refusals.
    #[test]
    fn an_authorizer_malfunction_is_a_refusal() {
        let malfunction = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
            Some(AUTHORIZER_MALFUNCTION_MESSAGE.to_owned()),
        );
        assert!(is_refusal(&malfunction));
        let other = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
            Some("no such table: x".to_owned()),
        );
        assert!(!is_refusal(&other));
    }
}
