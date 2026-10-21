//! The storage layer's typed errors, and the classification of an authorizer refusal (D126).

use core::fmt;
use std::path::PathBuf;

use crate::file::KeyEpoch;

/// Prefix of the message SQLite gives when the authorizer denies a function call.
const DENIED_FUNCTION_MESSAGE: &str = "not authorized to use function: ";

/// True when the authorizer refused the statement behind `error`.
///
/// SQLite reports most denials as `SQLITE_AUTH`, but a denied function call as plain
/// `SQLITE_ERROR` with its own message, and `rusqlite` reports a prepare error that SQLite can
/// locate in the SQL text as `Error::SqlInputError`, whose code `sqlite_error_code` does not
/// return (Story 1.7, finding 2). Both shapes are read here.
pub fn is_refusal(error: &rusqlite::Error) -> bool {
    let (failure, message) = match error {
        rusqlite::Error::SqliteFailure(failure, message) => (failure, message.as_deref()),
        rusqlite::Error::SqlInputError { error, msg, .. } => (error, Some(msg.as_str())),
        _ => return false,
    };
    failure.code == rusqlite::ErrorCode::AuthorizationForStatementDenied
        || (failure.extended_code == rusqlite::ffi::SQLITE_ERROR
            && message.is_some_and(|text| text.starts_with(DENIED_FUNCTION_MESSAGE)))
}

/// A failure of the storage layer.
#[derive(Debug)]
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
    /// The sidecar `<file>.epoch` cannot be parsed.
    MalformedEpoch(PathBuf),
    /// The file's `_meta` table lacks the key epoch.
    MissingEpoch,
    /// `create` found a file or a sidecar already in place.
    AlreadyExists(PathBuf),
    /// A TRUNCATE checkpoint stayed busy, or left WAL content, after every retry (D132).
    CheckpointIncomplete {
        /// Frames in the WAL at the last attempt.
        log: i32,
        /// Frames copied back at the last attempt.
        checkpointed: i32,
    },
    /// A file copy was asked for while the WAL still holds content (AD-23).
    WalNotEmpty(PathBuf),
    /// Any other SQLite failure.
    Sqlite(rusqlite::Error),
    /// A file system failure on the file, its sidecar or its directory.
    Io(std::io::Error),
}

impl Error {
    /// True for a statement the authorizer refused.
    pub fn is_refusal(&self) -> bool {
        matches!(self, Self::Refused(_))
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
            Self::Refused(error) => {
                write!(
                    formatter,
                    "refused by the connection authorizer: {}",
                    Summary(error)
                )
            }
            Self::WrongKey => formatter.write_str("the key does not open the file"),
            Self::SetupMismatch {
                setting,
                expected,
                found,
            } => {
                write!(
                    formatter,
                    "connection setup: {setting} is {found}, expected {expected}"
                )
            }
            Self::EpochMismatch { sidecar, file } => {
                write!(
                    formatter,
                    "key epoch of the sidecar ({sidecar}) differs from the file's _meta ({file})"
                )
            }
            Self::MalformedEpoch(path) => {
                write!(formatter, "malformed key epoch sidecar {}", path.display())
            }
            Self::MissingEpoch => formatter.write_str("the file's _meta table holds no key epoch"),
            Self::AlreadyExists(path) => write!(formatter, "{} already exists", path.display()),
            Self::CheckpointIncomplete { log, checkpointed } => write!(
                formatter,
                "TRUNCATE checkpoint incomplete after every retry ({checkpointed} of {log} frames)"
            ),
            Self::WalNotEmpty(path) => write!(formatter, "{} holds WAL content", path.display()),
            Self::Sqlite(error) => write!(formatter, "SQLite: {}", Summary(error)),
            Self::Io(error) => write!(formatter, "file system: {error}"),
        }
    }
}

/// A SQLite error without the SQL text: `rusqlite` prints the whole statement of an
/// `SqlInputError`, which may hold values, and the logging convention allows identifiers only.
struct Summary<'a>(&'a rusqlite::Error);

impl fmt::Display for Summary<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            rusqlite::Error::SqlInputError {
                error, msg, offset, ..
            } => {
                write!(
                    formatter,
                    "{msg} (code {}, at offset {offset})",
                    error.extended_code
                )
            }
            other => write!(formatter, "{other}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused(error) | Self::Sqlite(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// The result type of the storage layer.
pub type Result<T> = std::result::Result<T, Error>;
