//! Field validation on every write (FR-58, AD-6, D98, D104, I40): the Core's row writer holds
//! each field a write gives to its declaration, and refuses the whole write with a typed
//! [`RecordError`] when one value is outside it, so nothing of the write is stored.
//!
//! A write runs in one `BEGIN IMMEDIATE` transaction on the file's write handle: every field is
//! checked first, its storage class and its closed type or maximum length by
//! [`Field::check_value`](vilicus_module_api::Field::check_value), and a reviewed-vocabulary label
//! against the labels confirmed in that file, read under the write lock; only then does the
//! statement run. A value is never truncated or converted: it is stored as given, or the write
//! is refused.
//!
//! The row writer takes the envelope columns (AD-6) from its caller and holds each to its stored
//! form (`envelope`); stamping them (id, source, taint, data types, author, times and `rev`) is
//! the typed record API's, which writes through this module (Story 3.5). The row writer, label
//! confirmation and the check of stored rows are crate-private: no crate outside the Core can
//! write a row, choose an envelope or confirm a label, which has no surface in V0.1 (FR-50).
//!
//! ```compile_fail,E0603
//! let _ = vilicus_core::record::confirm_label;
//! ```
//!
//! ```compile_fail,E0603
//! let _ = vilicus_core::record::insert;
//! ```
//!
//! With the `testing` feature, which only test code enables, `Registry::fuzz_write_paths` drives
//! every write path of a registry's modules with values outside their declarations (AC4 of Story
//! 3.4).

// Until the typed record API of Story 3.5 calls the row writer, only the write path fuzz test and
// the unit tests do, so a build without either has no caller of it yet.
#![cfg_attr(
    not(any(test, feature = "testing")),
    allow(
        dead_code,
        reason = "the typed record API of Story 3.5 calls the row writer; until then only tests do"
    )
)]

mod envelope;
#[cfg(any(test, feature = "testing"))]
mod fuzz;

#[cfg(test)]
mod tests;

use core::fmt;

use vilicus_module_api::{
    ENVELOPE, Field, FieldKind, ModuleDeclaration, Structured, Table, Value, ValueError,
    check_vocabulary_label,
};
use vilicus_storage::{Handle, Inspect, SqlValue, Write};
use vilicus_types::{Id, UtcMillis};

#[cfg(any(test, feature = "testing"))]
pub use fuzz::{WriteFuzzError, WriteFuzzReport, WriteKind, WritePath};

/// Why the Core refuses a write, a label confirmation or a stored row. No variant carries a
/// value or a name the caller chose, which may be record content (spine conventions, Logging):
/// only the names the declaration holds.
#[derive(Debug)]
#[non_exhaustive]
pub enum RecordError {
    /// The module declares no table of the name written to.
    UnknownTable {
        /// The module.
        module: &'static str,
    },
    /// A column written to is neither a field of the table nor an envelope column.
    UnknownColumn {
        /// The table.
        table: &'static str,
    },
    /// A write gives a column twice.
    DuplicateColumn {
        /// The table.
        table: &'static str,
        /// The column.
        column: &'static str,
    },
    /// An insert leaves out a field that is not optional, or an envelope column.
    MissingColumn {
        /// The table.
        table: &'static str,
        /// The column.
        column: &'static str,
    },
    /// An update gives the record's `id`, which never changes.
    IdChanged {
        /// The table.
        table: &'static str,
    },
    /// An update gives no column.
    EmptyUpdate {
        /// The table.
        table: &'static str,
    },
    /// A value is outside its column's declaration (D98).
    Invalid {
        /// The table.
        table: &'static str,
        /// The column.
        column: &'static str,
        /// The rule the value breaks.
        error: ValueError,
    },
    /// An envelope value is outside its stored form: a `source`, `taint` or `data_types` text the
    /// Core does not write, or data types the record kind does not declare (AD-6).
    InvalidEnvelope {
        /// The table.
        table: &'static str,
        /// The envelope column.
        column: &'static str,
    },
    /// A reviewed-vocabulary label is not one an adult confirmed in this file (D104).
    UnconfirmedLabel {
        /// The table.
        table: &'static str,
        /// The column.
        column: &'static str,
        /// The vocabulary the column declares.
        vocabulary: &'static str,
    },
    /// A label confirmation names a vocabulary no field of the module declares.
    UnknownVocabulary {
        /// The module.
        module: &'static str,
    },
    /// A label confirmation gives a label outside the form of reviewed-vocabulary labels.
    InvalidLabel {
        /// The vocabulary.
        vocabulary: &'static str,
        /// The rule the label breaks.
        error: ValueError,
    },
    /// An update names a record the table does not hold.
    RecordNotFound {
        /// The table.
        table: &'static str,
    },
    /// The storage layer failed; the transaction was rolled back.
    Storage(vilicus_storage::Error),
}

impl fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTable { module } => {
                write!(formatter, "module {module} declares no such table")
            }
            Self::UnknownColumn { table } => {
                write!(formatter, "{table}: a column the table does not declare")
            }
            Self::DuplicateColumn { table, column } => {
                write!(formatter, "{table}.{column} given twice")
            }
            Self::MissingColumn { table, column } => {
                write!(formatter, "{table}.{column} is required")
            }
            Self::IdChanged { table } => write!(formatter, "{table}: a record's id never changes"),
            Self::EmptyUpdate { table } => write!(formatter, "{table}: an update gives no column"),
            Self::Invalid {
                table,
                column,
                error,
            } => write!(formatter, "{table}.{column}: {error}"),
            Self::InvalidEnvelope { table, column } => {
                write!(
                    formatter,
                    "{table}.{column}: outside the envelope's stored form"
                )
            }
            Self::UnconfirmedLabel {
                table,
                column,
                vocabulary,
            } => write!(
                formatter,
                "{table}.{column}: a label not confirmed in vocabulary {vocabulary}"
            ),
            Self::UnknownVocabulary { module } => {
                write!(formatter, "module {module} declares no such vocabulary")
            }
            Self::InvalidLabel { vocabulary, error } => {
                write!(formatter, "vocabulary {vocabulary}: {error}")
            }
            Self::RecordNotFound { table } => write!(formatter, "{table}: no such record"),
            Self::Storage(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for RecordError {}

impl From<vilicus_storage::Error> for RecordError {
    fn from(error: vilicus_storage::Error) -> Self {
        Self::Storage(error)
    }
}

/// Whether a write must give every column: an insert, or an update of some of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Completeness {
    Every,
    Some,
}

/// One column a write gives, after its checks: the declared name and the value to bind.
struct Checked<'a> {
    column: &'static str,
    value: &'a Value,
}

/// Inserts a record into `table` of `module`'s file (AD-9): the envelope columns as given, every
/// one of them, and the fields, each optional field left out being stored `NULL`. The write is
/// refused, and nothing stored, unless every value meets its declaration.
pub(crate) fn insert(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    table: &str,
    envelope: &[(&str, Value)],
    fields: &[(&str, Value)],
) -> Result<(), RecordError> {
    let table = declared_table(module, table)?;
    in_write_transaction(handle, || {
        let mut columns = check_envelope(table, envelope, Completeness::Every)?;
        columns.extend(check_fields(handle, table, fields, Completeness::Every)?);
        let names: Vec<&str> = columns.iter().map(|checked| checked.column).collect();
        let parameters: Vec<String> = (1..=columns.len())
            .map(|index| format!("?{index}"))
            .collect();
        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            table.name,
            names.join(", "),
            parameters.join(", ")
        );
        handle.execute_values(&sql, &bound(&columns))?;
        Ok(())
    })
}

/// Updates the record `id` of `table`: the envelope columns and fields given, and no other; the
/// record's `id` never changes. The write is refused, and nothing stored, unless every value
/// meets its declaration and the record exists.
pub(crate) fn update(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    table: &str,
    id: Id,
    envelope: &[(&str, Value)],
    fields: &[(&str, Value)],
) -> Result<(), RecordError> {
    let table = declared_table(module, table)?;
    in_write_transaction(handle, || {
        let mut columns = check_envelope(table, envelope, Completeness::Some)?;
        columns.extend(check_fields(handle, table, fields, Completeness::Some)?);
        if columns.is_empty() {
            return Err(RecordError::EmptyUpdate { table: table.name });
        }
        let assignments: Vec<String> = columns
            .iter()
            .enumerate()
            .map(|(index, checked)| format!("{} = ?{}", checked.column, index + 1))
            .collect();
        let sql = format!(
            "UPDATE {} SET {} WHERE id = ?{}",
            table.name,
            assignments.join(", "),
            columns.len() + 1
        );
        let mut values = bound(&columns);
        values.push(SqlValue::Blob(id.to_bytes().to_vec()));
        match handle.execute_values(&sql, &values)? {
            0 => Err(RecordError::RecordNotFound { table: table.name }),
            _ => Ok(()),
        }
    })
}

/// Records `label` as a confirmed label of `vocabulary` in `module`'s file, confirmed by the
/// adult `confirmed_by` at `confirmed_at` (D104): the label must have the form of
/// reviewed-vocabulary labels and a field of the module must declare the vocabulary. No surface
/// confirms labels in V0.1 (FR-50); the write path fuzz test seeds its own files through this.
pub(crate) fn confirm_label(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    vocabulary: &str,
    label: &str,
    confirmed_by: Id,
    confirmed_at: UtcMillis,
) -> Result<(), RecordError> {
    let vocabulary = declared_vocabularies(module)
        .find(|declared| *declared == vocabulary)
        .ok_or(RecordError::UnknownVocabulary {
            module: module.name,
        })?;
    check_vocabulary_label(label)
        .map_err(|error| RecordError::InvalidLabel { vocabulary, error })?;
    handle.confirm_vocabulary_label(vocabulary, label, confirmed_by, confirmed_at)?;
    Ok(())
}

/// Checks every stored row of every table of `module`'s file against the declaration: each
/// envelope value against its stored form, each field against its declaration and each
/// vocabulary label against the labels confirmed in the file. What a migration's back-fill
/// writes passes no write path, so this is how such values are checked.
pub(crate) fn check_stored_rows<R: Inspect>(
    handle: &Handle<R>,
    module: &'static ModuleDeclaration,
) -> Result<(), RecordError> {
    for table in module.tables {
        let names: Vec<&str> = ENVELOPE
            .iter()
            .map(|column| column.name)
            .chain(table.fields.iter().map(|field| field.name))
            .collect();
        let rows = handle.query_values(
            &format!("SELECT {} FROM {}", names.join(", "), table.name),
            &[],
        )?;
        for row in rows {
            let mut stored = row.into_iter().map(from_stored);
            for (column, value) in ENVELOPE.iter().zip(stored.by_ref()) {
                envelope::check(table, column, &value)?;
            }
            for (field, value) in table.fields.iter().zip(stored) {
                check_value(handle, table, field, &value)?;
            }
        }
    }
    Ok(())
}

/// The reviewed vocabularies the module's fields declare, each once per field.
pub(crate) fn declared_vocabularies(
    module: &'static ModuleDeclaration,
) -> impl Iterator<Item = &'static str> {
    module
        .tables
        .iter()
        .flat_map(|table| table.fields)
        .filter_map(|field| match field.kind {
            FieldKind::Structured(Structured::ReviewedVocabulary(vocabulary)) => Some(vocabulary),
            _ => None,
        })
}

fn declared_table(
    module: &'static ModuleDeclaration,
    table: &str,
) -> Result<&'static Table, RecordError> {
    module.table(table).ok_or(RecordError::UnknownTable {
        module: module.name,
    })
}

/// Runs `body` in a `BEGIN IMMEDIATE` transaction on `handle`, committed when it succeeds. When
/// `body` or the `COMMIT` fails, the transaction is rolled back, so a refused write leaves the
/// file as it was and the handle never stays inside the transaction.
fn in_write_transaction(
    handle: &Handle<Write>,
    body: impl FnOnce() -> Result<(), RecordError>,
) -> Result<(), RecordError> {
    handle.execute_batch("BEGIN IMMEDIATE")?;
    let outcome = body().and_then(|()| Ok(handle.execute_batch("COMMIT")?));
    if outcome.is_err() {
        // The rollback's own failure is not reported: the refusal says why nothing was written.
        // A COMMIT that failed on a deferred constraint leaves the transaction open, which this
        // rollback ends.
        let _ = handle.execute_batch("ROLLBACK");
    }
    outcome
}

/// The fields a write gives, each declared once in `table`, each value within its declaration
/// and each label confirmed in the file; with [`Completeness::Every`], every field that is not
/// optional is given.
fn check_fields<'a, R: Inspect>(
    handle: &Handle<R>,
    table: &'static Table,
    fields: &'a [(&str, Value)],
    completeness: Completeness,
) -> Result<Vec<Checked<'a>>, RecordError> {
    let mut checked: Vec<Checked<'a>> = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        let field = table
            .fields
            .iter()
            .find(|field| field.name == *name)
            .ok_or(RecordError::UnknownColumn { table: table.name })?;
        if checked.iter().any(|given| given.column == field.name) {
            return Err(RecordError::DuplicateColumn {
                table: table.name,
                column: field.name,
            });
        }
        check_value(handle, table, field, value)?;
        checked.push(Checked {
            column: field.name,
            value,
        });
    }
    if completeness == Completeness::Every
        && let Some(missing) = table.fields.iter().find(|field| {
            !field.optional && !checked.iter().any(|given| given.column == field.name)
        })
    {
        return Err(RecordError::MissingColumn {
            table: table.name,
            column: missing.name,
        });
    }
    Ok(checked)
}

/// One field's value against its declaration, then, for a reviewed-vocabulary label, against the
/// labels confirmed in the file.
fn check_value<R: Inspect>(
    handle: &Handle<R>,
    table: &'static Table,
    field: &'static Field,
    value: &Value,
) -> Result<(), RecordError> {
    field
        .check_value(value)
        .map_err(|error| RecordError::Invalid {
            table: table.name,
            column: field.name,
            error,
        })?;
    if let (FieldKind::Structured(Structured::ReviewedVocabulary(vocabulary)), Value::Text(label)) =
        (field.kind, value)
        && !handle.is_confirmed_label(vocabulary, label)?
    {
        return Err(RecordError::UnconfirmedLabel {
            table: table.name,
            column: field.name,
            vocabulary,
        });
    }
    Ok(())
}

/// The envelope columns a write gives, each an envelope column given once and in its stored form
/// (`envelope::check`); an update never gives `id`. With [`Completeness::Every`], every envelope
/// column is given.
fn check_envelope<'a>(
    table: &'static Table,
    envelope: &'a [(&str, Value)],
    completeness: Completeness,
) -> Result<Vec<Checked<'a>>, RecordError> {
    let mut checked: Vec<Checked<'a>> = Vec::with_capacity(envelope.len());
    for (name, value) in envelope {
        let column = ENVELOPE
            .iter()
            .find(|column| column.name == *name)
            .ok_or(RecordError::UnknownColumn { table: table.name })?;
        if checked.iter().any(|given| given.column == column.name) {
            return Err(RecordError::DuplicateColumn {
                table: table.name,
                column: column.name,
            });
        }
        if column.primary_key && completeness == Completeness::Some {
            return Err(RecordError::IdChanged { table: table.name });
        }
        envelope::check(table, column, value)?;
        checked.push(Checked {
            column: column.name,
            value,
        });
    }
    if completeness == Completeness::Every
        && let Some(missing) = ENVELOPE
            .iter()
            .find(|column| !checked.iter().any(|given| given.column == column.name))
    {
        return Err(RecordError::MissingColumn {
            table: table.name,
            column: missing.name,
        });
    }
    Ok(checked)
}

/// The values to bind, in the order of `columns`.
fn bound(columns: &[Checked<'_>]) -> Vec<SqlValue> {
    columns
        .iter()
        .map(|checked| to_stored(checked.value))
        .collect()
}

fn to_stored(value: &Value) -> SqlValue {
    match value {
        Value::Null => SqlValue::Null,
        Value::Integer(number) => SqlValue::Integer(*number),
        Value::Real(number) => SqlValue::Real(*number),
        Value::Text(text) => SqlValue::Text(text.clone()),
        Value::Blob(bytes) => SqlValue::Blob(bytes.clone()),
    }
}

fn from_stored(value: SqlValue) -> Value {
    match value {
        SqlValue::Null => Value::Null,
        SqlValue::Integer(number) => Value::Integer(number),
        SqlValue::Real(number) => Value::Real(number),
        SqlValue::Text(text) => Value::Text(text),
        SqlValue::Blob(bytes) => Value::Blob(bytes),
    }
}
