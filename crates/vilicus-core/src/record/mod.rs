//! Record writes (FR-18, FR-58, AD-6, AD-7, AD-9): the typed record API a module writes through,
//! the provenance the Core stamps on each write, and the row writer under both.
//!
//! [`run_call`] runs one call of a module in one `BEGIN IMMEDIATE` transaction on the module
//! file's write handle, and gives the module's code the port of `vilicus-module-api`,
//! [`Records`](vilicus_module_api::Records): insert, update by id with the expected revision,
//! delete by id. For each write the Core stamps the envelope (id, `source`, `author`, times,
//! `rev`) and computes `taint`, `text_taint` and `data_types` from the [`Call`] (who makes it, on
//! what authority) and from the records the write is derived from; the module gives field values
//! and input ids only. A refused write rolls back the whole call. In the same transaction the
//! Core journals each record the call changes (`journal`, AD-26), writes the call's effect
//! intents to the outbox (AD-28) and records the event a consumer's call reacts to (AD-10); a
//! repeated call, by its principal, `source` and `call_id`, returns the first one's result
//! without running again. Effect outcomes are recorded after the commit (`effect`), and the
//! journal's retention purge runs per partition kind ([`purge_expired_journal`]).
//!
//! The row writer holds each field a write gives to its declaration (D98, D104, I40), and each
//! envelope value to its stored form (`envelope`, D146), and refuses the whole write with a typed
//! [`RecordError`] when one value is outside it: every field is checked first, its storage class
//! and its closed type or maximum length by
//! [`Field::check_value`](vilicus_module_api::Field::check_value), and a reviewed-vocabulary label
//! against the labels confirmed in that file, read under the write lock; only then does the
//! statement run. A value is never truncated or converted: it is stored as given, or the write
//! is refused. The row writer, label confirmation and the check of stored rows are crate-private,
//! and [`run_call`] needs a write handle, which only the Core opens: no crate outside the Core
//! can write a row, choose an envelope or confirm a label, which has no surface in V0.1 (FR-50).
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

// The row writer's own transactions and label confirmation (no surface in V0.1, FR-50) have no
// caller but the tests and the write path fuzz test yet; the check of stored rows has the
// migration runner (Story 3.7).
#![cfg_attr(
    not(any(test, feature = "testing")),
    allow(
        dead_code,
        reason = "label confirmation and the row writer's own transactions have no caller outside tests yet"
    )
)]

mod call;
mod effect;
mod envelope;
#[cfg(any(test, feature = "testing"))]
mod fuzz;
mod journal;
mod provenance;

#[cfg(test)]
mod inspect;
#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
pub(crate) mod tests_call;
#[cfg(test)]
mod tests_deletion;
#[cfg(test)]
mod tests_journal;
#[cfg(test)]
mod tests_migration;

use core::fmt;

use vilicus_module_api::{
    DataType, ENVELOPE, Field, FieldKind, ModuleDeclaration, Structured, Table, Value, ValueError,
    WriteError, check_vocabulary_label,
};
use vilicus_storage::{Handle, Inspect, SqlValue, Write};
use vilicus_types::{Id, UtcMillis};

use crate::availability::ModuleUnavailable;

pub use call::{
    Authority, Call, CallOutcome, CallResult, Consumed, EarlierCall, EventDelivery, Invocation,
    MAX_WRITE_INPUTS, RecordChange, RequestedEffect, Stamper, run_call,
};
pub(crate) use call::{read_record, run_call_reading};
pub use effect::{
    ReportTo, UnknownEffect, effects_to_perform, record_effect_outcome, retry_failed_effect,
};
#[cfg(any(test, feature = "testing"))]
pub use fuzz::{WriteFuzzError, WriteFuzzReport, WriteKind, WritePath};
pub(crate) use journal::decode_provenance;
pub use journal::{
    INPUT_COLUMNS, JournaledInput, Row, decode_inputs, decode_row, journal_retention,
    purge_expired_journal,
};
pub use provenance::{DRAFT_RUN_WORDS, RecordProvenance};

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
    /// An envelope value is outside its stored form: a `source`, `taint`, `text_taint` or
    /// `data_types` text the Core does not write, a `text_taint` below the `taint`, or data types
    /// the record kind does not declare (AD-6).
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
    /// An update or a delete names a record the table does not hold.
    RecordNotFound {
        /// The table.
        table: &'static str,
    },
    /// An update expects another revision than the stored one (AD-9).
    StaleRevision {
        /// The table.
        table: &'static str,
    },
    /// A derived write of a call no member made or approved declares no input (AD-7, I9).
    MissingInputs {
        /// The table.
        table: &'static str,
    },
    /// A write has more than `MAX_WRITE_INPUTS` inputs, declared and implicit together.
    TooManyInputs {
        /// The table.
        table: &'static str,
    },
    /// An input is neither a record of this file nor one the call read.
    UnknownInput {
        /// The table written to.
        table: &'static str,
    },
    /// The data types the record would hold are not all declared by its table (D103).
    UndeclaredDataType {
        /// The table.
        table: &'static str,
    },
    /// A write's `data_types` does not hold every data type of its inputs (I43).
    DataTypesBelowInputs {
        /// The table.
        table: &'static str,
    },
    /// The call does not hold together: a member's own action from a principal other than
    /// `Member` or `Cli`, an approval for a principal other than `AiTask` or `Plugin`, a `Member`
    /// or `Cli` call that is not the member's own action, a `source` its principal does not
    /// produce, or an event delivery to a principal other than `Event`, or none to an `Event`.
    InconsistentCall,
    /// An effect intent whose effect is not an identifier, or whose idempotency key is empty
    /// (AD-28).
    InvalidEffect,
    /// A journal row of the file does not decode.
    InvalidJournal,
    /// An effect request of a name and idempotency key the file holds for another payload or
    /// another caller (AD-28).
    EffectConflict,
    /// A call whose principal, `source` and `call_id` name an earlier call of the file that
    /// carried another request hash: the call id is reused for another request.
    CallIdReused,
    /// An event of a topic the module does not declare (AD-29).
    UnknownTopic,
    /// An event of a topic of another module: the Core stamps the real emitter, and a claim of
    /// another is refused (D20).
    ForeignTopic,
    /// An event or a link request about a record the call did not change.
    UnchangedRecord,
    /// An event whose payload is longer than `EVENT_PAYLOAD_MAX_LEN`.
    PayloadTooLong,
    /// A link request whose target module is not a module name, or is the module itself (AD-10).
    InvalidLink,
    /// A consumer's call requested an outbound effect or emitted an event: a write in reaction to
    /// an event is at most tier 1 (AD-27, D20), and an event does not trigger another.
    NotInConsumer,
    /// An event's provenance in the outbox does not decode.
    InvalidEvent,
    /// A read of a query no registered module offers under that name (AD-5).
    UnknownQuery,
    /// A read of a query whose access list does not name the calling module (AD-5).
    QueryNotAllowed {
        /// The query.
        query: &'static str,
    },
    /// A read of a module whose file in the call's scope is not ready, or not open (AD-54).
    Unavailable(ModuleUnavailable),
    /// The module's code ended the call with its own error; the call was rolled back.
    Aborted(WriteError),
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
            Self::StaleRevision { table } => {
                write!(formatter, "{table}: the record changed since it was read")
            }
            Self::MissingInputs { table } => {
                write!(formatter, "{table}: a derived write declares no input")
            }
            Self::TooManyInputs { table } => {
                write!(
                    formatter,
                    "{table}: a write with more inputs than the Core accepts"
                )
            }
            Self::UnknownInput { table } => {
                write!(formatter, "{table}: an input record the Core does not know")
            }
            Self::UndeclaredDataType { table } => {
                write!(formatter, "{table}: a data type the table does not declare")
            }
            Self::DataTypesBelowInputs { table } => {
                write!(
                    formatter,
                    "{table}: data types missing a data type of an input"
                )
            }
            Self::InconsistentCall => {
                formatter.write_str("the call's authority does not fit its principal")
            }
            Self::InvalidEffect => {
                formatter.write_str("an effect intent needs an identifier and an idempotency key")
            }
            Self::InvalidJournal => formatter.write_str("a journal row of the file is malformed"),
            Self::EffectConflict => {
                formatter.write_str("an effect of that name and key exists for another request")
            }
            Self::CallIdReused => formatter.write_str("the call id names another request"),
            Self::UnknownTopic => formatter.write_str("the module declares no such topic"),
            Self::PayloadTooLong => formatter.write_str("an event payload longer than the bound"),
            Self::ForeignTopic => formatter.write_str("a topic of another module"),
            Self::UnchangedRecord => {
                formatter.write_str("an event or a link about a record the call did not change")
            }
            Self::InvalidLink => {
                formatter.write_str("a link needs another module's name as its target module")
            }
            Self::NotInConsumer => {
                formatter.write_str("a consumer of an event requests no effect and emits no event")
            }
            Self::InvalidEvent => formatter.write_str("an event of the outbox is malformed"),
            Self::UnknownQuery => formatter.write_str("no module offers such a query"),
            Self::QueryNotAllowed { query } => {
                write!(
                    formatter,
                    "query {query}: its access list does not name the caller"
                )
            }
            Self::Unavailable(unavailable) => write!(formatter, "{unavailable}"),
            Self::Aborted(error) => write!(formatter, "the module ended the call: {error}"),
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

/// Inserts a record into `table` of `module`'s file (AD-9) in a transaction of its own: the
/// envelope columns as given, every one of them, and the fields, each optional field left out
/// being stored `NULL`. The write is refused, and nothing stored, unless every value meets its
/// declaration and the envelope's `data_types` holds every type of `inputs_data_types`, the
/// union of the data types of the records the write is derived from (I43).
pub(crate) fn insert(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    table: &str,
    envelope: &[(&str, Value)],
    fields: &[(&str, Value)],
    inputs_data_types: &[DataType],
) -> Result<(), RecordError> {
    let table = declared_table(module, table)?;
    in_write_transaction(handle, || {
        insert_row(handle, table, envelope, fields, inputs_data_types)
    })
}

/// Updates the record `id` of `table` in a transaction of its own: the envelope columns and
/// fields given, and no other; the record's `id` never changes. The write is refused, and nothing
/// stored, unless every value meets its declaration, the record exists and, when
/// `inputs_data_types` is not empty, the envelope gives a `data_types` holding each of them.
pub(crate) fn update(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    table: &str,
    id: Id,
    envelope: &[(&str, Value)],
    fields: &[(&str, Value)],
    inputs_data_types: &[DataType],
) -> Result<(), RecordError> {
    let table = declared_table(module, table)?;
    in_write_transaction(handle, || {
        update_row(handle, table, id, envelope, fields, inputs_data_types)
    })
}

/// The insert of [`insert`], inside a transaction its caller holds.
fn insert_row(
    handle: &Handle<Write>,
    table: &'static Table,
    envelope: &[(&str, Value)],
    fields: &[(&str, Value)],
    inputs_data_types: &[DataType],
) -> Result<(), RecordError> {
    let mut columns = check_envelope(table, envelope, Completeness::Every)?;
    check_inputs_data_types(table, &columns, inputs_data_types)?;
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
}

/// The update of [`update`], inside a transaction its caller holds.
fn update_row(
    handle: &Handle<Write>,
    table: &'static Table,
    id: Id,
    envelope: &[(&str, Value)],
    fields: &[(&str, Value)],
    inputs_data_types: &[DataType],
) -> Result<(), RecordError> {
    let mut columns = check_envelope(table, envelope, Completeness::Some)?;
    check_inputs_data_types(table, &columns, inputs_data_types)?;
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
}

/// Refuses envelope columns whose `data_types` misses a data type of the write's inputs, or that
/// leave `data_types` out although the write has inputs: a derived record holds at least the
/// union of its inputs' sets (D103, I43), whoever computed its envelope.
fn check_inputs_data_types(
    table: &'static Table,
    columns: &[Checked<'_>],
    inputs_data_types: &[DataType],
) -> Result<(), RecordError> {
    if inputs_data_types.is_empty() {
        return Ok(());
    }
    let given =
        columns.iter().find_map(
            |checked| match (envelope::rule(checked.column), checked.value) {
                (Some(envelope::EnvelopeRule::DataTypes), Value::Text(text)) => Some(text),
                _ => None,
            },
        );
    let holds_inputs = given.is_some_and(|text| {
        inputs_data_types
            .iter()
            .all(|data_type| text.split(',').any(|name| name == data_type.as_str()))
    });
    if holds_inputs {
        Ok(())
    } else {
        Err(RecordError::DataTypesBelowInputs { table: table.name })
    }
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
            let mut labels = (Value::Null, Value::Null);
            for (column, value) in ENVELOPE.iter().zip(stored.by_ref()) {
                envelope::check(table, column, &value)?;
                match envelope::rule(column.name) {
                    Some(envelope::EnvelopeRule::Taint) => labels.0 = value,
                    Some(envelope::EnvelopeRule::TextTaint) => labels.1 = value,
                    _ => {}
                }
            }
            envelope::check_labels(table, &labels.0, &labels.1)?;
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
/// `body` or the `COMMIT` fails, or `body` panics, the transaction is rolled back, so a refused
/// write leaves the file as it was and the handle never stays inside the transaction.
fn in_write_transaction<T>(
    handle: &Handle<Write>,
    body: impl FnOnce() -> Result<T, RecordError>,
) -> Result<T, RecordError> {
    handle.execute_batch("BEGIN IMMEDIATE")?;
    let transaction = OpenTransaction { handle, open: true };
    let value = body()?;
    transaction.commit()?;
    Ok(value)
}

/// A write transaction that rolls back when it is dropped uncommitted: on a refusal, on a failed
/// `COMMIT` (a deferred constraint leaves the transaction open) and while a panic unwinds, in
/// module code or in the Core's, so the next call on the handle starts from the committed file
/// (AD-9).
struct OpenTransaction<'a> {
    handle: &'a Handle<Write>,
    open: bool,
}

impl OpenTransaction<'_> {
    fn commit(mut self) -> Result<(), RecordError> {
        self.handle.execute_batch("COMMIT")?;
        self.open = false;
        Ok(())
    }
}

impl Drop for OpenTransaction<'_> {
    fn drop(&mut self) {
        if self.open {
            // The rollback's own failure is not reported: the refusal, or the panic, says why
            // nothing was written.
            let _ = self.handle.execute_batch("ROLLBACK");
        }
    }
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
    check_given_labels(table, &checked)?;
    Ok(checked)
}

/// The two labels of a write go together: given both, `text_taint` is not below `taint`; given
/// one, the other is missing, so no write can leave a row's labels apart (AD-6).
fn check_given_labels(table: &'static Table, checked: &[Checked<'_>]) -> Result<(), RecordError> {
    let given = |wanted| {
        checked
            .iter()
            .find(|given| envelope::rule(given.column) == Some(wanted))
            .map(|given| given.value)
    };
    match (
        given(envelope::EnvelopeRule::Taint),
        given(envelope::EnvelopeRule::TextTaint),
    ) {
        (None, None) => Ok(()),
        (Some(taint), Some(text_taint)) => {
            envelope::check_labels(table, taint, text_taint).map(drop)
        }
        (Some(_), None) => Err(RecordError::MissingColumn {
            table: table.name,
            column: "text_taint",
        }),
        (None, Some(_)) => Err(RecordError::MissingColumn {
            table: table.name,
            column: "taint",
        }),
    }
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
