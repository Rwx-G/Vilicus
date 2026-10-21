//! The typed record API (AD-9, FR-18): the only way a module writes its records. A module inserts
//! a record, updates one by id with the revision it expects, or deletes one by id; it gives the
//! values of its declared fields and the ids of the records a write is derived from, and nothing
//! else. The Core implements this port over its storage layer: in the call's write transaction it
//! checks every value against its declaration, stamps the envelope (id, `source`, `author`, times,
//! `rev`), and computes `taint`, `text_taint` and `data_types` from who makes the call and from
//! the inputs (AD-6, AD-7). No method takes an envelope value, so a module cannot choose its own provenance,
//! and no method runs SQL. The Core journals every write in the same transaction (AD-26).
//!
//! A module never performs an outbound effect: it requests one, with a business idempotency key
//! derived from the effect's parameters, and the Core performs it after the call commits (AD-28).
//! Nor does it reach another module's file: it emits an event about a record it changed, which
//! the Core delivers to the consumers the topic allows once the call commits, or requests a link
//! from such a record to a record of another module, which the Core registers in the link table
//! of the partition after the commit (AD-10, AD-29); and it reads another module's record through
//! that module's typed API, which the Core serves (AD-5).
//!
//! A module's code holds a `&mut dyn Records` for the duration of one call:
//!
//! ```
//! use vilicus_module_api::{Id, Records, Rev, Value, WriteError};
//!
//! /// Adds an item derived from the recipe `recipe`, then marks the list it belongs to.
//! fn add_from_recipe(
//!     records: &mut dyn Records,
//!     recipe: Id,
//!     list: Id,
//!     list_rev: Rev,
//! ) -> Result<Id, WriteError> {
//!     let item = records.insert(
//!         "items",
//!         &[("label", Value::Text("Pommes".into())), ("status", Value::Text("open".into()))],
//!         &[recipe],
//!     )?;
//!     records.update("lists", list, list_rev, &[("status", Value::Text("open".into()))], &[recipe])?;
//!     Ok(item.id)
//! }
//! ```

use core::fmt;

use vilicus_types::{Id, Rev};

use crate::query::ReadRecord;
use crate::value::{Value, ValueError};

/// The record API a module writes through, implemented by the Core for one call on one module
/// file. Each method writes one record in the call's transaction; when a write is refused, the
/// whole call is rolled back, the writes before it included, and every later write of the call is
/// refused with [`WriteError::CallRefused`].
///
/// `fields` names declared fields only, each once; `inputs` are the ids of the records the write
/// is derived from, which the Core reads to compute the stored labels and `data_types` (AD-7,
/// I9, I43). A call that no member makes or approves, other than a plugin's or an adapter's,
/// declares at least one input on every insert and update, or the write is refused.
pub trait Records {
    /// Inserts a record into `table`: the fields given, each optional field left out being stored
    /// `NULL`. Returns the id and revision the Core stamped.
    fn insert(
        &mut self,
        table: &str,
        fields: &[(&str, Value)],
        inputs: &[Id],
    ) -> Result<Written, WriteError>;

    /// Updates the fields given of the record `id` of `table`, whose stored revision must be
    /// `expected`. Returns its new revision.
    fn update(
        &mut self,
        table: &str,
        id: Id,
        expected: Rev,
        fields: &[(&str, Value)],
        inputs: &[Id],
    ) -> Result<Written, WriteError>;

    /// Deletes the record `id` of `table`.
    fn delete(&mut self, table: &str, id: Id) -> Result<(), WriteError>;

    /// Requests the outbound effect `effect`, an identifier, with `payload` as its parameters
    /// and `idempotency_key`, a key the module derives from those parameters, so the same
    /// effect asked twice has the same key (AD-28). The request is written in the call's
    /// transaction and the Core performs the effect after the commit; it is never performed when
    /// the call is rolled back. A request of a name and key the file already holds, with the same
    /// payload and from the same caller, is that earlier request: nothing is written, and its id
    /// is returned; with another payload or from another caller it is
    /// [`WriteError::EffectConflict`]. Returns the id of the request.
    fn request_effect(
        &mut self,
        effect: &str,
        idempotency_key: &[u8],
        payload: &[u8],
    ) -> Result<Id, WriteError>;

    /// Emits an event of `topic`, one of the module's own topics, about `record`, a record this
    /// call inserted, updated or deleted, with `payload` encoded at the topic's current version
    /// (AD-29), at most [`EVENT_PAYLOAD_MAX_LEN`](crate::EVENT_PAYLOAD_MAX_LEN) bytes
    /// ([`WriteError::PayloadTooLong`]). The event is written in the call's transaction and
    /// delivered after the commit;
    /// it is never delivered when the call is rolled back. The Core stamps the emitter, the
    /// payload version and the provenance of `record` as the call leaves it, which every write of
    /// a consumer derives from (AD-27). A topic of another module is
    /// [`WriteError::ForeignTopic`]. Returns the id of the event.
    fn emit(&mut self, topic: &str, record: Id, payload: &[u8]) -> Result<Id, WriteError>;

    /// Requests a link from `record`, a record this call inserted or updated, to the record
    /// `target` of the module `target_module` in the same partition (AD-10). The request is
    /// written in the call's transaction; the Core registers the link in the partition's link
    /// table after the commit, never in this transaction, and only when `target` is a record of
    /// that module in the same partition. Returns the id of the request.
    fn request_link(
        &mut self,
        record: Id,
        target_module: &str,
        target: Id,
    ) -> Result<Id, WriteError>;

    /// Reads the record `id` through the query `query` of the module `module`'s typed API (AD-5):
    /// the fields the query names, as that module's file holds them, read on a read connection of
    /// that file, never in this call's transaction. The Core looks the record up only in the
    /// partitions in this call's scope: the partition of the call's own file, and the household
    /// partition when that file is a member's. A query the module does not offer is
    /// [`WriteError::UnknownQuery`], one whose access list does not name this module
    /// [`WriteError::QueryNotAllowed`], a file in scope that is not ready
    /// [`WriteError::ModuleUnavailable`], and a record the query's table does not hold in scope
    /// [`WriteError::RecordNotFound`]. Like a refused write, a refused read ends the call.
    ///
    /// The record's provenance stays with the Core, and every write the call makes after the read
    /// derives from it, whether the write names it as an input or not, so reading another
    /// module's record never lowers what a write stores (AD-7).
    fn read(&mut self, module: &str, query: &str, id: Id) -> Result<ReadRecord, WriteError>;
}

/// A record the Core wrote: its id and the revision it now has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Written {
    /// The record's id, stamped by the Core on insert.
    pub id: Id,
    /// The record's revision after the write.
    pub rev: Rev,
}

/// Why the Core refused a write of the typed record API. No variant carries a value or a name the
/// caller chose: only the names the module's declaration holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteError {
    /// The module declares no table of the name written to.
    UnknownTable,
    /// A field written to is not declared by the table; envelope columns are never fields.
    UnknownColumn {
        /// The table.
        table: &'static str,
    },
    /// A write gives a field twice.
    DuplicateColumn {
        /// The table.
        table: &'static str,
        /// The field.
        column: &'static str,
    },
    /// An insert leaves out a field that is not optional.
    MissingColumn {
        /// The table.
        table: &'static str,
        /// The field.
        column: &'static str,
    },
    /// An update gives no field.
    EmptyUpdate {
        /// The table.
        table: &'static str,
    },
    /// A value is outside its field's declaration (D98).
    Invalid {
        /// The table.
        table: &'static str,
        /// The field.
        column: &'static str,
        /// The rule the value breaks.
        error: ValueError,
    },
    /// A reviewed-vocabulary label is not one an adult confirmed in this file (D104).
    UnconfirmedLabel {
        /// The table.
        table: &'static str,
        /// The field.
        column: &'static str,
        /// The vocabulary the field declares.
        vocabulary: &'static str,
    },
    /// An update or a delete names a record the table does not hold.
    RecordNotFound {
        /// The table.
        table: &'static str,
    },
    /// An update expects another revision than the stored one: the record changed since its
    /// caller read it.
    StaleRevision {
        /// The table.
        table: &'static str,
    },
    /// A derived write of a call no member made or approved declares no input (I9).
    MissingInputs {
        /// The table.
        table: &'static str,
    },
    /// A write has more inputs, declared and implicit together, than the Core accepts.
    TooManyInputs {
        /// The table.
        table: &'static str,
    },
    /// An input is a record the Core does not know: neither in this file nor among the records
    /// the call read.
    UnknownInput {
        /// The table.
        table: &'static str,
    },
    /// The data types the record would hold are not all declared by its table (D103).
    UndeclaredDataType {
        /// The table.
        table: &'static str,
    },
    /// An effect request whose effect is not an identifier, or whose idempotency key is empty.
    InvalidEffect,
    /// An effect request of a name and key the file holds for another request: one key names one
    /// effect, with one payload, of one caller.
    EffectConflict,
    /// An event of a topic the module does not declare.
    UnknownTopic,
    /// An event of a topic of another module: the Core stamps the real emitter, and a claim of
    /// another is refused (D20).
    ForeignTopic,
    /// An event or a link request about a record this call did not change.
    UnchangedRecord,
    /// An event whose payload is longer than
    /// [`EVENT_PAYLOAD_MAX_LEN`](crate::EVENT_PAYLOAD_MAX_LEN).
    PayloadTooLong,
    /// A link request to a module that is not a module name, or to the module itself.
    InvalidLink,
    /// A consumer's call requested an outbound effect or emitted an event: a write in reaction to
    /// an event is at most tier 1 (AD-27, D20), and an event does not trigger another.
    NotInConsumer,
    /// A read of a query no registered module offers under that name.
    UnknownQuery,
    /// A read of a query whose access list does not name the calling module (AD-5).
    QueryNotAllowed,
    /// A read of a module whose file in the call's scope is not ready (AD-54).
    ModuleUnavailable,
    /// An earlier write of this call was refused; the call is rolled back.
    CallRefused,
    /// The Core could not complete the write; the call is rolled back.
    Failed,
}

impl fmt::Display for WriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTable => formatter.write_str("the module declares no such table"),
            Self::UnknownColumn { table } => {
                write!(formatter, "{table}: a field the table does not declare")
            }
            Self::DuplicateColumn { table, column } => {
                write!(formatter, "{table}.{column} given twice")
            }
            Self::MissingColumn { table, column } => {
                write!(formatter, "{table}.{column} is required")
            }
            Self::EmptyUpdate { table } => write!(formatter, "{table}: an update gives no field"),
            Self::Invalid {
                table,
                column,
                error,
            } => write!(formatter, "{table}.{column}: {error}"),
            Self::UnconfirmedLabel {
                table,
                column,
                vocabulary,
            } => write!(
                formatter,
                "{table}.{column}: a label not confirmed in vocabulary {vocabulary}"
            ),
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
            Self::InvalidEffect => {
                formatter.write_str("an effect request needs an identifier and an idempotency key")
            }
            Self::EffectConflict => {
                formatter.write_str("an effect of that name and key exists for another request")
            }
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
            Self::UnknownQuery => formatter.write_str("no module offers such a query"),
            Self::QueryNotAllowed => {
                formatter.write_str("the query's access list does not name this module")
            }
            Self::ModuleUnavailable => {
                formatter.write_str("the file of the module read is not ready")
            }
            Self::CallRefused => formatter.write_str("an earlier write of this call was refused"),
            Self::Failed => formatter.write_str("the write failed and the call was rolled back"),
        }
    }
}

impl std::error::Error for WriteError {}
