//! What a module declares: its tables, each one record kind with its data types and its fields,
//! its FTS5 tables and its migrations (AD-6, AD-9, D98, D103, D104, D127), its tools with the
//! capability matrix sections they implement (FR-22, I13, AD-48), and the event topics it emits
//! and consumes (FR-24, AD-29).
//!
//! Every declaration is plain `'static` data built in a `const` item, so the set of tables,
//! fields, value sets, data types and tools is fixed when the binary is built; nothing in this
//! crate builds or extends one at run time.

use vilicus_types::DataType;

use crate::event::{Consumer, Topic};
use crate::tool::Tool;

/// The SQL type a column is declared with in the module's migrations; the registry compares it
/// with `PRAGMA table_xinfo` of the migrated file, ignoring ASCII case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SqlType {
    /// `INTEGER`.
    Integer,
    /// `TEXT`.
    Text,
    /// `BLOB`.
    Blob,
}

impl SqlType {
    /// The type as written in a `CREATE TABLE` statement.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Integer => "INTEGER",
            Self::Text => "TEXT",
            Self::Blob => "BLOB",
        }
    }
}

/// A column of the record envelope (AD-6), which the Core stamps on every write; a module never
/// writes it and never declares a field of the same name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EnvelopeColumn {
    /// The column name.
    pub name: &'static str,
    /// Its SQL type.
    pub sql_type: SqlType,
    /// True when the column is `NOT NULL`.
    pub not_null: bool,
    /// True for the primary key, the record `id`.
    pub primary_key: bool,
}

const fn envelope(
    name: &'static str,
    sql_type: SqlType,
    not_null: bool,
    primary_key: bool,
) -> EnvelopeColumn {
    EnvelopeColumn {
        name,
        sql_type,
        not_null,
        primary_key,
    }
}

/// The record envelope every module table carries, in the order of AD-6. Ids are 16-byte UUIDv7
/// blobs and times UTC integer milliseconds (spine conventions); `taint` labels the record's
/// structured fields and `text_taint` the record read with its free text; `author` is empty for
/// the principals the conventions name, so it may be `NULL`. The Core stamps every column on every
/// write of the typed record API ([`Records`](crate::Records)), in the stored forms of D146.
pub const ENVELOPE: &[EnvelopeColumn] = &[
    envelope("id", SqlType::Blob, true, true),
    envelope("source", SqlType::Text, true, false),
    envelope("taint", SqlType::Text, true, false),
    envelope("text_taint", SqlType::Text, true, false),
    envelope("data_types", SqlType::Text, true, false),
    envelope("author", SqlType::Blob, false, false),
    envelope("created_at", SqlType::Integer, true, false),
    envelope("updated_at", SqlType::Integer, true, false),
    envelope("rev", SqlType::Integer, true, false),
];

/// A structured value set, fixed at build time (D104): a field whose values cannot carry free
/// text, so reading it does not taint a session (D70).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Structured {
    /// A compiled enumeration: one of the listed names, each an identifier
    /// ([`IDENTIFIER_MAX_LEN`](crate::IDENTIFIER_MAX_LEN) characters at most, lowercase ASCII
    /// letters, digits and underscores, starting with a letter). Stored as `TEXT`.
    Enumeration(&'static [&'static str]),
    /// An integer in `min..=max`. Stored as `INTEGER`.
    Integer {
        /// The smallest value accepted.
        min: i64,
        /// The largest value accepted.
        max: i64,
    },
    /// A calendar date. Stored as `TEXT`.
    Date,
    /// An instant, in UTC integer milliseconds (spine conventions, Time). Stored as `INTEGER`.
    Timestamp,
    /// An opaque UUIDv7, the 16-byte form of the spine conventions. Stored as `BLOB`.
    Uuid,
    /// A reviewed vocabulary, by name: only labels an adult confirmed are accepted (D104,
    /// Story 3.4). Stored as `TEXT`.
    ReviewedVocabulary(&'static str),
}

/// Whether a field is structured or free text (FR-58).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldKind {
    /// A value from a set fixed at build time.
    Structured(Structured),
    /// Free text, at most `max_len` characters; anything a run-time vocabulary holds is free text
    /// unless it is a reviewed vocabulary (D104). Stored as `TEXT`.
    FreeText {
        /// The maximum length, in characters; 0 is refused.
        max_len: u32,
    },
}

impl FieldKind {
    /// The SQL type the field is stored as.
    pub const fn sql_type(self) -> SqlType {
        match self {
            Self::Structured(Structured::Integer { .. } | Structured::Timestamp) => {
                SqlType::Integer
            }
            Self::Structured(Structured::Uuid) => SqlType::Blob,
            Self::Structured(
                Structured::Enumeration(_) | Structured::Date | Structured::ReviewedVocabulary(_),
            )
            | Self::FreeText { .. } => SqlType::Text,
        }
    }
}

/// A field of a table: a column beside the envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Field {
    /// The column name, an identifier.
    pub name: &'static str,
    /// Structured or free text.
    pub kind: FieldKind,
    /// True when the field may be absent (`NULL`); otherwise the column is `NOT NULL`.
    pub optional: bool,
}

/// A module table, which holds one record kind: the envelope, then the declared fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Table {
    /// The table name, an identifier.
    pub name: &'static str,
    /// The data types the record kind's fields may hold (FR-68, D103); at least one.
    pub data_types: &'static [DataType],
    /// The fields beside the envelope.
    pub fields: &'static [Field],
    /// True for a low-risk record kind the module declares exempt from the elevated queue,
    /// reviewed with the module (PRD FR-28, `doc/capability-matrix.md` Legend, *exempt*): a
    /// tainted AI or plugin session writes it without elevation, but from such a principal it
    /// accepts structured fields only, so free text the assistant writes there is still elevated
    /// (D104, DC-59). [`Table::accepts_without_elevation`] states which writes the exemption
    /// covers; elevating the others is the pipeline's.
    pub elevation_exempt: bool,
}

impl Table {
    /// True when a write of an AI or plugin principal giving `fields` to this record kind needs
    /// no elevation from a tainted session (D104): the kind is exempt, and every field given is a
    /// structured field it declares. A free-text field, or a name the kind does not declare,
    /// leaves the write to the elevated queue.
    pub fn accepts_without_elevation(&self, fields: &[&str]) -> bool {
        self.elevation_exempt
            && fields.iter().all(|given| {
                self.fields.iter().any(|field| {
                    field.name == *given && matches!(field.kind, FieldKind::Structured(_))
                })
            })
    }
}

/// A built-in FTS5 tokenizer, the allowlist of D127.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fts5Tokenizer {
    /// `unicode61`, FTS5's default.
    Unicode61,
    /// `ascii`.
    Ascii,
    /// `porter`.
    Porter,
    /// `trigram`.
    Trigram,
}

impl Fts5Tokenizer {
    /// Every tokenizer of the allowlist.
    pub const ALL: &'static [Self] = &[Self::Unicode61, Self::Ascii, Self::Porter, Self::Trigram];

    /// The tokenizer's name in a `tokenize=` option.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unicode61 => "unicode61",
            Self::Ascii => "ascii",
            Self::Porter => "porter",
            Self::Trigram => "trigram",
        }
    }
}

/// Where an FTS5 table's indexed text lives (D127): never a copy of its own, so the text stays in
/// an enveloped table, with its provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fts5Content {
    /// `content=''`: a contentless index.
    Contentless,
    /// `content='<table>'`: an external-content index over a table of the same module.
    Table(&'static str),
}

/// An FTS5 table of the module (D127). Its migration creates it with exactly these arguments and
/// sets its `secure-delete` option to 1 (D132), which the registry checks in the migrated file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fts5Table {
    /// The table name, an identifier.
    pub name: &'static str,
    /// The indexed columns, in order; with [`Fts5Content::Table`], fields of that table.
    pub columns: &'static [&'static str],
    /// The tokenizer.
    pub tokenizer: Fts5Tokenizer,
    /// Where the indexed text lives.
    pub content: Fts5Content,
}

/// The suffixes FTS5 gives its shadow tables, `<table>_<suffix>`; no module table may take one.
pub const FTS5_SHADOW_SUFFIXES: &[&str] = &["config", "content", "data", "docsize", "idx"];

/// One migration of the module's track (AD-23), declarative SQL embedded in the binary with its
/// frozen hash (D21). Its version is its position in [`ModuleDeclaration::migrations`], from 1.
///
/// The frozen hash is the SHA-256 of `sql`'s bytes, written once the migration is released and
/// never changed, as `sha256: vilicus_module_api::sha256_hex("<64 hex digits>")`. Before any
/// migration runs, the Core computes the digest of each migration's SQL and refuses the module's
/// migrations when one differs from its frozen hash; a file records the frozen hash of every
/// migration it ran, and the Core refuses a file whose record differs from the declaration, so a
/// released migration edited later never runs and never passes for the one a file ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Migration {
    /// The SQL, run by the Core's migration runner under the migration policy.
    pub sql: &'static str,
    /// The SHA-256 of `sql`, frozen with the migration.
    pub sha256: [u8; 32],
}

/// Everything a module declares: its file and its tools. A module crate exposes one as a `const`
/// item and checks it there with [`ModuleDeclaration::assert_valid`], so a declaration the
/// registry would refuse fails that crate's build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ModuleDeclaration {
    /// The module name (`vilicus_types::ModuleName` grammar), which names its files.
    pub name: &'static str,
    /// The module's tables.
    pub tables: &'static [Table],
    /// The module's FTS5 tables.
    pub fts5_tables: &'static [Fts5Table],
    /// The module's migrations, in order: the first is version 1.
    pub migrations: &'static [Migration],
    /// The sections of `doc/capability-matrix.md` the module implements, by number (`2`, `10a`):
    /// every row of these sections that a tool can implement needs one of the module's tools,
    /// and no other module may claim them.
    pub matrix_sections: &'static [&'static str],
    /// The module's tools.
    pub tools: &'static [Tool],
    /// The topics the module emits, each with its payload version and access list.
    pub topics: &'static [Topic],
    /// The module's consumers, each of one topic.
    pub consumers: &'static [Consumer],
}

impl ModuleDeclaration {
    /// The schema version the module's last migration brings a file to.
    pub const fn latest_version(&self) -> u32 {
        // A declaration's migrations are a static list written out in a module crate; no build
        // holds 2^32 of them.
        self.migrations.len() as u32
    }

    /// The table named `name`.
    pub fn table(&self, name: &str) -> Option<&'static Table> {
        self.tables.iter().find(|table| table.name == name)
    }

    /// The FTS5 table named `name`.
    pub fn fts5_table(&self, name: &str) -> Option<&'static Fts5Table> {
        self.fts5_tables.iter().find(|table| table.name == name)
    }

    /// The tool named `name`.
    pub fn tool(&self, name: &str) -> Option<&'static Tool> {
        self.tools.iter().find(|tool| tool.name == name)
    }

    /// The topic named `name`, among those the module emits.
    pub fn topic(&self, name: &str) -> Option<&'static Topic> {
        self.topics.iter().find(|topic| topic.name == name)
    }

    /// The module's consumer of the topic `topic`, if it has one.
    pub fn consumer_of(&self, topic: &str) -> Option<&'static Consumer> {
        self.consumers
            .iter()
            .find(|consumer| consumer.topic == topic)
    }
}
