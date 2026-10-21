//! The comparison of a module's declaration with the schema its migrations produced in a file
//! (AD-6, AD-9, D98, D127, D132): the Rust declaration is the single source of truth, and any
//! difference in either direction is a [`SchemaError`]. A difference is anything with behaviour:
//! a clause that writes, deletes, replaces or converts rows on its own (`REFERENCES` with its
//! actions, `ON CONFLICT REPLACE`, `DEFAULT`, `COLLATE`, `CHECK`, a `UNIQUE` constraint or index)
//! acts outside the typed record API, so it is refused like a missing column.
//!
//! The file holds exactly:
//! - the Core tables of `vilicus_storage::CORE_TABLES` with their indexes, which the Core
//!   migration track alone creates, and SQLite's internal objects (`sqlite_` prefix, which no
//!   migration can create);
//! - each declared table, created by the one statement its declaration implies, compared token
//!   by token ([`canonical_table`]): the envelope columns, then the declared fields in their
//!   order, each with its type, `NOT NULL` unless optional and `PRIMARY KEY` for `id` only, and
//!   no other clause; `STRICT` is the only table option allowed. Its columns are also read back
//!   through `PRAGMA table_xinfo`, it has no foreign key, and its indexes are the one its primary
//!   key makes and plain indexes made by `CREATE INDEX` over its columns: not `UNIQUE`, not
//!   partial, no expression, the `BINARY` collation;
//! - each declared FTS5 table, an `fts5` virtual table with its declared arguments and
//!   `secure-delete` at 1, and exactly the shadow tables FTS5 makes for it in that mode, each
//!   created by the statement FTS5 writes ([`FTS5_SHADOWS`]).
//!
//! Anything else (another table, a view, a trigger, any other index) is undeclared and refused.
//! Names compare ignoring ASCII case, as SQLite's do.

use core::fmt;

use vilicus_module_api::{ENVELOPE, Fts5Content, Fts5Table, ModuleDeclaration, SqlType, Table};
use vilicus_storage::{
    CORE_TABLES, ColumnInfo, Handle, IndexInfo, Inspect, Schema, TableInfo, TableKind,
};

use super::fts5;
use super::sql::{self, Expected};

/// The FTS5 option the migration of every FTS5 table sets to 1 (D127, D132).
const SECURE_DELETE: &str = "secure-delete";

/// The shadow tables FTS5 makes for a table with the options D127 allows (contentless or
/// external content, so no `_content`; `columnsize` on, so `_docsize`), and the statement it
/// creates each with, `{}` standing for the shadow table's name. The statements are FTS5's own
/// (SQLite 3.53.4 of D143); a test reads them back from real FTS5 tables.
pub(crate) const FTS5_SHADOWS: &[(&str, &str)] = &[
    (
        "data",
        "CREATE TABLE '{}'(id INTEGER PRIMARY KEY, block BLOB)",
    ),
    (
        "idx",
        "CREATE TABLE '{}'(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID",
    ),
    (
        "docsize",
        "CREATE TABLE '{}'(id INTEGER PRIMARY KEY, sz BLOB)",
    ),
    (
        "config",
        "CREATE TABLE '{}'(k PRIMARY KEY, v) WITHOUT ROWID",
    ),
];

/// What the registry reads of a file: its schema and the `secure-delete` option of each FTS5
/// table the declaration names and the file holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) schema: Schema,
    pub(crate) secure_delete: Vec<(String, Option<i64>)>,
}

impl Snapshot {
    pub(crate) fn read<R: Inspect>(
        handle: &Handle<R>,
        module: &ModuleDeclaration,
    ) -> vilicus_storage::Result<Self> {
        let schema = handle.schema()?;
        let mut secure_delete = Vec::new();
        for fts5 in module.fts5_tables {
            let present = schema.tables.iter().any(|table| {
                table.name.eq_ignore_ascii_case(fts5.name) && table.kind == TableKind::Virtual
            });
            if present {
                secure_delete.push((
                    fts5.name.to_owned(),
                    handle.fts5_option(fts5.name, SECURE_DELETE)?,
                ));
            }
        }
        Ok(Self {
            schema,
            secure_delete,
        })
    }
}

/// A difference between a module's declaration and a file's schema.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchemaError {
    /// A declared table or FTS5 table is not in the file.
    MissingTable {
        /// The table.
        table: &'static str,
    },
    /// A declared table is in the file, but not as an ordinary table.
    NotOrdinaryTable {
        /// The table.
        table: &'static str,
    },
    /// A column of the record envelope is missing (FR-18, AD-6, I8).
    EnvelopeColumnMissing {
        /// The table.
        table: &'static str,
        /// The envelope column.
        column: &'static str,
    },
    /// A declared field has no column.
    FieldMissing {
        /// The table.
        table: &'static str,
        /// The field.
        field: &'static str,
    },
    /// A column is neither in the envelope nor declared (FR-58).
    UndeclaredColumn {
        /// The table.
        table: &'static str,
        /// The column.
        column: String,
    },
    /// A column's type, nullability, key or kind differs from its declaration.
    ColumnMismatch {
        /// The table.
        table: &'static str,
        /// The column.
        column: &'static str,
        /// The column as declared.
        expected: String,
        /// The column as the file holds it.
        found: String,
    },
    /// A table holds a foreign key, whose actions write or delete rows on their own.
    ForeignKey {
        /// The table.
        table: &'static str,
        /// The table it references.
        references: String,
    },
    /// An index of a declared table is not a plain index over its columns.
    IndexNotAllowed {
        /// The table.
        table: &'static str,
        /// The index.
        index: String,
        /// What makes it more than a plain index.
        reason: &'static str,
    },
    /// The statement that created a table is not the one its declaration implies: a clause or
    /// an option beyond the declared columns, or columns in another order.
    Definition {
        /// The table, or the shadow table.
        table: String,
        /// The statement the declaration implies.
        expected: String,
        /// The statement the file holds.
        found: String,
    },
    /// A table, view, trigger or index of the file is not declared.
    UndeclaredObject {
        /// Its kind, as SQLite names it.
        kind: String,
        /// Its name.
        name: String,
    },
    /// A declared FTS5 table is in the file as something else than an FTS5 virtual table.
    NotFts5 {
        /// The FTS5 table.
        table: &'static str,
    },
    /// The arguments an FTS5 table was created with are not its declared ones, or leave the
    /// allowlist of D127.
    Fts5Arguments {
        /// The FTS5 table.
        table: &'static str,
        /// What differs.
        reason: String,
    },
    /// A shadow table FTS5 makes for a declared FTS5 table is missing.
    Fts5ShadowMissing {
        /// The FTS5 table.
        table: &'static str,
        /// The shadow table.
        shadow: String,
    },
    /// An FTS5 table's `secure-delete` option is not 1 (D127, D132).
    Fts5SecureDeleteOff {
        /// The FTS5 table.
        table: &'static str,
    },
}

impl fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTable { table } => write!(formatter, "table {table} is missing"),
            Self::NotOrdinaryTable { table } => {
                write!(formatter, "table {table} is not an ordinary table")
            }
            Self::EnvelopeColumnMissing { table, column } => {
                write!(
                    formatter,
                    "table {table} lacks the envelope column {column}"
                )
            }
            Self::FieldMissing { table, field } => {
                write!(formatter, "table {table} lacks the declared field {field}")
            }
            Self::UndeclaredColumn { table, column } => {
                write!(formatter, "column {table}.{column} is not declared")
            }
            Self::ColumnMismatch {
                table,
                column,
                expected,
                found,
            } => write!(
                formatter,
                "column {table}.{column} is {found}, declared {expected}"
            ),
            Self::ForeignKey { table, references } => {
                write!(formatter, "table {table} has a foreign key to {references}")
            }
            Self::IndexNotAllowed {
                table,
                index,
                reason,
            } => write!(formatter, "index {index} of table {table}: {reason}"),
            Self::Definition {
                table,
                expected,
                found,
            } => write!(
                formatter,
                "table {table} is created by {found:?}, declared {expected:?}"
            ),
            Self::UndeclaredObject { kind, name } => {
                write!(formatter, "{kind} {name} is not declared")
            }
            Self::NotFts5 { table } => write!(formatter, "{table} is not an FTS5 table"),
            Self::Fts5Arguments { table, reason } => {
                write!(formatter, "FTS5 table {table}: {reason}")
            }
            Self::Fts5ShadowMissing { table, shadow } => {
                write!(
                    formatter,
                    "FTS5 table {table} lacks its shadow table {shadow}"
                )
            }
            Self::Fts5SecureDeleteOff { table } => {
                write!(
                    formatter,
                    "FTS5 table {table} does not set secure-delete to 1"
                )
            }
        }
    }
}

impl std::error::Error for SchemaError {}

/// A column as a declaration or a file has it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Shape<'a> {
    declared_type: &'a str,
    not_null: bool,
    primary_key: bool,
    generated: bool,
}

impl Shape<'_> {
    fn matches(&self, other: &Shape<'_>) -> bool {
        self.declared_type.eq_ignore_ascii_case(other.declared_type)
            && self.not_null == other.not_null
            && self.primary_key == other.primary_key
            && self.generated == other.generated
    }
}

impl fmt::Display for Shape<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let declared_type = if self.declared_type.is_empty() {
            "(no type)"
        } else {
            self.declared_type
        };
        formatter.write_str(declared_type)?;
        if self.not_null {
            formatter.write_str(" NOT NULL")?;
        }
        if self.primary_key {
            formatter.write_str(" PRIMARY KEY")?;
        }
        if self.generated {
            formatter.write_str(" GENERATED")?;
        }
        Ok(())
    }
}

fn declared(sql_type: SqlType, not_null: bool, primary_key: bool) -> Shape<'static> {
    Shape {
        declared_type: sql_type.as_str(),
        not_null,
        primary_key,
        generated: false,
    }
}

fn found(column: &ColumnInfo) -> Shape<'_> {
    Shape {
        declared_type: &column.declared_type,
        not_null: column.not_null,
        primary_key: column.primary_key != 0,
        generated: column.hidden != 0,
    }
}

/// Every column a declared table holds, in order: the envelope, then the fields. The flag is
/// true for an envelope column.
fn columns(table: &'static Table) -> Vec<(&'static str, Shape<'static>, bool)> {
    let envelope = ENVELOPE.iter().map(|column| {
        let shape = declared(column.sql_type, column.not_null, column.primary_key);
        (column.name, shape, true)
    });
    let fields = table.fields.iter().map(|field| {
        let shape = declared(field.kind.sql_type(), !field.optional, false);
        (field.name, shape, false)
    });
    envelope.chain(fields).collect()
}

/// The tokens of the one statement that creates `table`:
/// `CREATE TABLE <table> (<column> <TYPE> [NOT NULL] [PRIMARY KEY], ...)`, envelope first, then
/// the fields in their declared order. A migration that adds a field later appends it, so the
/// declaration lists it last; SQLite writes an added column into the stored statement.
pub(crate) fn canonical_table(table: &'static Table) -> Vec<Expected<'static>> {
    let mut tokens = vec![
        Expected::Keyword("CREATE"),
        Expected::Keyword("TABLE"),
        Expected::Name(table.name),
        Expected::Punct('('),
    ];
    for (position, (name, shape, _)) in columns(table).into_iter().enumerate() {
        if position > 0 {
            tokens.push(Expected::Punct(','));
        }
        tokens.push(Expected::Name(name));
        tokens.push(Expected::Keyword(shape.declared_type));
        if shape.not_null {
            tokens.extend([Expected::Keyword("NOT"), Expected::Keyword("NULL")]);
        }
        if shape.primary_key {
            tokens.extend([Expected::Keyword("PRIMARY"), Expected::Keyword("KEY")]);
        }
    }
    tokens.push(Expected::Punct(')'));
    tokens
}

fn find_table<'a>(tables: &'a [TableInfo], name: &str) -> Option<&'a TableInfo> {
    tables
        .iter()
        .find(|info| info.name.eq_ignore_ascii_case(name))
}

/// The SQL text `sqlite_master` holds for the table named `name`.
fn table_sql<'a>(snapshot: &'a Snapshot, name: &str) -> Option<&'a str> {
    snapshot
        .schema
        .objects
        .iter()
        .find(|object| object.kind == "table" && object.name.eq_ignore_ascii_case(name))
        .and_then(|object| object.sql.as_deref())
}

/// Compares `module` with the file `snapshot` was read from; the first difference is returned.
pub(crate) fn compare(module: &ModuleDeclaration, snapshot: &Snapshot) -> Result<(), SchemaError> {
    let tables = &snapshot.schema.tables;
    for table in module.tables {
        let info = find_table(tables, table.name)
            .ok_or(SchemaError::MissingTable { table: table.name })?;
        compare_table(table, info, table_sql(snapshot, table.name))?;
    }
    for fts5 in module.fts5_tables {
        compare_fts5(fts5, snapshot)?;
    }
    for info in tables {
        if !belongs_to(module, info) {
            return Err(SchemaError::UndeclaredObject {
                kind: kind_name(&info.kind).to_owned(),
                name: info.name.clone(),
            });
        }
    }
    for object in &snapshot.schema.objects {
        let allowed = match object.kind.as_str() {
            "table" | "view" => true,
            "index" => {
                module
                    .tables
                    .iter()
                    .any(|table| table.name.eq_ignore_ascii_case(&object.table))
                    || CORE_TABLES
                        .iter()
                        .any(|core| core.eq_ignore_ascii_case(&object.table))
            }
            _ => false,
        };
        if !allowed {
            return Err(SchemaError::UndeclaredObject {
                kind: object.kind.clone(),
                name: object.name.clone(),
            });
        }
    }
    Ok(())
}

fn compare_table(
    table: &'static Table,
    info: &TableInfo,
    sql: Option<&str>,
) -> Result<(), SchemaError> {
    if info.kind != TableKind::Ordinary {
        return Err(SchemaError::NotOrdinaryTable { table: table.name });
    }
    let expected = columns(table);
    for &(name, shape, in_envelope) in &expected {
        let Some(column) = info
            .columns
            .iter()
            .find(|column| column.name.eq_ignore_ascii_case(name))
        else {
            return Err(if in_envelope {
                SchemaError::EnvelopeColumnMissing {
                    table: table.name,
                    column: name,
                }
            } else {
                SchemaError::FieldMissing {
                    table: table.name,
                    field: name,
                }
            });
        };
        let in_file = found(column);
        if !shape.matches(&in_file) {
            return Err(SchemaError::ColumnMismatch {
                table: table.name,
                column: name,
                expected: shape.to_string(),
                found: in_file.to_string(),
            });
        }
    }
    if let Some(extra) = info.columns.iter().find(|column| {
        !expected
            .iter()
            .any(|(name, _, _)| name.eq_ignore_ascii_case(&column.name))
    }) {
        return Err(SchemaError::UndeclaredColumn {
            table: table.name,
            column: extra.name.clone(),
        });
    }
    if let Some(foreign_key) = info.foreign_keys.first() {
        return Err(SchemaError::ForeignKey {
            table: table.name,
            references: foreign_key.table.clone(),
        });
    }
    for index in &info.indexes {
        check_index(table, index)?;
    }
    compare_definition(table, sql)
}

/// The indexes a declared table may hold: the one SQLite makes for the `id` primary key, and
/// plain indexes made by `CREATE INDEX`. A `UNIQUE` index refuses or, with `REPLACE`, deletes
/// rows; a partial or expression index evaluates SQL on every write; a collation changes what
/// counts as equal. None of them is declared, so none is allowed.
fn check_index(table: &'static Table, index: &IndexInfo) -> Result<(), SchemaError> {
    let refuse = |reason| SchemaError::IndexNotAllowed {
        table: table.name,
        index: index.name.clone(),
        reason,
    };
    let keys: Vec<_> = index.columns.iter().filter(|column| column.key).collect();
    if index.partial {
        return Err(refuse("a partial index"));
    }
    if keys.iter().any(|column| column.cid < 0) {
        return Err(refuse("an index on an expression or the rowid"));
    }
    if keys.iter().any(|column| {
        !column
            .collation
            .as_deref()
            .is_some_and(|collation| collation.eq_ignore_ascii_case("BINARY"))
    }) {
        return Err(refuse("a collation other than BINARY"));
    }
    match index.origin.as_str() {
        "pk" => {
            let primary = ENVELOPE
                .iter()
                .find(|column| column.primary_key)
                .map(|column| column.name);
            let only_id = keys.len() == 1
                && keys[0]
                    .name
                    .as_deref()
                    .zip(primary)
                    .is_some_and(|(found, id)| found.eq_ignore_ascii_case(id));
            if only_id {
                Ok(())
            } else {
                Err(refuse("a primary key other than the envelope id"))
            }
        }
        "c" if !index.unique => Ok(()),
        "c" => Err(refuse("a UNIQUE index")),
        _ => Err(refuse("an index made by a UNIQUE constraint")),
    }
}

fn compare_definition(table: &'static Table, sql: Option<&str>) -> Result<(), SchemaError> {
    let expected = canonical_table(table);
    let found = sql.unwrap_or_default();
    let tokens = sql::tokenize(found).unwrap_or_default();
    let strict_option = [Expected::Keyword("STRICT")];
    let same = sql::matches(&expected, &tokens)
        || (tokens.len() == expected.len() + 1
            && sql::matches(&expected, &tokens[..expected.len()])
            && sql::matches(&strict_option, &tokens[expected.len()..]));
    if same {
        Ok(())
    } else {
        Err(SchemaError::Definition {
            table: table.name.to_owned(),
            expected: sql::render(&expected),
            found: found.to_owned(),
        })
    }
}

fn compare_fts5(fts5: &'static Fts5Table, snapshot: &Snapshot) -> Result<(), SchemaError> {
    let table = fts5.name;
    let info =
        find_table(&snapshot.schema.tables, table).ok_or(SchemaError::MissingTable { table })?;
    let sql = table_sql(snapshot, table);
    let (TableKind::Virtual, Some(sql)) = (&info.kind, sql) else {
        return Err(SchemaError::NotFts5 { table });
    };
    let reason = |reason: String| SchemaError::Fts5Arguments { table, reason };
    let parsed =
        fts5::parse(sql).map_err(|error| reason(format!("unreadable arguments ({error:?})")))?;
    if !parsed.module.eq_ignore_ascii_case("fts5") {
        return Err(SchemaError::NotFts5 { table });
    }
    let same_columns = parsed.columns.len() == fts5.columns.len()
        && parsed
            .columns
            .iter()
            .zip(fts5.columns)
            .all(|(found, declared)| found.eq_ignore_ascii_case(declared));
    if !same_columns {
        return Err(reason(format!(
            "columns {:?}, declared {:?}",
            parsed.columns, fts5.columns
        )));
    }
    let mut tokenizer = None;
    let mut content = None;
    for (key, value) in &parsed.options {
        let slot = match key.as_str() {
            "tokenize" => &mut tokenizer,
            "content" => &mut content,
            other => return Err(reason(format!("option {other} is not allowed"))),
        };
        if slot.replace(value.as_str()).is_some() {
            return Err(reason(format!("option {key} is given twice")));
        }
    }
    let declared_tokenizer = fts5.tokenizer.as_str();
    if !tokenizer
        .unwrap_or("unicode61")
        .eq_ignore_ascii_case(declared_tokenizer)
    {
        return Err(reason(format!(
            "tokenizer {:?}, declared {declared_tokenizer}",
            tokenizer.unwrap_or_default()
        )));
    }
    let declared_content = match fts5.content {
        Fts5Content::Contentless => "",
        Fts5Content::Table(name) => name,
    };
    if content != Some(declared_content) {
        return Err(reason(format!(
            "content {content:?}, declared {declared_content:?}"
        )));
    }
    for (suffix, template) in FTS5_SHADOWS {
        let shadow = format!("{table}_{suffix}");
        let present = find_table(&snapshot.schema.tables, &shadow)
            .is_some_and(|info| info.kind == TableKind::Shadow);
        if !present {
            return Err(SchemaError::Fts5ShadowMissing { table, shadow });
        }
        let expected_sql = template.replace("{}", &shadow);
        let found = table_sql(snapshot, &shadow).unwrap_or_default();
        let same = sql::tokenize(&expected_sql)
            .ok()
            .zip(sql::tokenize(found).ok())
            .is_some_and(|(expected, found)| sql::same_statement(&expected, &found));
        if !same {
            return Err(SchemaError::Definition {
                table: shadow,
                expected: expected_sql,
                found: found.to_owned(),
            });
        }
    }
    let secure_delete = snapshot
        .secure_delete
        .iter()
        .find(|(name, _)| name == table)
        .and_then(|(_, value)| *value);
    if secure_delete != Some(1) {
        return Err(SchemaError::Fts5SecureDeleteOff { table });
    }
    Ok(())
}

/// True when the file may hold `info` for `module`: a Core or internal table, a declared table
/// or FTS5 table, or one of the shadow tables FTS5 makes for a declared FTS5 table. A table
/// SQLite marks as a shadow table by its name alone is not enough: only the names of
/// [`FTS5_SHADOWS`] are.
fn belongs_to(module: &ModuleDeclaration, info: &TableInfo) -> bool {
    let name = info.name.as_str();
    is_internal(name)
        || CORE_TABLES
            .iter()
            .any(|core| core.eq_ignore_ascii_case(name))
        || module
            .tables
            .iter()
            .any(|table| table.name.eq_ignore_ascii_case(name))
        || module
            .fts5_tables
            .iter()
            .any(|fts5| fts5.name.eq_ignore_ascii_case(name))
        || (info.kind == TableKind::Shadow
            && module.fts5_tables.iter().any(|fts5| {
                FTS5_SHADOWS.iter().any(|(suffix, _)| {
                    name.eq_ignore_ascii_case(&format!("{}_{suffix}", fts5.name))
                })
            }))
}

/// SQLite's own objects: its schema and statistics tables and the indexes it makes for
/// constraints. No migration can create a name with this prefix.
fn is_internal(name: &str) -> bool {
    name.get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("sqlite_"))
}

fn kind_name(kind: &TableKind) -> &str {
    match kind {
        TableKind::Ordinary => "table",
        TableKind::Virtual => "virtual table",
        TableKind::Shadow => "shadow table",
        TableKind::View => "view",
        TableKind::Other(other) => other,
    }
}
