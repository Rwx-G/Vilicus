//! The comparison of a module's declaration with the schema its migrations produced in a file
//! (AD-6, AD-9, D98, D127, D132): the Rust declaration is the single source of truth, and any
//! difference in either direction is a [`SchemaError`].
//!
//! The file holds exactly: the Core tables of `vilicus_storage::CORE_TABLES`; SQLite's internal
//! tables (`sqlite_` prefix, which no migration can create); each declared table, with the record
//! envelope and the declared fields and no other column; each declared FTS5 table
//! with its declared arguments, its `secure-delete` option at 1, and the shadow tables SQLite
//! marks as its own; and indexes on declared tables. Anything else (another table, a view, a
//! trigger, a generated column) is undeclared and refused: a trigger, for one, could write rows
//! that no declaration or envelope stamping covers.

use core::fmt;

use vilicus_module_api::{ENVELOPE, Fts5Content, Fts5Table, ModuleDeclaration, SqlType, Table};
use vilicus_storage::{CORE_TABLES, ColumnInfo, Handle, Inspect, Schema, TableInfo, TableKind};

use super::fts5;

/// The FTS5 option the migration of every FTS5 table sets to 1 (D127, D132).
const SECURE_DELETE: &str = "secure-delete";

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
            let present = schema
                .tables
                .iter()
                .any(|table| table.name == fts5.name && table.kind == TableKind::Virtual);
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
            Self::UndeclaredObject { kind, name } => {
                write!(formatter, "{kind} {name} is not declared")
            }
            Self::NotFts5 { table } => write!(formatter, "{table} is not an FTS5 table"),
            Self::Fts5Arguments { table, reason } => {
                write!(formatter, "FTS5 table {table}: {reason}")
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

/// Compares `module` with the file `snapshot` was read from; the first difference is returned.
pub(crate) fn compare(module: &ModuleDeclaration, snapshot: &Snapshot) -> Result<(), SchemaError> {
    let tables = &snapshot.schema.tables;
    for table in module.tables {
        let info = tables
            .iter()
            .find(|info| info.name == table.name)
            .ok_or(SchemaError::MissingTable { table: table.name })?;
        compare_table(table, info)?;
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
                is_internal(&object.name)
                    || module.tables.iter().any(|table| table.name == object.table)
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

fn compare_table(table: &'static Table, info: &TableInfo) -> Result<(), SchemaError> {
    if info.kind != TableKind::Ordinary {
        return Err(SchemaError::NotOrdinaryTable { table: table.name });
    }
    let envelope = ENVELOPE.iter().map(|column| {
        let shape = declared(column.sql_type, column.not_null, column.primary_key);
        (column.name, shape, true)
    });
    let fields = table.fields.iter().map(|field| {
        let shape = declared(field.kind.sql_type(), !field.optional, false);
        (field.name, shape, false)
    });
    let expected: Vec<(&'static str, Shape<'static>, bool)> = envelope.chain(fields).collect();
    for &(name, shape, in_envelope) in &expected {
        let Some(column) = info.columns.iter().find(|column| column.name == name) else {
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
    if let Some(extra) = info
        .columns
        .iter()
        .find(|column| !expected.iter().any(|(name, _, _)| *name == column.name))
    {
        return Err(SchemaError::UndeclaredColumn {
            table: table.name,
            column: extra.name.clone(),
        });
    }
    Ok(())
}

fn compare_fts5(fts5: &'static Fts5Table, snapshot: &Snapshot) -> Result<(), SchemaError> {
    let table = fts5.name;
    let info = snapshot
        .schema
        .tables
        .iter()
        .find(|info| info.name == table)
        .ok_or(SchemaError::MissingTable { table })?;
    let sql = snapshot
        .schema
        .objects
        .iter()
        .find(|object| object.kind == "table" && object.name == table)
        .and_then(|object| object.sql.as_deref());
    let (TableKind::Virtual, Some(sql)) = (&info.kind, sql) else {
        return Err(SchemaError::NotFts5 { table });
    };
    let reason = |reason: String| SchemaError::Fts5Arguments { table, reason };
    let parsed =
        fts5::parse(sql).map_err(|error| reason(format!("unreadable arguments ({error:?})")))?;
    if !parsed.module.eq_ignore_ascii_case("fts5") {
        return Err(SchemaError::NotFts5 { table });
    }
    if parsed.columns != fts5.columns {
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
/// or FTS5 table, or a shadow table of a declared FTS5 table.
fn belongs_to(module: &ModuleDeclaration, info: &TableInfo) -> bool {
    let name = info.name.as_str();
    is_internal(name)
        || CORE_TABLES
            .iter()
            .any(|core| core.eq_ignore_ascii_case(name))
        || module.tables.iter().any(|table| table.name == name)
        || module.fts5_tables.iter().any(|fts5| fts5.name == name)
        || (info.kind == TableKind::Shadow
            && module.fts5_tables.iter().any(|fts5| {
                name.strip_prefix(fts5.name)
                    .is_some_and(|rest| rest.starts_with('_'))
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
