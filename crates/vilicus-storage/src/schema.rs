//! What a module file's schema holds, read for the module registry, which compares it with the
//! module's declarations when it opens a file (AD-9). Reading only: the schema is read through
//! the handle's own authorizer, with `SELECT` on `sqlite_master` and the introspection pragmas
//! `table_list` and `table_xinfo`, so a read or write handle needs no extra right.

use rusqlite::types::Value;

use crate::error::Result;
use crate::handle::{Handle, Inspect};

/// The kind of a table of the file, as `PRAGMA table_list` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TableKind {
    /// An ordinary table.
    Ordinary,
    /// A virtual table, such as an FTS5 table.
    Virtual,
    /// A shadow table, which a virtual table keeps its data in; SQLite marks it so only when the
    /// virtual table it belongs to exists and claims it.
    Shadow,
    /// A view.
    View,
    /// A kind this SQLite version reports that the list above does not know.
    Other(String),
}

impl TableKind {
    fn from_table_list(kind: &str) -> Self {
        match kind {
            "table" => Self::Ordinary,
            "virtual" => Self::Virtual,
            "shadow" => Self::Shadow,
            "view" => Self::View,
            other => Self::Other(other.to_owned()),
        }
    }
}

/// One column of an ordinary table, as `PRAGMA table_xinfo` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnInfo {
    /// The column name.
    pub name: String,
    /// The declared type, as written in the `CREATE TABLE` or `ALTER TABLE` statement.
    pub declared_type: String,
    /// True for a `NOT NULL` column.
    pub not_null: bool,
    /// The column's position in the primary key, from 1; 0 when it is not part of it.
    pub primary_key: u32,
    /// `table_xinfo`'s `hidden` value: 0 for an ordinary column, 2 or 3 for a generated one.
    pub hidden: i64,
}

/// One table or view of the file's main schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableInfo {
    /// The table name.
    pub name: String,
    /// Its kind.
    pub kind: TableKind,
    /// True for a `STRICT` table.
    pub strict: bool,
    /// True for a `WITHOUT ROWID` table.
    pub without_rowid: bool,
    /// The columns of an ordinary table, in their order; empty for the other kinds.
    pub columns: Vec<ColumnInfo>,
}

/// One entry of `sqlite_master`: a table, an index, a view or a trigger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaObject {
    /// `table`, `index`, `view` or `trigger`.
    pub kind: String,
    /// The object name.
    pub name: String,
    /// The table the object belongs to (its own name for a table or view).
    pub table: String,
    /// The SQL text that created it; none for the indexes SQLite creates for a constraint.
    pub sql: Option<String>,
}

/// The schema of a file's main database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schema {
    /// Every table and view, by name.
    pub tables: Vec<TableInfo>,
    /// Every entry of `sqlite_master`, by kind then name.
    pub objects: Vec<SchemaObject>,
}

impl<R: Inspect> Handle<R> {
    /// Reads the schema of the file's main database.
    pub fn schema(&self) -> Result<Schema> {
        let connection = self.connection();
        let mut tables: Vec<TableInfo> = connection
            .prepare(
                "SELECT name, type, wr, strict FROM pragma_table_list \
                 WHERE schema = 'main' ORDER BY name",
            )?
            .query_map([], |row| {
                Ok(TableInfo {
                    name: row.get(0)?,
                    kind: TableKind::from_table_list(&row.get::<_, String>(1)?),
                    without_rowid: row.get(2)?,
                    strict: row.get(3)?,
                    columns: Vec::new(),
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        let mut columns = connection.prepare(
            "SELECT name, type, \"notnull\", pk, hidden FROM pragma_table_xinfo(?1, 'main') \
             ORDER BY cid",
        )?;
        for table in &mut tables {
            if table.kind == TableKind::Ordinary {
                table.columns = columns
                    .query_map([&table.name], |row| {
                        Ok(ColumnInfo {
                            name: row.get(0)?,
                            declared_type: row.get(1)?,
                            not_null: row.get(2)?,
                            primary_key: row.get(3)?,
                            hidden: row.get(4)?,
                        })
                    })?
                    .collect::<rusqlite::Result<_>>()?;
            }
        }
        let objects = connection
            .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")?
            .query_map([], |row| {
                Ok(SchemaObject {
                    kind: row.get(0)?,
                    name: row.get(1)?,
                    table: row.get(2)?,
                    sql: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(Schema { tables, objects })
    }

    /// The integer value of option `key` in the configuration table of the FTS5 table `table`
    /// (`<table>_config`), such as `secure-delete` (D127, D132): `None` when the option is not
    /// set, or set to anything but an integer.
    pub fn fts5_option(&self, table: &str, key: &str) -> Result<Option<i64>> {
        let config = quote_identifier(&format!("{table}_config"));
        let value = self.connection().query_row(
            &format!("SELECT v FROM {config} WHERE k = ?1"),
            [key],
            |row| row.get::<_, Value>(0),
        );
        match value {
            Ok(Value::Integer(value)) => Ok(Some(value)),
            Ok(_) | Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

/// `name` as an SQL identifier, in double quotes with any double quote doubled.
fn quote_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_quoted_with_their_quotes_doubled() {
        assert_eq!(quote_identifier("notes_config"), "\"notes_config\"");
        assert_eq!(quote_identifier("a\"b"), "\"a\"\"b\"");
    }
}
