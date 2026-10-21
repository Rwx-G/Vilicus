//! The hostile statement set of E11, kept as data so Story 3.1 can replay it against
//! `vilicus-storage` unchanged.

use std::path::Path;

/// The forbidden class a hostile statement belongs to, as D21 and AD-5 name them, plus the
/// confinement escapes the authorizer must also cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Attach,
    Detach,
    UnsafePragma,
    ExtensionLoading,
    CopyOut,
    InternalTable,
}

/// One hostile statement. `{dir}` in `sql` stands for a scratch directory, so a statement that
/// slipped through would write there and nowhere else.
#[derive(Clone, Copy, Debug)]
pub struct HostileStatement {
    pub name: &'static str,
    pub class: Class,
    pub sql: &'static str,
}

impl HostileStatement {
    /// The statement with `{dir}` replaced by `scratch_dir`.
    pub fn sql_in(&self, scratch_dir: &Path) -> String {
        self.sql
            .replace("{dir}", &escape_for_sql_string(scratch_dir))
    }
}

/// `path` with every single quote doubled, ready to sit between single quotes in SQL.
pub fn escape_for_sql_string(path: &Path) -> String {
    path.to_string_lossy().replace('\'', "''")
}

/// Every hostile statement. A `DETACH` needs an attached database to be meaningful; the tests
/// attach `other` before installing the authorizer. `sqlite_dbpage` is not here: this build
/// does not compile it in, which a separate test checks.
pub const HOSTILE_STATEMENTS: &[HostileStatement] = &[
    HostileStatement {
        name: "attach_file",
        class: Class::Attach,
        sql: "ATTACH DATABASE '{dir}/attached.db' AS hijack",
    },
    HostileStatement {
        name: "attach_plaintext_key",
        class: Class::Attach,
        sql: "ATTACH DATABASE '{dir}/attached.db' AS hijack KEY ''",
    },
    HostileStatement {
        name: "attach_uri",
        class: Class::Attach,
        sql: "ATTACH DATABASE 'file:{dir}/attached.db?mode=rwc' AS hijack",
    },
    HostileStatement {
        name: "attach_memory",
        class: Class::Attach,
        sql: "ATTACH DATABASE ':memory:' AS hijack",
    },
    HostileStatement {
        name: "detach",
        class: Class::Detach,
        sql: "DETACH DATABASE other",
    },
    HostileStatement {
        name: "pragma_key",
        class: Class::UnsafePragma,
        sql: "PRAGMA key = 'attacker'",
    },
    HostileStatement {
        name: "pragma_rekey",
        class: Class::UnsafePragma,
        sql: "PRAGMA rekey = 'attacker'",
    },
    HostileStatement {
        name: "pragma_journal_mode_off",
        class: Class::UnsafePragma,
        sql: "PRAGMA journal_mode = OFF",
    },
    HostileStatement {
        name: "pragma_schema_qualified_journal_mode",
        class: Class::UnsafePragma,
        sql: "PRAGMA main.journal_mode = DELETE",
    },
    HostileStatement {
        name: "pragma_writable_schema",
        class: Class::UnsafePragma,
        sql: "PRAGMA writable_schema = ON",
    },
    HostileStatement {
        name: "pragma_secure_delete_off",
        class: Class::UnsafePragma,
        sql: "PRAGMA secure_delete = OFF",
    },
    HostileStatement {
        name: "pragma_foreign_keys_off",
        class: Class::UnsafePragma,
        sql: "PRAGMA foreign_keys = OFF",
    },
    HostileStatement {
        name: "pragma_trusted_schema_on",
        class: Class::UnsafePragma,
        sql: "PRAGMA trusted_schema = ON",
    },
    HostileStatement {
        name: "pragma_cipher_compatibility",
        class: Class::UnsafePragma,
        sql: "PRAGMA cipher_compatibility = 1",
    },
    HostileStatement {
        name: "pragma_cipher_plaintext_header",
        class: Class::UnsafePragma,
        sql: "PRAGMA cipher_plaintext_header_size = 32",
    },
    HostileStatement {
        name: "pragma_uppercase_key",
        class: Class::UnsafePragma,
        sql: "PRAGMA KEY = 'attacker'",
    },
    HostileStatement {
        name: "pragma_database_list",
        class: Class::UnsafePragma,
        sql: "PRAGMA database_list",
    },
    HostileStatement {
        name: "pragma_table_function_database_list",
        class: Class::UnsafePragma,
        sql: "SELECT * FROM pragma_database_list",
    },
    HostileStatement {
        name: "load_extension_function",
        class: Class::ExtensionLoading,
        sql: "SELECT load_extension('{dir}/evil.so')",
    },
    HostileStatement {
        name: "load_extension_function_entry_point",
        class: Class::ExtensionLoading,
        sql: "SELECT load_extension('{dir}/evil.so', 'sqlite3_evil_init')",
    },
    HostileStatement {
        name: "load_extension_uppercase",
        class: Class::ExtensionLoading,
        sql: "SELECT LOAD_EXTENSION('{dir}/evil.so')",
    },
    HostileStatement {
        name: "sqlcipher_export",
        class: Class::CopyOut,
        sql: "SELECT sqlcipher_export('other')",
    },
    HostileStatement {
        name: "vacuum_into",
        class: Class::CopyOut,
        sql: "VACUUM INTO '{dir}/copy.db'",
    },
];

/// Hostile on read and write connections only; `sqlite_sequence` exists because the test fixture
/// has an `AUTOINCREMENT` table. The migration policy allows writes to the
/// internal tables SQLite itself updates from inside DDL and `ANALYZE` (see
/// `MIGRATION_INTERNAL_TABLES`), so these are not refused in a migration.
pub const RUNTIME_HOSTILE_STATEMENTS: &[HostileStatement] = &[
    HostileStatement {
        name: "update_sqlite_sequence",
        class: Class::InternalTable,
        sql: "UPDATE sqlite_sequence SET seq = 0",
    },
    HostileStatement {
        name: "delete_sqlite_sequence",
        class: Class::InternalTable,
        sql: "DELETE FROM sqlite_sequence",
    },
];
