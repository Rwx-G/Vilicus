//! E11 spike: does the SQLite authorizer, on the SQLCipher build the product uses, keep a
//! connection confined to its own file?
//!
//! The policy is an allowlist per [`Policy`]: every authorizer action that is not explicitly
//! allowed is denied, so an action code SQLite adds later is refused by default. SQL functions
//! are allowlisted too ([`ALLOWED_FUNCTIONS`]); a test fails when the engine offers a function
//! that has not been reviewed. Connection setup pragmas run before the authorizer is installed;
//! once it is installed, no pragma outside [`INTROSPECTION_PRAGMAS`] can run.

#![deny(unsafe_code)]

pub mod hostile;

use std::path::Path;

use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::{Connection, OpenFlags};

/// What a connection is opened for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Applies migrations through [`apply_migration`] and nothing else.
    Migration,
    /// Ordinary writes through the typed record API: rows only, never schema.
    Write,
    /// Ordinary reads.
    Read,
}

impl Role {
    /// The policy [`open`] installs. A migration connection is closed to every statement
    /// outside [`apply_migration`], which opens the migration policy only inside its own
    /// transaction.
    pub fn opening_policy(self) -> Policy {
        match self {
            Role::Migration => Policy::Closed,
            Role::Write => Policy::Write,
            Role::Read => Policy::Read,
        }
    }
}

/// The authorizer policy in force on a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Denies every action.
    Closed,
    /// Schema changes and data backfill in the connection's own file, inside the runner's
    /// transaction.
    Migration,
    /// Rows in the connection's own tables.
    Write,
    /// Reads.
    Read,
}

/// Read-only schema introspection pragmas, allowed under every policy but [`Policy::Closed`].
/// Compared ignoring ASCII case, because the authorizer receives the pragma name as written.
pub const INTROSPECTION_PRAGMAS: &[&str] = &[
    "table_info",
    "table_xinfo",
    "index_list",
    "index_info",
    "index_xinfo",
    "foreign_key_list",
    "foreign_key_check",
];

/// Built-in SQL functions reviewed as safe for module SQL: pure computation on values, dates,
/// JSON, window and aggregate functions, and the FTS5 ranking and highlighting helpers.
/// Compared ignoring ASCII case.
pub const ALLOWED_FUNCTIONS: &[&str] = &[
    "->",
    "->>",
    "abs",
    "avg",
    "bm25",
    "changes",
    "char",
    "coalesce",
    "concat",
    "concat_ws",
    "count",
    "cume_dist",
    "current_date",
    "current_time",
    "current_timestamp",
    "date",
    "datetime",
    "dense_rank",
    "first_value",
    "format",
    "glob",
    "group_concat",
    "hex",
    "highlight",
    "if",
    "ifnull",
    "iif",
    "instr",
    "json",
    "json_array",
    "json_array_length",
    "json_error_position",
    "json_extract",
    "json_group_array",
    "json_group_object",
    "json_insert",
    "json_object",
    "json_patch",
    "json_pretty",
    "json_quote",
    "json_remove",
    "json_replace",
    "json_set",
    "json_type",
    "json_valid",
    "jsonb",
    "jsonb_array",
    "jsonb_extract",
    "jsonb_group_array",
    "jsonb_group_object",
    "jsonb_insert",
    "jsonb_object",
    "jsonb_patch",
    "jsonb_remove",
    "jsonb_replace",
    "jsonb_set",
    "julianday",
    "lag",
    "last_insert_rowid",
    "last_value",
    "lead",
    "length",
    "like",
    "likelihood",
    "likely",
    "lower",
    "ltrim",
    "match",
    "max",
    "min",
    "nth_value",
    "ntile",
    "nullif",
    "octet_length",
    "percent_rank",
    "printf",
    "quote",
    "random",
    "randomblob",
    "rank",
    "replace",
    "round",
    "row_number",
    "rtrim",
    "sign",
    "snippet",
    "soundex",
    "strftime",
    "string_agg",
    "substr",
    "substring",
    "subtype",
    "sum",
    "time",
    "timediff",
    "total",
    "total_changes",
    "trim",
    "typeof",
    "unhex",
    "unicode",
    "unistr",
    "unistr_quote",
    "unixepoch",
    "unlikely",
    "upper",
    "zeroblob",
];

/// Built-in SQL functions reviewed and left out of [`ALLOWED_FUNCTIONS`]: they load native code,
/// copy the database into another file, take or return raw pointers, inspect FTS3, FTS5 or
/// R-tree internals, write to the SQLite log, or reveal build details. The policy never reads
/// this list; it exists so the coverage test can tell a reviewed refusal from a function nobody
/// has looked at.
pub const DENIED_FUNCTIONS: &[&str] = &[
    "load_extension",
    "sqlcipher_export",
    "fts3_tokenizer",
    "fts5",
    "fts5_get_locale",
    "fts5_insttoken",
    "fts5_locale",
    "fts5_source_id",
    "matchinfo",
    "offsets",
    "optimize",
    "rtreecheck",
    "rtreedepth",
    "rtreenode",
    "sqlite_compileoption_get",
    "sqlite_compileoption_used",
    "sqlite_log",
    "sqlite_source_id",
    "sqlite_version",
];

/// SQLite's internal functions that `ALTER TABLE` calls from its own nested statements, which
/// still pass through the authorizer. Allowed under [`Policy::Migration`] only. SQL text cannot
/// call them: SQLite resolves internal functions only inside its own nested statements, which a
/// test checks.
pub const INTERNAL_ALTER_FUNCTIONS: &[&str] = &[
    "sqlite_rename_column",
    "sqlite_rename_table",
    "sqlite_rename_test",
    "sqlite_drop_column",
    "sqlite_rename_quotefix",
];

fn function_allowed(policy: Policy, function_name: &str) -> bool {
    listed(ALLOWED_FUNCTIONS, function_name)
        || (policy == Policy::Migration && listed(INTERNAL_ALTER_FUNCTIONS, function_name))
}

fn listed(list: &[&str], name: &str) -> bool {
    list.iter().any(|entry| entry.eq_ignore_ascii_case(name))
}

/// Internal tables SQLite writes from its own nested statements during DDL (the schema tables,
/// the temporary one included, which `ALTER TABLE` rewrites; `sqlite_sequence` on
/// `ALTER TABLE ... RENAME`) and `ANALYZE` (the statistics tables). The authorizer sees those
/// writes like any other, so the migration policy allows them.
pub const MIGRATION_INTERNAL_TABLES: &[&str] = &[
    "sqlite_master",
    "sqlite_temp_master",
    "sqlite_sequence",
    "sqlite_stat1",
    "sqlite_stat4",
];

/// Row writes: SQLite's internal tables (`sqlite_` prefix) are refused, except
/// [`MIGRATION_INTERNAL_TABLES`] under the migration policy.
fn row_write_allowed(policy: Policy, table_name: &str) -> bool {
    let internal = table_name
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("sqlite_"));
    match policy {
        Policy::Migration => !internal || listed(MIGRATION_INTERNAL_TABLES, table_name),
        Policy::Write => !internal,
        Policy::Read | Policy::Closed => false,
    }
}

/// The authorizer decision for one action, as a pure function so the policy can be read and
/// tested without a connection.
pub fn authorize(policy: Policy, context: &AuthContext<'_>) -> Authorization {
    let allowed = policy != Policy::Closed
        && match context.action {
            AuthAction::Select | AuthAction::Read { .. } | AuthAction::Recursive => true,
            AuthAction::Function { function_name } => function_allowed(policy, function_name),
            AuthAction::Pragma { pragma_name, .. } => listed(INTROSPECTION_PRAGMAS, pragma_name),
            AuthAction::Insert { table_name }
            | AuthAction::Update { table_name, .. }
            | AuthAction::Delete { table_name } => row_write_allowed(policy, table_name),
            // The migration runner owns the transaction; migration SQL that commits, rolls back
            // or opens a savepoint would split the migration into parts that apply on their own.
            AuthAction::Transaction { .. } | AuthAction::Savepoint { .. } => {
                matches!(policy, Policy::Write | Policy::Read)
            }
            AuthAction::CreateTable { .. }
            | AuthAction::CreateIndex { .. }
            | AuthAction::CreateTrigger { .. }
            | AuthAction::CreateView { .. }
            | AuthAction::DropTable { .. }
            | AuthAction::DropIndex { .. }
            | AuthAction::DropTrigger { .. }
            | AuthAction::DropView { .. }
            | AuthAction::AlterTable { .. }
            | AuthAction::Reindex { .. }
            | AuthAction::Analyze { .. } => policy == Policy::Migration,
            // Everything else, including ATTACH, DETACH, temporary objects, virtual tables and
            // any action code this binding does not know, is refused.
            _ => false,
        };
    if allowed {
        Authorization::Allow
    } else {
        Authorization::Deny
    }
}

/// Installs `policy` as the authorizer of `connection`. SQLite expires every statement prepared
/// before the call, so a cached statement cannot bypass it.
pub fn install_authorizer(connection: &Connection, policy: Policy) -> rusqlite::Result<()> {
    connection.authorizer(Some(move |context: AuthContext<'_>| {
        authorize(policy, &context)
    }))
}

fn remove_authorizer(connection: &Connection) -> rusqlite::Result<()> {
    connection.authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
}

/// Opens a SQLCipher file with a raw 256-bit key, runs the connection setup (extension loading
/// API off, key, `secure_delete` on, `trusted_schema` off, WAL for writers), then installs the
/// role's opening policy. A read connection is also opened read-only.
pub fn open(path: &Path, raw_key: &[u8; 32], role: Role) -> rusqlite::Result<Connection> {
    let flags = match role {
        Role::Read => OpenFlags::SQLITE_OPEN_READ_ONLY,
        Role::Migration | Role::Write => {
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
        }
    } | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(path, flags)?;
    disable_extension_loading_api(&connection)?;
    apply_raw_key(&connection, raw_key)?;
    connection.pragma_update(None, "secure_delete", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    if role != Role::Read {
        connection.pragma_update(None, "journal_mode", "WAL")?;
    }
    install_authorizer(&connection, role.opening_policy())?;
    Ok(connection)
}

/// Turns off `sqlite3_load_extension` for this connection. The authorizer never sees that C
/// call, and `libsqlite3-sys` builds the bundled SQLCipher with `SQLITE_ENABLE_LOAD_EXTENSION`,
/// which turns it on for every new connection. rusqlite exposes no safe setter for this switch.
#[allow(unsafe_code)] // One FFI call; rusqlite's `DbConfig` omits this option.
pub fn disable_extension_loading_api(connection: &Connection) -> rusqlite::Result<()> {
    // SAFETY: the handle comes from a live, owned connection that is not used concurrently
    // (opened with NO_MUTEX and borrowed here); this op takes an int and a nullable int pointer.
    let code = unsafe {
        rusqlite::ffi::sqlite3_db_config(
            connection.handle(),
            rusqlite::ffi::SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION,
            0 as std::ffi::c_int,
            std::ptr::null_mut::<std::ffi::c_int>(),
        )
    };
    if code == rusqlite::ffi::SQLITE_OK {
        Ok(())
    } else {
        Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(code),
            Some("could not turn off extension loading".to_owned()),
        ))
    }
}

/// Keys the connection with a raw key (SQLCipher `x'...'` form, no SQLCipher KDF) and reads the
/// schema so a wrong key fails here rather than at first use. Spike only: the hex string and
/// the SQL text holding it are not zeroized.
pub fn apply_raw_key(connection: &Connection, raw_key: &[u8; 32]) -> rusqlite::Result<()> {
    let hex: String = raw_key.iter().map(|byte| format!("{byte:02x}")).collect();
    connection.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))?;
    connection.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })?;
    Ok(())
}

/// Applies one migration atomically. The runner opens and ends the transaction with the
/// authorizer removed, and the migration SQL itself runs under [`Policy::Migration`], which
/// refuses transaction control. On any error the transaction is rolled back and nothing is
/// written. On every exit, success or failure, the connection is left under [`Policy::Closed`],
/// the opening policy of a migration connection; a connection opened for another role is
/// closed too rather than left open to anything.
pub fn apply_migration(connection: &mut Connection, sql: &str) -> rusqlite::Result<()> {
    let outcome = run_migration(connection, sql);
    let closed = install_authorizer(connection, Policy::Closed);
    outcome.and(closed)
}

fn run_migration(connection: &mut Connection, sql: &str) -> rusqlite::Result<()> {
    remove_authorizer(connection)?;
    let transaction = connection.transaction()?;
    install_authorizer(&transaction, Policy::Migration)?;
    let applied = transaction.execute_batch(sql);
    remove_authorizer(&transaction)?;
    match applied {
        Ok(()) => transaction.commit(),
        Err(error) => {
            transaction.rollback()?;
            Err(error)
        }
    }
}

/// The SQLite result code behind `error`. Unlike `rusqlite::Error::sqlite_error_code`, this
/// also reads `SqlInputError`, which rusqlite returns (with `modern_sqlite`, implied by
/// `bundled-sqlcipher`) for a prepare error SQLite can locate in the SQL text, such as a denied
/// function call.
pub fn sqlite_code(error: &rusqlite::Error) -> Option<rusqlite::ErrorCode> {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
        | rusqlite::Error::SqlInputError { error: failure, .. } => Some(failure.code),
        _ => None,
    }
}

/// Prefix of the message SQLite gives when the authorizer denies a function call.
const DENIED_FUNCTION_MESSAGE: &str = "not authorized to use function: ";

/// True when the authorizer refused the statement behind `error`. SQLite reports most denials
/// as `SQLITE_AUTH`, but a denied function call as plain `SQLITE_ERROR` with its own message,
/// so the code alone does not identify an authorizer refusal.
pub fn is_authorizer_denial(error: &rusqlite::Error) -> bool {
    let (failure, message) = match error {
        rusqlite::Error::SqliteFailure(failure, message) => (failure, message.as_deref()),
        rusqlite::Error::SqlInputError { error, msg, .. } => (error, Some(msg.as_str())),
        _ => return false,
    };
    failure.code == rusqlite::ErrorCode::AuthorizationForStatementDenied
        || (failure.extended_code == rusqlite::ffi::SQLITE_ERROR
            && message.is_some_and(|text| text.starts_with(DENIED_FUNCTION_MESSAGE)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_POLICIES: [Policy; 4] = [
        Policy::Closed,
        Policy::Migration,
        Policy::Write,
        Policy::Read,
    ];

    fn decide(policy: Policy, action: AuthAction<'_>) -> Authorization {
        authorize(
            policy,
            &AuthContext {
                action,
                database_name: Some("main"),
                accessor: None,
            },
        )
    }

    /// Actions no policy may allow: an unknown action code, attaching and detaching, virtual
    /// tables and temporary objects.
    #[test]
    fn confinement_actions_are_denied_under_every_policy() {
        for policy in ALL_POLICIES {
            let actions = [
                AuthAction::Unknown {
                    code: 9999,
                    arg1: None,
                    arg2: None,
                },
                AuthAction::Attach {
                    filename: "/tmp/other.db",
                },
                AuthAction::Detach {
                    database_name: "other",
                },
                AuthAction::CreateVtable {
                    table_name: "search",
                    module_name: "fts5",
                },
                AuthAction::DropVtable {
                    table_name: "search",
                    module_name: "fts5",
                },
                AuthAction::CreateTempTable {
                    table_name: "scratch",
                },
                AuthAction::CreateTempTrigger {
                    trigger_name: "scratch",
                    table_name: "items",
                },
                AuthAction::CreateTempView {
                    view_name: "scratch",
                },
            ];
            for action in actions {
                let label = format!("{action:?}");
                assert_eq!(
                    decide(policy, action),
                    Authorization::Deny,
                    "{policy:?} {label}"
                );
            }
        }
    }

    /// The intended policy per action family, one row per policy.
    #[test]
    fn each_policy_allows_only_its_own_actions() {
        let expectations: [(Policy, [bool; 7]); 4] = [
            // (select, create table, insert, insert sqlite_master, insert sqlite_sequence,
            //  begin, allowed pragma)
            (
                Policy::Closed,
                [false, false, false, false, false, false, false],
            ),
            (
                Policy::Migration,
                [true, true, true, true, true, false, true],
            ),
            (Policy::Write, [true, false, true, false, false, true, true]),
            (Policy::Read, [true, false, false, false, false, true, true]),
        ];
        for (policy, expected) in expectations {
            let actions = [
                AuthAction::Select,
                AuthAction::CreateTable { table_name: "t" },
                AuthAction::Insert {
                    table_name: "items",
                },
                AuthAction::Insert {
                    table_name: "sqlite_master",
                },
                AuthAction::Insert {
                    table_name: "SQLITE_SEQUENCE",
                },
                AuthAction::Transaction {
                    operation: rusqlite::hooks::TransactionOperation::Begin,
                },
                AuthAction::Pragma {
                    pragma_name: "TABLE_INFO",
                    pragma_value: Some("items"),
                },
            ];
            for (action, allow) in actions.into_iter().zip(expected) {
                let label = format!("{action:?}");
                let want = if allow {
                    Authorization::Allow
                } else {
                    Authorization::Deny
                };
                assert_eq!(decide(policy, action), want, "{policy:?} {label}");
            }
        }
    }

    #[test]
    fn functions_are_matched_ignoring_case_and_unknown_ones_are_denied() {
        let decision = |name| {
            decide(
                Policy::Read,
                AuthAction::Function {
                    function_name: name,
                },
            )
        };
        assert_eq!(decision("UPPER"), Authorization::Allow);
        assert_eq!(decision("Load_Extension"), Authorization::Deny);
        assert_eq!(decision("not_a_reviewed_function"), Authorization::Deny);
    }
}
