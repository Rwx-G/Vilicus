//! The connection authorizer (AD-5, AD-9, I6, D126), moved from the E11 spike
//! (`spikes/sqlite-authorizer/src/lib.rs`) with the same policies and lists.
//!
//! Each policy is an allowlist: an authorizer action that is not explicitly allowed is denied,
//! so an action code SQLite adds later is refused by default. SQL functions are allowlisted too;
//! a test fails when the engine offers a function that is in neither list. Connection setup runs
//! before the authorizer is installed, because SQLCipher pragmas go through it (Story 1.7,
//! finding 6); once it is installed, no pragma outside [`INTROSPECTION_PRAGMAS`] runs.
//!
//! The Core tables of a module file ([`CORE_TABLES`], AD-26) are the Core's: no module SQL,
//! write or migration, and no trigger body, which SQLite authorizes when it fires, may write,
//! drop, alter, index or attach a trigger to them. Only [`Policy::Core`], which the Core installs
//! around its own statements, writes them.

use rusqlite::Connection;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

/// The authorizer policy in force on a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Policy {
    /// Denies every action: a migration connection outside the runner.
    Closed,
    /// Schema changes and data backfill in the connection's own file, inside the runner's
    /// transaction.
    Migration,
    /// Rows in the connection's own tables.
    Write,
    /// Reads, and `BEGIN`/`COMMIT` around them: a cross-module read made of several queries
    /// (AD-9) needs one snapshot to see one state. A snapshot held long keeps deleted rows in the
    /// WAL, which `Handle::checkpoint_truncate` then reports as incomplete.
    Read,
    /// The Core's own fixed statements on [`CORE_TABLES`]: the key epoch and the schema versions
    /// in `_meta`, the confirmed vocabulary labels in `_vocabulary`, and the transaction that
    /// holds them, nothing else.
    Core,
}

/// Tables the Core creates in every module file (AD-26) and that module SQL never changes:
/// `_meta`, and `_vocabulary`, the labels an adult confirmed for the file's reviewed vocabularies
/// (D104), with which a module that could write it would confirm its own labels.
/// Compared ignoring ASCII case; the authorizer receives the table name without its schema, so
/// `main._meta` is matched too. `_journal`, `_outbox`, `_consumed` and `_dead_letter` join this
/// list with the stories that create them (3.6, 3.8). The module registry reads it to tell the
/// Core's tables from a module's in a file's schema.
pub const CORE_TABLES: &[&str] = &["_meta", "_vocabulary"];

/// Virtual table modules reviewed as usable by module SQL under some policy: `fts5`, whose tables
/// a module migration may create once Story 3.7 applies D127. Today every `CREATE VIRTUAL TABLE`
/// is refused. A test fails when the engine offers a module in neither this list nor
/// [`DENIED_MODULES`].
#[cfg(test)]
pub(crate) const ALLOWED_MODULES: &[&str] = &["fts5"];

/// Virtual table modules reviewed and refused: page-level statistics of the file (`dbstat`, an
/// eponymous table any statement can read), FTS3 and FTS4 and their helpers (D127 keeps FTS5
/// only), `fts5vocab`, the R-tree modules and the `pragma_module_list` table function, which is a
/// pragma outside the allowlist. A read of a table with one of these names is refused, which is
/// how an eponymous module like `dbstat` is reached.
pub(crate) const DENIED_MODULES: &[&str] = &[
    "dbstat",
    "fts3",
    "fts3tokenize",
    "fts4",
    "fts4aux",
    "fts5vocab",
    "pragma_module_list",
    "rtree",
    "rtree_i32",
];

/// Read-only schema introspection pragmas, allowed under every policy but [`Policy::Closed`].
/// Compared ignoring ASCII case, because the authorizer receives the pragma name as written.
/// `temp_store` is not here, so temporary data stays in memory (D132). `table_list` names the
/// tables of the connection's own schemas with their kind (ordinary, virtual, shadow, view) and
/// their `STRICT` flag, which the module registry compares with its declarations (AD-9); it
/// reads no file path, unlike `database_list`.
pub(crate) const INTROSPECTION_PRAGMAS: &[&str] = &[
    "table_list",
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
/// Compared ignoring ASCII case. `json_array_insert` and `jsonb_array_insert`, new in SQLite
/// 3.53, were reviewed with the SQLCipher 4.19.0 build (D143): they compute on their arguments
/// like `json_insert`.
pub(crate) const ALLOWED_FUNCTIONS: &[&str] = &[
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
    "json_array_insert",
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
    "jsonb_array_insert",
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
#[cfg(test)]
pub(crate) const DENIED_FUNCTIONS: &[&str] = &[
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

/// Functions of [`DENIED_FUNCTIONS`] that the build compiles out, so the engine does not offer
/// them at all (D126, `build.rs`); a test checks that the engine indeed lacks them.
#[cfg(test)]
pub(crate) const COMPILED_OUT_FUNCTIONS: &[&str] = &["load_extension"];

/// SQLite's internal functions that `ALTER TABLE` calls from its own nested statements, which
/// still pass through the authorizer. Allowed under [`Policy::Migration`] only. SQL text cannot
/// call them: SQLite resolves internal functions only inside its own nested statements, which a
/// test checks.
pub(crate) const INTERNAL_ALTER_FUNCTIONS: &[&str] = &[
    "sqlite_rename_column",
    "sqlite_rename_table",
    "sqlite_rename_test",
    "sqlite_drop_column",
    "sqlite_rename_quotefix",
];

/// Internal tables SQLite writes from its own nested statements during DDL (the schema tables,
/// the temporary one included, which `ALTER TABLE` rewrites; `sqlite_sequence` on
/// `ALTER TABLE ... RENAME`) and `ANALYZE` (the statistics tables). The authorizer sees those
/// writes like any other, so the migration policy allows them.
pub(crate) const MIGRATION_INTERNAL_TABLES: &[&str] = &[
    "sqlite_master",
    "sqlite_temp_master",
    "sqlite_sequence",
    "sqlite_stat1",
    "sqlite_stat4",
];

pub(crate) fn listed(list: &[&str], name: &str) -> bool {
    list.iter().any(|entry| entry.eq_ignore_ascii_case(name))
}

fn function_allowed(policy: Policy, function_name: &str) -> bool {
    listed(ALLOWED_FUNCTIONS, function_name)
        || (policy == Policy::Migration && listed(INTERNAL_ALTER_FUNCTIONS, function_name))
}

/// Row writes: SQLite's internal tables (`sqlite_` prefix) are refused, except
/// [`MIGRATION_INTERNAL_TABLES`] under the migration policy; [`CORE_TABLES`] are written under
/// [`Policy::Core`] only, which writes nothing else.
fn row_write_allowed(policy: Policy, table_name: &str) -> bool {
    let internal = table_name
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("sqlite_"));
    let core = listed(CORE_TABLES, table_name);
    match policy {
        Policy::Migration => !core && (!internal || listed(MIGRATION_INTERNAL_TABLES, table_name)),
        Policy::Write => !core && !internal,
        Policy::Core => core,
        Policy::Read | Policy::Closed => false,
    }
}

/// Schema changes: the migration policy only, and never on [`CORE_TABLES`] (dropping, altering,
/// indexing or attaching a trigger to `_meta` would defeat the epoch cross-check of AD-5, and to
/// `_vocabulary` would let a module confirm its own labels).
fn schema_change_allowed(policy: Policy, table_name: Option<&str>) -> bool {
    policy == Policy::Migration && !table_name.is_some_and(|name| listed(CORE_TABLES, name))
}

/// The authorizer decision for one action, as a pure function so the policy can be read and
/// tested without a connection.
pub(crate) fn authorize(policy: Policy, context: &AuthContext<'_>) -> Authorization {
    let allowed = policy != Policy::Closed
        && match context.action {
            AuthAction::Select | AuthAction::Recursive => true,
            AuthAction::Read { table_name, .. } => !listed(DENIED_MODULES, table_name),
            AuthAction::Function { function_name } => function_allowed(policy, function_name),
            AuthAction::Pragma { pragma_name, .. } => listed(INTROSPECTION_PRAGMAS, pragma_name),
            AuthAction::Insert { table_name }
            | AuthAction::Update { table_name, .. }
            | AuthAction::Delete { table_name } => row_write_allowed(policy, table_name),
            // The migration runner owns the transaction; migration SQL that commits, rolls back
            // or opens a savepoint would split the migration into parts that apply on their own.
            AuthAction::Transaction { .. } => {
                matches!(policy, Policy::Write | Policy::Read | Policy::Core)
            }
            AuthAction::Savepoint { .. } => matches!(policy, Policy::Write | Policy::Read),
            AuthAction::CreateTable { table_name }
            | AuthAction::CreateIndex { table_name, .. }
            | AuthAction::CreateTrigger { table_name, .. }
            | AuthAction::DropTable { table_name }
            | AuthAction::DropIndex { table_name, .. }
            | AuthAction::DropTrigger { table_name, .. }
            | AuthAction::AlterTable { table_name, .. } => {
                schema_change_allowed(policy, Some(table_name))
            }
            AuthAction::CreateView { .. }
            | AuthAction::DropView { .. }
            | AuthAction::Reindex { .. }
            | AuthAction::Analyze { .. } => schema_change_allowed(policy, None),
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
pub(crate) fn install(connection: &Connection, policy: Policy) -> rusqlite::Result<()> {
    connection.authorizer(Some(move |context: AuthContext<'_>| {
        authorize(policy, &context)
    }))
}

/// Removes the authorizer; only the migration runner does, around its own transaction control.
/// The Core's own writes to `_meta` swap to [`Policy::Core`] instead, so even its statements stay
/// confined.
pub(crate) fn remove(connection: &Connection) -> rusqlite::Result<()> {
    connection.authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_POLICIES: [Policy; 5] = [
        Policy::Closed,
        Policy::Migration,
        Policy::Write,
        Policy::Read,
        Policy::Core,
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
        let expectations: [(Policy, [bool; 7]); 5] = [
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
            (Policy::Core, [true, false, false, false, false, true, true]),
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

    /// M1 of the Story 3.1 review: the Core tables are out of reach of every module policy, in
    /// any case spelling, and only the Core policy writes them, and nothing else.
    #[test]
    fn core_tables_are_written_only_under_the_core_policy() {
        for name in ["_meta", "_META", "_Meta"] {
            let actions = [
                AuthAction::Insert { table_name: name },
                AuthAction::Update {
                    table_name: name,
                    column_name: "value",
                },
                AuthAction::Delete { table_name: name },
                AuthAction::CreateTable { table_name: name },
                AuthAction::DropTable { table_name: name },
                AuthAction::AlterTable {
                    database_name: "main",
                    table_name: name,
                },
                AuthAction::CreateIndex {
                    index_name: "i",
                    table_name: name,
                },
                AuthAction::DropIndex {
                    index_name: "i",
                    table_name: name,
                },
                AuthAction::CreateTrigger {
                    trigger_name: "t",
                    table_name: name,
                },
                AuthAction::DropTrigger {
                    trigger_name: "t",
                    table_name: name,
                },
            ];
            for policy in [
                Policy::Closed,
                Policy::Migration,
                Policy::Write,
                Policy::Read,
            ] {
                for action in actions {
                    let label = format!("{action:?}");
                    assert_eq!(
                        decide(policy, action),
                        Authorization::Deny,
                        "{policy:?} {label}"
                    );
                }
            }
            for action in [
                AuthAction::Update {
                    table_name: name,
                    column_name: "value",
                },
                AuthAction::Insert { table_name: name },
            ] {
                let label = format!("{action:?}");
                assert_eq!(
                    decide(Policy::Core, action),
                    Authorization::Allow,
                    "{label}"
                );
            }
        }
        for action in [
            AuthAction::Update {
                table_name: "items",
                column_name: "label",
            },
            AuthAction::Delete {
                table_name: "items",
            },
            AuthAction::Savepoint {
                operation: rusqlite::hooks::TransactionOperation::Begin,
                savepoint_name: "s",
            },
            AuthAction::CreateTable { table_name: "t" },
        ] {
            let label = format!("{action:?}");
            assert_eq!(decide(Policy::Core, action), Authorization::Deny, "{label}");
        }
    }

    /// Item 5 of the review: a read of a denied module's eponymous table is refused under every
    /// policy; a read of an ordinary table is not.
    #[test]
    fn reads_of_denied_modules_are_refused() {
        for policy in ALL_POLICIES {
            for name in ["dbstat", "DBSTAT"] {
                let action = AuthAction::Read {
                    table_name: name,
                    column_name: "",
                };
                assert_eq!(
                    decide(policy, action),
                    Authorization::Deny,
                    "{policy:?} {name}"
                );
            }
        }
        assert_eq!(
            decide(
                Policy::Read,
                AuthAction::Read {
                    table_name: "items",
                    column_name: "label"
                }
            ),
            Authorization::Allow
        );
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
        assert_eq!(decision("SQLCIPHER_EXPORT"), Authorization::Deny);
        assert_eq!(decision("not_a_reviewed_function"), Authorization::Deny);
    }

    /// AC8: `temp_store` is outside the pragma allowlist under every policy (D132).
    #[test]
    fn temp_store_is_refused_under_every_policy() {
        for policy in ALL_POLICIES {
            for value in [None, Some("FILE"), Some("1")] {
                assert_eq!(
                    decide(
                        policy,
                        AuthAction::Pragma {
                            pragma_name: "temp_store",
                            pragma_value: value
                        }
                    ),
                    Authorization::Deny,
                    "{policy:?} temp_store {value:?}"
                );
            }
        }
    }
}
