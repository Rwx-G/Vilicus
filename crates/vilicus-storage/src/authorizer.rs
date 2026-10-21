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
//! around its own statements, writes them, and only [`Policy::CoreMigration`], under which the
//! Core track's own migrations run, changes their schema. Module SQL does not even read the
//! Core tables of [`CORE_PRIVATE_TABLES`]: the journal, the outbox and the wrapped record keys
//! hold earlier states of records, effect payloads and the keys that shred records.
//!
//! A module migration may create and drop FTS5 virtual tables in its own file, and no other
//! virtual table (D127, Story 3.7): FTS5 writes its shadow tables from its own nested statements,
//! which the migration policy allows like any table of the module, and every connection runs with
//! `SQLITE_DBCONFIG_DEFENSIVE`, under which module SQL cannot write a shadow table directly.

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
    /// in `_meta`, the confirmed vocabulary labels in `_vocabulary`, the journal, outbox,
    /// consumption and record key rows, and the transaction that holds them, nothing else.
    Core,
    /// The Core track's migrations (AD-26), inside the runner's transaction: schema changes of
    /// [`CORE_TABLES`] only, and the rows of the Core tables and of SQLite's internal tables those
    /// changes write.
    CoreMigration,
}

/// Tables the Core creates in every module file (AD-26) and that module SQL never changes:
/// `_meta`, which `create` writes, and the tables of the Core migration track (`core_schema`). A
/// module that could write `_vocabulary` would confirm its own labels, one that could write
/// `_journal` would forge the history undo restores, and one that could write `_outbox` or
/// `_consumed` would request effects or drop events outside its calls.
/// Compared ignoring ASCII case; the authorizer receives the table name without its schema, so
/// `main._meta` is matched too. The module registry reads it to tell the Core's tables from a
/// module's in a file's schema.
pub const CORE_TABLES: &[&str] = &[
    "_meta",
    "_vocabulary",
    "_migrations",
    "_journal",
    "_outbox",
    "_deliveries",
    "_consumed",
    "_dead_letter",
    "_record_keys",
];

/// The Core tables module SQL cannot read either, under any policy but the Core's own: the
/// journal's images are earlier states of records, deleted ones included, which a module would
/// otherwise still read once the record is gone; the outbox holds the payloads of effects and
/// events, and `_deliveries` and `_dead_letter` which events each consumer missed; and
/// a module that read a wrapped record key could copy it into a record and defeat its shredding
/// (D132). `_migrations`, the frozen hash of every migration the file ran, holds nothing secret,
/// but module SQL has no use for it, and D148 lets module SQL read `_meta` and `_vocabulary`
/// only. `_meta` and `_vocabulary` stay readable: the epoch is a counter and the labels are the
/// module's own vocabulary.
pub const CORE_PRIVATE_TABLES: &[&str] = &[
    "_migrations",
    "_journal",
    "_outbox",
    "_deliveries",
    "_consumed",
    "_dead_letter",
    "_record_keys",
];

/// Virtual table modules a module migration may create and drop, compared ignoring ASCII case:
/// `fts5` alone (D127), in the file's own schema, under [`Policy::Migration`] only. A test fails
/// when the engine offers a module in neither this list nor [`DENIED_MODULES`].
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
/// reads no file path, unlike `database_list`. `data_version` returns a counter of the commits
/// other connections made, and FTS5 reads it before it uses its index, so without it no FTS5
/// table could be created, written or searched (D127, Story 3.2's open point).
pub(crate) const INTROSPECTION_PRAGMAS: &[&str] = &[
    "table_list",
    "table_info",
    "table_xinfo",
    "index_list",
    "index_info",
    "index_xinfo",
    "foreign_key_list",
    "foreign_key_check",
    "data_version",
];

/// Read-only pragmas that SQLite runs from inside a schema change, allowed under the two
/// migration policies only: `quick_check`, which `ALTER TABLE ... ADD COLUMN` runs on a `STRICT`
/// table to check the existing rows against the new column (Story 3.2's finding), and which
/// reports a check, never a value or a path.
pub(crate) const MIGRATION_PRAGMAS: &[&str] = &["quick_check"];

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
/// `ALTER TABLE ... RENAME`). The authorizer sees those writes like any other, so the migration
/// policies allow them. The statistics tables are not among them: no policy runs `ANALYZE`.
pub(crate) const MIGRATION_INTERNAL_TABLES: &[&str] =
    &["sqlite_master", "sqlite_temp_master", "sqlite_sequence"];

/// True for SQLite's statistics tables (`sqlite_stat1` to `sqlite_stat4`, ignoring ASCII case),
/// which `ANALYZE` fills with sampled index keys: run over the whole file, it would copy the keys
/// of the Core's private indexes (call ids, idempotency keys, wrapped record keys) into rows any
/// role reads, and keep them past the deletion of their rows (Story 3.6 review, M1). No policy
/// runs `ANALYZE`, creates, writes or reads them.
fn is_statistics_table(table_name: &str) -> bool {
    table_name
        .get(..11)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("sqlite_stat"))
}

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
    let migration_internal = listed(MIGRATION_INTERNAL_TABLES, table_name);
    match policy {
        Policy::Migration => !core && (!internal || migration_internal),
        Policy::Write => !core && !internal,
        Policy::Core => core,
        Policy::CoreMigration => core || migration_internal,
        Policy::Read | Policy::Closed => false,
    }
}

/// Schema changes: the migration policy, never on [`CORE_TABLES`] (dropping, altering, indexing
/// or attaching a trigger to `_meta` would defeat the epoch cross-check of AD-5, to `_vocabulary`
/// would let a module confirm its own labels, and to `_journal` would let it rewrite history) nor
/// on a statistics table; and the Core migration policy, on [`CORE_TABLES`] only. A view, which
/// names no table, is the migration policy's alone.
fn schema_change_allowed(policy: Policy, table_name: Option<&str>) -> bool {
    let core = table_name.is_some_and(|name| listed(CORE_TABLES, name));
    let statistics = table_name.is_some_and(is_statistics_table);
    match policy {
        Policy::Migration => !core && !statistics,
        Policy::CoreMigration => core,
        Policy::Write | Policy::Read | Policy::Core | Policy::Closed => false,
    }
}

/// Reads: never of a denied virtual table module nor of a statistics table, and of
/// [`CORE_PRIVATE_TABLES`] only under the Core's own policies.
fn read_allowed(policy: Policy, table_name: &str) -> bool {
    !listed(DENIED_MODULES, table_name)
        && !is_statistics_table(table_name)
        && (matches!(policy, Policy::Core | Policy::CoreMigration)
            || !listed(CORE_PRIVATE_TABLES, table_name))
}

/// Pragmas: the introspection allowlist under every policy, and the pragmas SQLite runs inside a
/// schema change under the migration policies.
fn pragma_allowed(policy: Policy, pragma_name: &str) -> bool {
    listed(INTROSPECTION_PRAGMAS, pragma_name)
        || (matches!(policy, Policy::Migration | Policy::CoreMigration)
            && listed(MIGRATION_PRAGMAS, pragma_name))
}

/// `CREATE VIRTUAL TABLE` and `DROP VIRTUAL TABLE` (D127): under the migration policy only, for
/// a module of [`ALLOWED_MODULES`] (`fts5`, ignoring ASCII case), in the connection's own schema
/// (`main`, never `temp`), and never under a Core table's or a statistics table's name.
fn virtual_table_allowed(
    policy: Policy,
    database_name: Option<&str>,
    table_name: &str,
    module_name: &str,
) -> bool {
    policy == Policy::Migration
        && listed(ALLOWED_MODULES, module_name)
        && database_name == Some("main")
        && schema_change_allowed(policy, Some(table_name))
}

/// The authorizer decision for one action, as a pure function so the policy can be read and
/// tested without a connection.
pub(crate) fn authorize(policy: Policy, context: &AuthContext<'_>) -> Authorization {
    let allowed = policy != Policy::Closed
        && match context.action {
            AuthAction::Select | AuthAction::Recursive => true,
            AuthAction::Read { table_name, .. } => read_allowed(policy, table_name),
            AuthAction::Function { function_name } => function_allowed(policy, function_name),
            AuthAction::Pragma { pragma_name, .. } => pragma_allowed(policy, pragma_name),
            AuthAction::CreateVtable {
                table_name,
                module_name,
            }
            | AuthAction::DropVtable {
                table_name,
                module_name,
            } => virtual_table_allowed(policy, context.database_name, table_name, module_name),
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
            // SQLite authorizes a `CREATE INDEX` as a reindex of the new index too, naming the
            // index only; both migration policies create indexes on their own tables.
            AuthAction::Reindex { .. } => {
                matches!(policy, Policy::Migration | Policy::CoreMigration)
            }
            AuthAction::CreateView { .. } | AuthAction::DropView { .. } => {
                schema_change_allowed(policy, None)
            }
            // `ANALYZE` samples index keys into the statistics tables, those of the Core's
            // private indexes included, under every policy (Story 3.6 review, M1).
            AuthAction::Analyze { .. } => false,
            // Everything else, including ATTACH, DETACH, temporary objects and any action code
            // this binding does not know, is refused.
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

    const ALL_POLICIES: [Policy; 6] = [
        Policy::Closed,
        Policy::Migration,
        Policy::Write,
        Policy::Read,
        Policy::Core,
        Policy::CoreMigration,
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
    /// tables of any module but FTS5 and temporary objects.
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
                    module_name: "fts4",
                },
                AuthAction::DropVtable {
                    table_name: "search",
                    module_name: "rtree",
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

    fn decide_in(policy: Policy, database_name: &str, action: AuthAction<'_>) -> Authorization {
        authorize(
            policy,
            &AuthContext {
                action,
                database_name: Some(database_name),
                accessor: None,
            },
        )
    }

    /// AC9 of Story 3.7 (D127): a virtual table is created or dropped under the migration policy
    /// only, only for the `fts5` module in any case spelling and in the file's own schema, and
    /// never under a Core table's or a statistics table's name; every other module of the
    /// engine, reviewed or not, is refused under every policy.
    #[test]
    fn only_a_module_migration_creates_or_drops_an_fts5_table() {
        let virtual_table = |create: bool, table_name, module_name| {
            if create {
                AuthAction::CreateVtable {
                    table_name,
                    module_name,
                }
            } else {
                AuthAction::DropVtable {
                    table_name,
                    module_name,
                }
            }
        };
        for create in [true, false] {
            for policy in ALL_POLICIES {
                for spelling in ["fts5", "FTS5", "Fts5"] {
                    assert_eq!(
                        decide(policy, virtual_table(create, "notes_search", spelling)),
                        if policy == Policy::Migration {
                            Authorization::Allow
                        } else {
                            Authorization::Deny
                        },
                        "{policy:?} {spelling} create {create}"
                    );
                    for schema in ["temp", "other"] {
                        assert_eq!(
                            decide_in(
                                policy,
                                schema,
                                virtual_table(create, "notes_search", spelling)
                            ),
                            Authorization::Deny,
                            "{policy:?} {schema}.{spelling} create {create}"
                        );
                    }
                }
                for &module in DENIED_MODULES
                    .iter()
                    .chain(&["fts5x", "fts", "", "unknown"])
                {
                    assert_eq!(
                        decide(policy, virtual_table(create, "notes_search", module)),
                        Authorization::Deny,
                        "{policy:?} {module} create {create}"
                    );
                }
                for name in CORE_TABLES
                    .iter()
                    .copied()
                    .chain(["sqlite_stat1", "SQLITE_STAT4"])
                {
                    assert_eq!(
                        decide(policy, virtual_table(create, name, "fts5")),
                        Authorization::Deny,
                        "{policy:?} {name} create {create}"
                    );
                }
            }
        }
    }

    /// AC9 of Story 3.7: FTS5 reads `data_version` before it uses its index, under every policy
    /// that runs statements, and `ALTER TABLE ... ADD COLUMN` on a `STRICT` table runs
    /// `quick_check`, under the migration policies only.
    #[test]
    fn the_pragmas_fts5_and_strict_tables_run_are_allowed_where_they_run() {
        for policy in ALL_POLICIES {
            let decision = |pragma_name, pragma_value| {
                decide(
                    policy,
                    AuthAction::Pragma {
                        pragma_name,
                        pragma_value,
                    },
                )
            };
            let runs = policy != Policy::Closed;
            let migrates = matches!(policy, Policy::Migration | Policy::CoreMigration);
            assert_eq!(
                decision("data_version", None) == Authorization::Allow,
                runs,
                "{policy:?} data_version"
            );
            for (name, value) in [("quick_check", Some("items")), ("QUICK_CHECK", None)] {
                assert_eq!(
                    decision(name, value) == Authorization::Allow,
                    migrates,
                    "{policy:?} {name}"
                );
            }
            for name in [
                "integrity_check",
                "cell_size_check",
                "schema_version",
                "user_version",
            ] {
                assert_eq!(
                    decision(name, None),
                    Authorization::Deny,
                    "{policy:?} {name}"
                );
            }
        }
    }

    /// The intended policy per action family, one row per policy.
    #[test]
    fn each_policy_allows_only_its_own_actions() {
        let expectations: [(Policy, [bool; 7]); 6] = [
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
            (
                Policy::CoreMigration,
                [true, false, false, true, true, false, true],
            ),
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

    /// Story 3.6 review, M1: `ANALYZE`, of the file, of a table or of the schema, runs under no
    /// policy, and no policy creates, writes or reads a statistics table, in any case spelling.
    #[test]
    fn no_policy_analyzes_or_reaches_the_statistics_tables() {
        for policy in ALL_POLICIES {
            for table_name in ["", "items", "_journal", "main"] {
                assert_eq!(
                    decide(policy, AuthAction::Analyze { table_name }),
                    Authorization::Deny,
                    "{policy:?} ANALYZE {table_name}"
                );
            }
            for name in [
                "sqlite_stat1",
                "SQLITE_STAT4",
                "sqlite_stat2",
                "sqlite_Stat3",
            ] {
                let actions = [
                    AuthAction::Read {
                        table_name: name,
                        column_name: "sample",
                    },
                    AuthAction::Insert { table_name: name },
                    AuthAction::Update {
                        table_name: name,
                        column_name: "stat",
                    },
                    AuthAction::Delete { table_name: name },
                    AuthAction::CreateTable { table_name: name },
                    AuthAction::DropTable { table_name: name },
                ];
                for action in actions {
                    let label = format!("{policy:?} {action:?}");
                    assert_eq!(decide(policy, action), Authorization::Deny, "{label}");
                }
            }
        }
        assert_eq!(
            decide(
                Policy::Migration,
                AuthAction::Insert {
                    table_name: "sqlite_sequence"
                }
            ),
            Authorization::Allow,
            "the internal writes of DDL stay allowed"
        );
    }

    /// Story 3.6: every Core table, the journal's included, is written under the Core policy
    /// only and changed in schema under the Core migration policy only; the Core migration policy
    /// changes no module table; and the private Core tables are read under the Core's policies
    /// only, while `_meta` and `_vocabulary` stay readable.
    #[test]
    fn the_core_track_alone_shapes_the_core_tables_and_their_private_rows_stay_the_cores() {
        for &name in CORE_TABLES {
            for spelling in [name.to_owned(), name.to_ascii_uppercase()] {
                let name = spelling.as_str();
                let writes = [
                    AuthAction::Insert { table_name: name },
                    AuthAction::Update {
                        table_name: name,
                        column_name: "x",
                    },
                    AuthAction::Delete { table_name: name },
                ];
                let schema_changes = [
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
                    AuthAction::CreateTrigger {
                        trigger_name: "t",
                        table_name: name,
                    },
                ];
                for policy in ALL_POLICIES {
                    let may_write = matches!(policy, Policy::Core | Policy::CoreMigration);
                    for action in writes {
                        let label = format!("{policy:?} {action:?}");
                        assert_eq!(
                            decide(policy, action) == Authorization::Allow,
                            may_write,
                            "{label}"
                        );
                    }
                    for action in schema_changes {
                        let label = format!("{policy:?} {action:?}");
                        assert_eq!(
                            decide(policy, action) == Authorization::Allow,
                            policy == Policy::CoreMigration,
                            "{label}"
                        );
                    }
                    let read = AuthAction::Read {
                        table_name: name,
                        column_name: "x",
                    };
                    let may_read = policy != Policy::Closed
                        && (matches!(policy, Policy::Core | Policy::CoreMigration)
                            || !listed(CORE_PRIVATE_TABLES, name));
                    assert_eq!(
                        decide(policy, read) == Authorization::Allow,
                        may_read,
                        "{policy:?} read {name}"
                    );
                }
            }
        }
        for private in CORE_PRIVATE_TABLES {
            assert!(listed(CORE_TABLES, private), "{private} is a Core table");
        }
        for readable in ["_meta", "_vocabulary"] {
            assert!(!listed(CORE_PRIVATE_TABLES, readable), "{readable}");
        }
        for action in [
            AuthAction::CreateTable {
                table_name: "items",
            },
            AuthAction::Insert {
                table_name: "items",
            },
            AuthAction::Delete {
                table_name: "items",
            },
            AuthAction::CreateView { view_name: "v" },
            AuthAction::Transaction {
                operation: rusqlite::hooks::TransactionOperation::Begin,
            },
            AuthAction::Function {
                function_name: "sqlite_rename_table",
            },
        ] {
            let label = format!("{action:?}");
            assert_eq!(
                decide(Policy::CoreMigration, action),
                Authorization::Deny,
                "{label}"
            );
        }
    }
}
