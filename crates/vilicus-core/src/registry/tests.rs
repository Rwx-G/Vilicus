//! Story 3.2: the registry built at build time (AC1), the envelope (AC2), the field declarations
//! (AC3), the data types (AC4), the declaration compared with the migrated schema in the
//! build-time test and at open (AC5), and the FTS5 allowlist (AC7).

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use vilicus_module_api::{
    DataType, DeclarationError, ENVELOPE, Field, FieldKind, Fts5Content, Fts5Table, Fts5Tokenizer,
    Migration, ModuleDeclaration, Structured, Table,
};
use vilicus_storage::{ModuleFile, Partition, Read, Write};
use vilicus_types::ModuleName;

use super::schema::{self, SchemaError, Snapshot};
use super::{FileError, Registry, RegistryError};

/// Test key only; the Core derives one key per file.
const KEY: [u8; 32] = [0x3c; 32];

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vilicus-core-registry-{}-{}-{label}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("create scratch directory");
    dir
}

/// The envelope columns as a migration writes them, built from `ENVELOPE` so no list is retyped.
fn envelope_sql() -> String {
    ENVELOPE
        .iter()
        .map(|column| {
            column_sql(
                column.name,
                column.sql_type.as_str(),
                column.not_null,
                column.primary_key,
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn column_sql(name: &str, sql_type: &str, not_null: bool, primary_key: bool) -> String {
    let mut sql = format!("{name} {sql_type}");
    if not_null {
        sql.push_str(" NOT NULL");
    }
    if primary_key {
        sql.push_str(" PRIMARY KEY");
    }
    sql
}

fn leak<T>(items: Vec<T>) -> &'static [T] {
    items.leak()
}

fn leak_str(text: String) -> &'static str {
    text.leak()
}

const ITEM_FIELDS: &[Field] = &[
    Field {
        name: "label",
        kind: FieldKind::FreeText { max_len: 200 },
        optional: false,
    },
    Field {
        name: "status",
        kind: FieldKind::Structured(Structured::Enumeration(&["open", "done"])),
        optional: false,
    },
    Field {
        name: "quantity",
        kind: FieldKind::Structured(Structured::Integer { min: 0, max: 999 }),
        optional: true,
    },
    Field {
        name: "due_on",
        kind: FieldKind::Structured(Structured::Date),
        optional: true,
    },
    Field {
        name: "reminded_at",
        kind: FieldKind::Structured(Structured::Timestamp),
        optional: true,
    },
    Field {
        name: "list_id",
        kind: FieldKind::Structured(Structured::Uuid),
        optional: true,
    },
];

/// The field the second migration adds.
const AISLE: Field = Field {
    name: "aisle",
    kind: FieldKind::Structured(Structured::ReviewedVocabulary("aisles")),
    optional: true,
};

fn items_columns_sql() -> String {
    let fields: Vec<String> = ITEM_FIELDS
        .iter()
        .map(|field| {
            column_sql(
                field.name,
                field.kind.sql_type().as_str(),
                !field.optional,
                false,
            )
        })
        .collect();
    format!("{}, {}", envelope_sql(), fields.join(", "))
}

/// A module that meets the contract: two tables, two migrations, an index.
fn sample() -> ModuleDeclaration {
    let mut fields = ITEM_FIELDS.to_vec();
    fields.push(AISLE);
    ModuleDeclaration {
        name: "sample",
        tables: leak(vec![
            Table {
                name: "items",
                data_types: &[DataType::ShoppingList, DataType::Stock],
                fields: leak(fields),
            },
            Table {
                name: "notes",
                data_types: &[DataType::Journal],
                fields: &[Field {
                    name: "body",
                    kind: FieldKind::FreeText { max_len: 4000 },
                    optional: false,
                }],
            },
        ]),
        fts5_tables: &[],
        migrations: leak(vec![
            Migration {
                sql: leak_str(format!(
                    "CREATE TABLE items ({});\nCREATE INDEX items_status ON items (status);",
                    items_columns_sql()
                )),
            },
            Migration {
                sql: leak_str(format!(
                    "ALTER TABLE items ADD COLUMN {};\nCREATE TABLE notes ({}, body TEXT NOT NULL) STRICT;",
                    column_sql(AISLE.name, AISLE.kind.sql_type().as_str(), false, false),
                    envelope_sql()
                )),
            },
        ]),
        matrix_sections: &[],
        tools: &[],
    }
}

fn registry_of(modules: Vec<ModuleDeclaration>) -> Registry {
    let modules: Vec<&'static ModuleDeclaration> = modules
        .into_iter()
        .map(|module| &*Box::leak(Box::new(module)))
        .collect();
    Registry::new(leak(modules)).expect("a valid registry")
}

/// `sample` with its first migration replaced by an `items` table of `columns`. The `items` table
/// is not `STRICT`: the second migration adds a column to it, which SQLite checks on a `STRICT`
/// table through `pragma_quick_check`, a pragma the migration authorizer refuses.
fn sample_with_items_sql(columns: &str) -> ModuleDeclaration {
    sample_with_items_definition(columns, "")
}

fn verify(module: ModuleDeclaration, label: &str) -> Result<(), FileError> {
    registry_of(vec![module])
        .verify_migrations(&scratch_dir(label), &KEY)
        .map_err(|error| error.error)
}

fn schema_error(outcome: Result<(), FileError>) -> SchemaError {
    match outcome {
        Err(FileError::Schema(error)) => error,
        other => panic!("expected a schema error, got {other:?}"),
    }
}

const EMPTY: ModuleDeclaration = ModuleDeclaration {
    name: "empty",
    tables: &[],
    fts5_tables: &[],
    migrations: &[],
    matrix_sections: &[],
    tools: &[],
};

const LITERAL: ModuleDeclaration = ModuleDeclaration {
    name: "literal",
    tables: &[Table {
        name: "entries",
        data_types: &[DataType::Health],
        fields: &[Field {
            name: "body",
            kind: FieldKind::FreeText { max_len: 100 },
            optional: false,
        }],
    }],
    fts5_tables: &[],
    migrations: &[Migration {
        sql: "CREATE TABLE entries (id BLOB NOT NULL PRIMARY KEY, source TEXT NOT NULL, \
              taint TEXT NOT NULL, text_taint TEXT NOT NULL, data_types TEXT NOT NULL, \
              author BLOB, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, \
              rev INTEGER NOT NULL, body TEXT NOT NULL) STRICT;",
    }],
    matrix_sections: &[],
    tools: &[],
};

/// AC1: a registry built in a `const` item, from a `'static` list.
const REGISTRY: Registry = match Registry::new(&[&EMPTY, &LITERAL]) {
    Ok(registry) => registry,
    Err(error) => panic!("{}", error.rule()),
};

/// AC1 (FR-22, AD-9): the registry, built at build time, lists each module's schema, migrations
/// and record kinds with their data types.
#[test]
fn the_registry_lists_its_modules_built_at_build_time() {
    let names: Vec<&str> = REGISTRY
        .modules()
        .iter()
        .map(|module| module.name)
        .collect();
    assert_eq!(names, ["empty", "literal"]);
    let literal = REGISTRY
        .module(&ModuleName::from_static("literal"))
        .expect("registered");
    assert_eq!(literal.tables[0].name, "entries");
    assert_eq!(literal.tables[0].data_types, [DataType::Health]);
    assert_eq!(literal.tables[0].fields[0].name, "body");
    assert_eq!(literal.migrations.len(), 1);
    assert!(REGISTRY.module(&ModuleName::from_static("other")).is_none());
    REGISTRY
        .verify_migrations(&scratch_dir("const-registry"), &KEY)
        .expect("the literal migration produces the declared schema");
}

/// AC1, AC3, AC4: the registry refuses a declaration that breaks a rule, and two modules of one
/// name.
#[test]
fn the_registry_refuses_invalid_or_duplicate_modules() {
    let without_data_types = ModuleDeclaration {
        tables: &[Table {
            name: "entries",
            data_types: &[],
            fields: &[],
        }],
        ..LITERAL
    };
    let free_text_unbounded = ModuleDeclaration {
        tables: &[Table {
            name: "entries",
            data_types: &[DataType::Health],
            fields: &[Field {
                name: "body",
                kind: FieldKind::FreeText { max_len: 0 },
                optional: false,
            }],
        }],
        ..LITERAL
    };
    let cases = [
        (
            without_data_types,
            DeclarationError::NoDataType { table: "entries" },
        ),
        (
            free_text_unbounded,
            DeclarationError::FreeTextWithoutMaxLength {
                table: "entries",
                field: "body",
            },
        ),
    ];
    for (module, error) in cases {
        let modules = leak(vec![&*Box::leak(Box::new(module))]);
        assert_eq!(
            Registry::new(modules).map(|_| ()),
            Err(RegistryError::Declaration {
                module: "literal",
                error
            })
        );
    }
    assert_eq!(
        Registry::new(&[&EMPTY, &LITERAL, &EMPTY]).map(|_| ()),
        Err(RegistryError::DuplicateModule { module: "empty" })
    );
}

/// AC5, the build-time test: the sample module's two migrations produce its declaration.
#[test]
fn the_migrations_of_a_conforming_module_produce_its_declaration() {
    verify(sample(), "conforming").expect("conforming module");
}

/// AC2 (FR-18, AD-6, I8): a table missing `source`, `taint` or any other envelope column fails
/// registration, naming the column.
#[test]
fn a_table_missing_an_envelope_column_fails_registration() {
    for missing in ENVELOPE {
        let columns: Vec<String> = ENVELOPE
            .iter()
            .filter(|column| column.name != missing.name)
            .map(|column| {
                column_sql(
                    column.name,
                    column.sql_type.as_str(),
                    column.not_null,
                    column.primary_key,
                )
            })
            .chain(ITEM_FIELDS.iter().map(|field| {
                column_sql(
                    field.name,
                    field.kind.sql_type().as_str(),
                    !field.optional,
                    false,
                )
            }))
            .collect();
        let error = schema_error(verify(
            sample_with_items_sql(&columns.join(", ")),
            &format!("envelope-{}", missing.name),
        ));
        assert_eq!(
            error,
            SchemaError::EnvelopeColumnMissing {
                table: "items",
                column: missing.name
            }
        );
    }
}

/// AC2: an envelope column of the wrong type, nullability or key fails too.
#[test]
fn an_envelope_column_of_another_shape_fails_registration() {
    for (column, replacement) in [
        ("taint", "taint INTEGER NOT NULL"),
        ("text_taint", "text_taint TEXT"),
        ("source", "source TEXT"),
        ("id", "id BLOB NOT NULL"),
        ("author", "author BLOB NOT NULL"),
        ("rev", "rev ANY NOT NULL"),
    ] {
        let original = ENVELOPE
            .iter()
            .find(|envelope| envelope.name == column)
            .map(|envelope| {
                column_sql(
                    envelope.name,
                    envelope.sql_type.as_str(),
                    envelope.not_null,
                    envelope.primary_key,
                )
            })
            .expect("envelope column");
        let columns = items_columns_sql().replacen(&original, replacement, 1);
        let error = schema_error(verify(
            sample_with_items_sql(&columns),
            &format!("envelope-shape-{column}"),
        ));
        assert!(
            matches!(&error, SchemaError::ColumnMismatch { table: "items", column: found, .. } if *found == column),
            "{column}: {error:?}"
        );
    }
}

/// AC3 (FR-58): a column the declaration does not hold, a declared field without its column, or
/// a field of another type or nullability, fails registration.
#[test]
fn fields_must_be_the_declared_ones() {
    let base = items_columns_sql();
    let cases = [
        (
            format!("{base}, notes TEXT"),
            SchemaError::UndeclaredColumn {
                table: "items",
                column: "notes".to_owned(),
            },
        ),
        (
            base.replacen(", label TEXT NOT NULL", "", 1),
            SchemaError::FieldMissing {
                table: "items",
                field: "label",
            },
        ),
        (
            base.replacen("status TEXT NOT NULL", "status INTEGER NOT NULL", 1),
            SchemaError::ColumnMismatch {
                table: "items",
                column: "status",
                expected: "TEXT NOT NULL".to_owned(),
                found: "INTEGER NOT NULL".to_owned(),
            },
        ),
        (
            base.replacen("quantity INTEGER", "quantity INTEGER NOT NULL DEFAULT 0", 1),
            SchemaError::ColumnMismatch {
                table: "items",
                column: "quantity",
                expected: "INTEGER".to_owned(),
                found: "INTEGER NOT NULL".to_owned(),
            },
        ),
        (
            base.replacen("label TEXT NOT NULL", "label TEXT", 1),
            SchemaError::ColumnMismatch {
                table: "items",
                column: "label",
                expected: "TEXT NOT NULL".to_owned(),
                found: "TEXT".to_owned(),
            },
        ),
        (
            base.replacen(
                "quantity INTEGER",
                "quantity INTEGER GENERATED ALWAYS AS (length(label)) VIRTUAL",
                1,
            ),
            SchemaError::ColumnMismatch {
                table: "items",
                column: "quantity",
                expected: "INTEGER".to_owned(),
                found: "INTEGER GENERATED".to_owned(),
            },
        ),
    ];
    for (index, (columns, expected)) in cases.into_iter().enumerate() {
        let error = schema_error(verify(
            sample_with_items_sql(&columns),
            &format!("fields-{index}"),
        ));
        assert_eq!(error, expected, "{columns}");
    }
}

/// AC5: whatever the migrations leave besides the declaration (a table, a view, a trigger) fails
/// registration, and a declared table they do not create does too.
#[test]
fn undeclared_objects_and_missing_tables_fail_registration() {
    let undeclared = [
        ("CREATE TABLE extra (x INTEGER) STRICT;", "table", "extra"),
        (
            "CREATE VIEW labels AS SELECT label FROM items;",
            "view",
            "labels",
        ),
        (
            "CREATE TRIGGER items_copy AFTER INSERT ON items BEGIN SELECT 1; END;",
            "trigger",
            "items_copy",
        ),
    ];
    for (index, (sql, kind, name)) in undeclared.into_iter().enumerate() {
        let mut module = sample();
        let mut migrations = module.migrations.to_vec();
        migrations.push(Migration { sql });
        module.migrations = leak(migrations);
        let error = schema_error(verify(module, &format!("undeclared-{index}")));
        assert_eq!(
            error,
            SchemaError::UndeclaredObject {
                kind: kind.to_owned(),
                name: name.to_owned()
            },
            "{sql}"
        );
    }

    let mut module = sample();
    module.migrations = leak(module.migrations[..1].to_vec());
    module.tables = leak(
        module
            .tables
            .iter()
            .map(|table| Table {
                fields: if table.name == "items" {
                    ITEM_FIELDS
                } else {
                    table.fields
                },
                ..*table
            })
            .collect(),
    );
    let error = schema_error(verify(module, "missing-table"));
    assert_eq!(error, SchemaError::MissingTable { table: "notes" });
}

/// The file migrated for `sample`, closed, at the sample's latest version.
fn migrated_sample(label: &str) -> ModuleFile {
    let dir = scratch_dir(label);
    registry_of(vec![sample()])
        .verify_migrations(&dir, &KEY)
        .expect("conforming");
    ModuleFile::new(dir, ModuleName::from_static("sample"), Partition::Household)
}

/// AC5 at open: the Core checks every file it opens, on a read or a write handle, and refuses
/// one whose schema differs from the declaration with a typed error.
#[test]
fn the_core_checks_each_file_it_opens() {
    let file = migrated_sample("open");
    let registry = registry_of(vec![sample()]);
    registry
        .open::<Read>(&file, &KEY)
        .expect("read")
        .close()
        .expect("close");
    registry
        .open::<Write>(&file, &KEY)
        .expect("write")
        .close()
        .expect("close");

    let mut extra_field = sample();
    let mut tables = extra_field.tables.to_vec();
    let mut fields = tables[1].fields.to_vec();
    fields.push(Field {
        name: "mood",
        kind: FieldKind::Structured(Structured::Enumeration(&["calm"])),
        optional: true,
    });
    tables[1].fields = leak(fields);
    extra_field.tables = leak(tables);
    let outcome = registry_of(vec![extra_field]).open::<Read>(&file, &KEY);
    assert!(
        matches!(
            outcome,
            Err(FileError::Schema(SchemaError::FieldMissing {
                table: "notes",
                field: "mood"
            }))
        ),
        "{outcome:?}"
    );

    let mut fewer_fields = sample();
    let mut tables = fewer_fields.tables.to_vec();
    tables[0].fields = ITEM_FIELDS;
    fewer_fields.tables = leak(tables);
    let outcome = registry_of(vec![fewer_fields]).open::<Write>(&file, &KEY);
    assert!(
        matches!(
            &outcome,
            Err(FileError::Schema(SchemaError::UndeclaredColumn { table: "items", column }))
                if column == "aisle"
        ),
        "{outcome:?}"
    );
}

#[test]
fn a_file_of_another_version_or_module_is_refused_at_open() {
    let file = migrated_sample("versions");

    let mut ahead = sample();
    let mut migrations = ahead.migrations.to_vec();
    migrations.push(Migration {
        sql: "CREATE INDEX notes_body ON notes (body);",
    });
    ahead.migrations = leak(migrations);
    let outcome = registry_of(vec![ahead]).open::<Read>(&file, &KEY);
    assert!(
        matches!(
            outcome,
            Err(FileError::MigrationPending {
                found: 2,
                latest: 3
            })
        ),
        "{outcome:?}"
    );

    let mut behind = sample();
    behind.migrations = leak(behind.migrations[..1].to_vec());
    let outcome = registry_of(vec![behind]).open::<Read>(&file, &KEY);
    assert!(
        matches!(
            outcome,
            Err(FileError::NewerThanCode {
                found: 2,
                latest: 1
            })
        ),
        "{outcome:?}"
    );

    let outcome = registry_of(vec![LITERAL]).open::<Read>(&file, &KEY);
    assert!(
        matches!(&outcome, Err(FileError::UnregisteredModule(name)) if name.as_str() == "sample"),
        "{outcome:?}"
    );
}

/// Story 3.6, AC1: a file whose Core track is not at the Core's version is refused at open, older
/// as pending, newer as newer than the code, before its module track is looked at.
#[test]
fn a_file_whose_core_track_differs_from_the_core_is_refused_at_open() {
    let latest = vilicus_storage::CORE_SCHEMA_VERSION;
    for (found, pending) in [(latest - 1, true), (latest + 1, false)] {
        let file = migrated_sample("core-version");
        raw_connection(&file)
            .execute_batch(&format!(
                "UPDATE _meta SET value = {found} WHERE key = 'core_schema_version'"
            ))
            .expect("plant another Core version");
        let outcome = registry_of(vec![sample()]).open::<Read>(&file, &KEY);
        let refused = match outcome {
            Err(FileError::CoreMigrationPending {
                found: in_file,
                latest: expected,
            }) => pending && in_file == found && expected == latest,
            Err(FileError::CoreNewerThanCode {
                found: in_file,
                latest: expected,
            }) => !pending && in_file == found && expected == latest,
            _ => false,
        };
        assert!(refused, "Core version {found}: {outcome:?}");
    }
}

/// Story 3.6, AC1: a new module file holds every Core table, and the registry, which holds a
/// file to exactly its declaration, accepts them and their indexes.
#[test]
fn a_new_file_holds_every_core_table_and_registers() {
    let file = migrated_sample("core-tables");
    let handle = registry_of(vec![sample()])
        .open::<Read>(&file, &KEY)
        .expect("a migrated file registers");
    let names: Vec<String> = handle
        .schema()
        .expect("schema")
        .tables
        .into_iter()
        .map(|table| table.name)
        .collect();
    for core in vilicus_storage::CORE_TABLES {
        assert!(names.iter().any(|name| name == core), "{core} in {names:?}");
    }
    assert_eq!(
        handle
            .schema_version(vilicus_storage::MigrationTrack::Core)
            .expect("version"),
        vilicus_storage::CORE_SCHEMA_VERSION
    );
}

/// M1 of the Story 3.2 review: clauses that write, delete, replace or convert rows on their own,
/// and indexes or keys beyond a plain index, fail registration even though the column types,
/// nullability and keys read back as declared. Each one, as a migration wrote it, passed the
/// first comparison and acted on a write handle.
#[test]
fn clauses_with_behaviour_fail_registration() {
    let base = items_columns_sql();
    let definition = |found: &str| -> SchemaError {
        SchemaError::Definition {
            table: "items".to_owned(),
            expected: String::new(),
            found: found.to_owned(),
        }
    };
    let cases: Vec<(String, &str, SchemaError)> = vec![
        (
            base.replacen(
                "list_id BLOB",
                "list_id BLOB REFERENCES notes (id) ON DELETE CASCADE",
                1,
            ),
            "",
            SchemaError::ForeignKey {
                table: "items",
                references: "notes".to_owned(),
            },
        ),
        (
            base.replacen(
                "label TEXT NOT NULL",
                "label TEXT NOT NULL REFERENCES _meta (key) ON UPDATE CASCADE",
                1,
            ),
            "",
            SchemaError::ForeignKey {
                table: "items",
                references: "_meta".to_owned(),
            },
        ),
        (
            base.replacen(
                "label TEXT NOT NULL",
                "label TEXT NOT NULL UNIQUE ON CONFLICT REPLACE",
                1,
            ),
            "",
            SchemaError::IndexNotAllowed {
                table: "items",
                index: "sqlite_autoindex_items_2".to_owned(),
                reason: "an index made by a UNIQUE constraint",
            },
        ),
        (
            base.replacen(
                "id BLOB NOT NULL PRIMARY KEY",
                "id BLOB NOT NULL PRIMARY KEY ON CONFLICT REPLACE",
                1,
            ),
            "",
            definition(""),
        ),
        (
            base.replacen(
                "taint TEXT NOT NULL",
                "taint TEXT NOT NULL ON CONFLICT REPLACE DEFAULT 'clean'",
                1,
            ),
            "",
            definition(""),
        ),
        (
            base.replacen(
                "taint TEXT NOT NULL",
                "taint TEXT NOT NULL COLLATE NOCASE",
                1,
            ),
            "",
            definition(""),
        ),
        (
            base.replacen(
                "rev INTEGER NOT NULL",
                "rev INTEGER NOT NULL CHECK (rev > 0)",
                1,
            ),
            "",
            definition(""),
        ),
        (
            base.replacen(
                "source TEXT NOT NULL",
                "source TEXT NOT NULL DEFAULT 'system'",
                1,
            ),
            "",
            definition(""),
        ),
        (base.clone(), " WITHOUT ROWID", definition("")),
        (
            base.replacen(
                "source TEXT NOT NULL, taint TEXT NOT NULL",
                "taint TEXT NOT NULL, source TEXT NOT NULL",
                1,
            ),
            "",
            definition(""),
        ),
        (
            base.replacen(
                "taint TEXT NOT NULL, text_taint TEXT NOT NULL",
                "text_taint TEXT NOT NULL, taint TEXT NOT NULL",
                1,
            ),
            "",
            definition(""),
        ),
        (
            base.replacen(
                "text_taint TEXT NOT NULL",
                "text_taint TEXT NOT NULL DEFAULT 'trusted'",
                1,
            ),
            "",
            definition(""),
        ),
    ];
    for (index, (columns, suffix, expected)) in cases.into_iter().enumerate() {
        let error = schema_error(verify(
            sample_with_items_definition(&columns, suffix),
            &format!("behaviour-{index}"),
        ));
        match (&error, &expected) {
            (SchemaError::Definition { table, found, .. }, SchemaError::Definition { .. }) => {
                assert_eq!(table, "items", "{columns}{suffix}");
                assert!(
                    found.contains(&columns) && found.ends_with(suffix),
                    "{found}"
                );
            }
            _ => assert_eq!(error, expected, "{columns}{suffix}"),
        }
    }
}

/// M1 of the review, indexes: a plain index over declared columns passes; a `UNIQUE`, partial,
/// expression or non-`BINARY` index does not.
#[test]
fn only_plain_indexes_pass_registration() {
    let refused = [
        (
            "CREATE UNIQUE INDEX items_x ON items (lower(source)) WHERE taint = 'trusted';",
            "a partial index",
        ),
        (
            "CREATE UNIQUE INDEX items_x ON items (label);",
            "a UNIQUE index",
        ),
        (
            "CREATE INDEX items_x ON items (lower(label));",
            "an index on an expression or the rowid",
        ),
        (
            "CREATE INDEX items_x ON items (label COLLATE NOCASE);",
            "a collation other than BINARY",
        ),
        (
            "CREATE INDEX items_x ON items (label) WHERE quantity > 0;",
            "a partial index",
        ),
    ];
    for (index, (sql, reason)) in refused.into_iter().enumerate() {
        let mut module = sample();
        let mut migrations = module.migrations.to_vec();
        migrations.push(Migration { sql });
        module.migrations = leak(migrations);
        let error = schema_error(verify(module, &format!("index-{index}")));
        assert_eq!(
            error,
            SchemaError::IndexNotAllowed {
                table: "items",
                index: "items_x".to_owned(),
                reason
            },
            "{sql}"
        );
    }
    let mut module = sample();
    let mut migrations = module.migrations.to_vec();
    migrations.push(Migration {
        sql: "CREATE INDEX items_x ON items (label DESC, list_id COLLATE BINARY);",
    });
    module.migrations = leak(migrations);
    verify(module, "index-plain").expect("a plain index is allowed");
}

/// SQLite compares names ignoring ASCII case, and comments carry no behaviour: neither makes a
/// conforming statement differ.
#[test]
fn case_and_comments_do_not_make_a_difference() {
    let columns = items_columns_sql().replacen(
        "id BLOB NOT NULL PRIMARY KEY",
        "\"ID\" blob /* the record id */ not null PRIMARY key -- stamped by the Core\n",
        1,
    );
    let mut module = sample();
    let mut migrations = module.migrations.to_vec();
    migrations[0] = Migration {
        sql: leak_str(format!("CREATE TABLE ITEMS ({columns});")),
    };
    module.migrations = leak(migrations);
    verify(module, "case-and-comments").expect("the same statement");
}

/// `items` created by `columns` and `suffix`, otherwise as `sample`.
fn sample_with_items_definition(columns: &str, suffix: &str) -> ModuleDeclaration {
    let mut module = sample();
    let mut migrations = module.migrations.to_vec();
    migrations[0] = Migration {
        sql: leak_str(format!("CREATE TABLE items ({columns}){suffix};")),
    };
    module.migrations = leak(migrations);
    module
}

const NOTES_SEARCH: Fts5Table = Fts5Table {
    name: "notes_search",
    columns: &["body"],
    tokenizer: Fts5Tokenizer::Porter,
    content: Fts5Content::Table("notes"),
};

const NOTES_SEARCH_SQL: &str =
    "CREATE VIRTUAL TABLE notes_search USING fts5(body, content='notes', tokenize='porter');";

const SECURE_DELETE_SQL: &str =
    "INSERT INTO notes_search (notes_search, rank) VALUES ('secure-delete', 1);";

fn sample_declaring(fts5: Fts5Table) -> ModuleDeclaration {
    let mut module = sample();
    module.fts5_tables = leak(vec![fts5]);
    module
}

/// A connection to `file` keyed and nothing else: no setup, no authorizer. Test code only.
fn raw_connection(file: &ModuleFile) -> rusqlite::Connection {
    let connection =
        rusqlite::Connection::open(file.path()).expect("open without the storage layer");
    let hex: String = KEY.iter().map(|byte| format!("{byte:02x}")).collect();
    connection
        .execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))
        .expect("key");
    connection
}

/// The migrated `sample` file, to which `sql` adds FTS5 objects without the authorizer: real
/// FTS5 tables, made by SQLite's FTS5 as Story 3.7's migrations will make them. No migration can
/// before that story, which allows `CREATE VIRTUAL TABLE ... USING fts5` (D127).
fn fts5_file(label: &str, sql: &str) -> ModuleFile {
    let file = migrated_sample(label);
    let connection = raw_connection(&file);
    connection
        .execute_batch(sql)
        .expect("create the FTS5 objects");
    connection.close().expect("close");
    file
}

fn open_with(declaration: ModuleDeclaration, file: &ModuleFile) -> Result<(), FileError> {
    registry_of(vec![declaration])
        .open::<Read>(file, &KEY)
        .map(|handle| handle.close().expect("close"))
}

/// AC7 (D127, D132) on real FTS5 tables: the declared arguments within the allowlist, the shadow
/// tables FTS5 writes, as FTS5 writes them, and `secure-delete` at 1.
#[test]
fn real_fts5_tables_with_their_declared_arguments_pass() {
    let accepted = [
        (
            NOTES_SEARCH,
            format!("{NOTES_SEARCH_SQL}{SECURE_DELETE_SQL}"),
        ),
        (
            Fts5Table {
                tokenizer: Fts5Tokenizer::Unicode61,
                content: Fts5Content::Contentless,
                ..NOTES_SEARCH
            },
            format!(
                "CREATE VIRTUAL TABLE notes_search USING fts5(body, content=''); {SECURE_DELETE_SQL}"
            ),
        ),
        (
            Fts5Table {
                tokenizer: Fts5Tokenizer::Trigram,
                ..NOTES_SEARCH
            },
            format!(
                "CREATE VIRTUAL TABLE notes_search USING FTS5(body, tokenize = \"trigram\", content = notes); {SECURE_DELETE_SQL}"
            ),
        ),
    ];
    for (index, (fts5, sql)) in accepted.into_iter().enumerate() {
        let file = fts5_file(&format!("fts5-real-{index}"), &sql);
        open_with(sample_declaring(fts5), &file).unwrap_or_else(|error| panic!("{sql}: {error}"));
    }
}

#[test]
fn a_real_fts5_table_without_secure_delete_is_refused() {
    for (index, extra) in [
        "",
        "INSERT INTO notes_search (notes_search, rank) VALUES ('secure-delete', 0);",
    ]
    .into_iter()
    .enumerate()
    {
        let file = fts5_file(
            &format!("fts5-secure-delete-{index}"),
            &format!("{NOTES_SEARCH_SQL}{extra}"),
        );
        let outcome = open_with(sample_declaring(NOTES_SEARCH), &file);
        assert!(
            matches!(
                outcome,
                Err(FileError::Schema(SchemaError::Fts5SecureDeleteOff {
                    table: "notes_search"
                }))
            ),
            "{outcome:?}"
        );
    }
}

/// M2 of the review: SQLite marks a table as an FTS5 shadow table by its name alone, so a
/// `_content` table beside a contentless FTS5 table read as a shadow table and passed, holding
/// rows without an envelope. The shadow tables are exactly the ones FTS5 makes in the declared
/// mode, each created by FTS5's own statement.
#[test]
fn shadow_tables_are_exactly_the_ones_fts5_makes() {
    let contentless = Fts5Table {
        tokenizer: Fts5Tokenizer::Unicode61,
        content: Fts5Content::Contentless,
        ..NOTES_SEARCH
    };
    let contentless_sql = format!(
        "CREATE VIRTUAL TABLE notes_search USING fts5(body, content=''); {SECURE_DELETE_SQL}"
    );

    let file = fts5_file(
        "fts5-fake-content",
        &format!(
            "CREATE TABLE notes_search_content (secret TEXT, anything BLOB);
             INSERT INTO notes_search_content VALUES ('no envelope, no taint', x'00');
             {contentless_sql}"
        ),
    );
    let outcome = open_with(sample_declaring(contentless), &file);
    assert!(
        matches!(
            &outcome,
            Err(FileError::Schema(SchemaError::UndeclaredObject { kind, name }))
                if kind == "shadow table" && name == "notes_search_content"
        ),
        "{outcome:?}"
    );

    let file = fts5_file(
        "fts5-rebuilt-docsize",
        &format!(
            "{contentless_sql}
             DROP TABLE notes_search_docsize;
             CREATE TABLE notes_search_docsize (id INTEGER PRIMARY KEY, sz BLOB, secret TEXT);"
        ),
    );
    let outcome = open_with(sample_declaring(contentless), &file);
    assert!(
        matches!(
            &outcome,
            Err(FileError::Schema(SchemaError::Definition { table, .. })) if table == "notes_search_docsize"
        ),
        "{outcome:?}"
    );

    let file = fts5_file(
        "fts5-dropped-docsize",
        &format!("{contentless_sql} DROP TABLE notes_search_docsize;"),
    );
    let outcome = open_with(sample_declaring(contentless), &file);
    assert!(
        matches!(
            &outcome,
            Err(FileError::Schema(SchemaError::Fts5ShadowMissing { table: "notes_search", shadow }))
                if shadow == "notes_search_docsize"
        ),
        "{outcome:?}"
    );
}

/// The arguments of a real FTS5 table, its text in `sqlite_master` replaced by each refused form;
/// most of them FTS5 itself would accept.
#[test]
fn fts5_arguments_outside_the_declaration_or_the_allowlist_are_refused() {
    let file = fts5_file(
        "fts5-arguments",
        &format!("{NOTES_SEARCH_SQL}{SECURE_DELETE_SQL}"),
    );
    let module = sample_declaring(NOTES_SEARCH);
    let reader = vilicus_storage::open::<Read>(&file, &KEY).expect("open");
    let snapshot = Snapshot::read(&reader, &module).expect("snapshot");
    reader.close().expect("close");
    assert_eq!(schema::compare(&module, &snapshot), Ok(()));

    let arguments = |reason: &str| SchemaError::Fts5Arguments {
        table: "notes_search",
        reason: reason.to_owned(),
    };
    let refused = [
        (
            "CREATE VIRTUAL TABLE notes_search USING fts5(body, content='notes', tokenize='porter unicode61')",
            arguments("tokenizer \"porter unicode61\", declared porter"),
        ),
        (
            "CREATE VIRTUAL TABLE notes_search USING fts5(body, content='notes', tokenize='attacker')",
            arguments("tokenizer \"attacker\", declared porter"),
        ),
        (
            "CREATE VIRTUAL TABLE notes_search USING fts5(body, content='notes')",
            arguments("tokenizer \"\", declared porter"),
        ),
        (
            "CREATE VIRTUAL TABLE notes_search USING fts5(body, content='_journal', tokenize='porter')",
            arguments("content Some(\"_journal\"), declared \"notes\""),
        ),
        (
            "CREATE VIRTUAL TABLE notes_search USING fts5(body, tokenize='porter')",
            arguments("content None, declared \"notes\""),
        ),
        (
            "CREATE VIRTUAL TABLE notes_search USING fts5(body, content='notes', content='notes', tokenize='porter')",
            arguments("option content is given twice"),
        ),
        (
            "CREATE VIRTUAL TABLE notes_search USING fts5(body, content='notes', tokenize='porter', prefix='2')",
            arguments("option prefix is not allowed"),
        ),
        (
            "CREATE VIRTUAL TABLE notes_search USING fts5(body, content='notes', tokenize='porter', content_rowid='rev')",
            arguments("option content_rowid is not allowed"),
        ),
        (
            "CREATE VIRTUAL TABLE notes_search USING fts5(body UNINDEXED, content='notes', tokenize='porter')",
            arguments("columns [\"body UNINDEXED\"], declared [\"body\"]"),
        ),
        (
            "CREATE VIRTUAL TABLE notes_search USING fts5(body, label, content='notes', tokenize='porter')",
            arguments("columns [\"body\", \"label\"], declared [\"body\"]"),
        ),
        (
            "CREATE VIRTUAL TABLE notes_search USING fts5(body, content='notes' tokenize='porter')",
            arguments("unreadable arguments (Argument)"),
        ),
        (
            "CREATE VIRTUAL TABLE notes_search USING fts4(body, content='notes', tokenize='porter')",
            SchemaError::NotFts5 {
                table: "notes_search",
            },
        ),
    ];
    for (sql, expected) in refused {
        let mut altered = snapshot.clone();
        altered
            .schema
            .objects
            .iter_mut()
            .filter(|object| object.name == "notes_search")
            .for_each(|object| object.sql = Some(sql.to_owned()));
        assert_eq!(schema::compare(&module, &altered), Err(expected), "{sql}");
    }
}

#[test]
fn fts5_tables_absent_undeclared_or_of_another_kind_are_refused() {
    let file = migrated_sample("fts5-absent");
    let outcome = open_with(sample_declaring(NOTES_SEARCH), &file);
    assert!(
        matches!(
            outcome,
            Err(FileError::Schema(SchemaError::MissingTable {
                table: "notes_search"
            }))
        ),
        "{outcome:?}"
    );

    let file = fts5_file("fts5-ordinary", "CREATE TABLE notes_search (body TEXT);");
    let outcome = open_with(sample_declaring(NOTES_SEARCH), &file);
    assert!(
        matches!(
            outcome,
            Err(FileError::Schema(SchemaError::NotFts5 {
                table: "notes_search"
            }))
        ),
        "{outcome:?}"
    );

    let file = fts5_file(
        "fts5-undeclared",
        &format!(
            "{NOTES_SEARCH_SQL}{SECURE_DELETE_SQL}
             CREATE VIRTUAL TABLE hidden_search USING fts5(body, content='');"
        ),
    );
    let outcome = open_with(sample_declaring(NOTES_SEARCH), &file);
    assert!(
        matches!(
            &outcome,
            Err(FileError::Schema(SchemaError::UndeclaredObject { kind, name }))
                if kind == "virtual table" && name == "hidden_search"
        ),
        "{outcome:?}"
    );
}
