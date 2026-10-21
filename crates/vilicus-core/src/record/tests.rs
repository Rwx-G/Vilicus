//! Story 3.4: a value outside its closed type refuses the whole write (AC1), a value longer than
//! its maximum is refused, never truncated (AC2), only confirmed labels of the restricted
//! alphabet are accepted (AC3), the write path fuzz test (AC4), and label confirmation, which no
//! surface reaches (AC5).

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use vilicus_module_api::{
    DataType, ENVELOPE, Field, FieldKind, Migration, ModuleDeclaration, SqlType, Structured, Table,
    VOCABULARY_LABEL_MAX_LEN, Value, ValueError,
};
use vilicus_storage::{Handle, MigrationTrack, ModuleFile, SqlValue, TableKind, Write};
use vilicus_types::{Id, Source, Taint, UtcMillis};

use super::envelope::{EnvelopeRule, data_types_text, rule};
use super::{RecordError, WriteKind, WritePath, check_stored_rows, confirm_label, insert, update};
use crate::registry::{Registry, create_migrated};

/// Test key only; the Core derives one key per file.
const KEY: [u8; 32] = [0x4d; 32];

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vilicus-core-record-{}-{}-{label}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("create scratch directory");
    dir
}

const ITEM_FIELDS: &[Field] = &[
    Field {
        name: "label",
        kind: FieldKind::FreeText { max_len: 12 },
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
    Field {
        name: "room",
        kind: FieldKind::Structured(Structured::ReviewedVocabulary("rooms")),
        optional: true,
    },
];

const PLACE_FIELDS: &[Field] = &[
    Field {
        name: "name",
        kind: FieldKind::FreeText { max_len: 40 },
        optional: false,
    },
    Field {
        name: "room",
        kind: FieldKind::Structured(Structured::ReviewedVocabulary("rooms")),
        optional: false,
    },
    Field {
        name: "side",
        kind: FieldKind::Structured(Structured::ReviewedVocabulary("sides")),
        optional: true,
    },
];

/// The `CREATE TABLE` statement a declaration implies, without `STRICT`: field validation is the
/// only guard on these tables, as on a table a later migration adds a column to.
fn create_sql(table: &Table) -> String {
    let columns: Vec<String> = ENVELOPE
        .iter()
        .map(|column| {
            (
                column.name,
                column.sql_type,
                column.not_null,
                column.primary_key,
            )
        })
        .chain(
            table
                .fields
                .iter()
                .map(|field| (field.name, field.kind.sql_type(), !field.optional, false)),
        )
        .map(|(name, sql_type, not_null, primary_key)| {
            let mut sql = format!("{name} {}", sql_type.as_str());
            if not_null {
                sql.push_str(" NOT NULL");
            }
            if primary_key {
                sql.push_str(" PRIMARY KEY");
            }
            sql
        })
        .collect();
    format!("CREATE TABLE {} ({});", table.name, columns.join(", "))
}

/// A module of `tables`, created by its first migration; `back_fill`, when given, is a second
/// migration.
fn module(
    name: &'static str,
    tables: Vec<Table>,
    back_fill: Option<String>,
) -> &'static ModuleDeclaration {
    let create: String = tables.iter().map(create_sql).collect::<Vec<_>>().join(
        "
",
    );
    let mut migrations = vec![Migration { sql: create.leak() }];
    if let Some(sql) = back_fill {
        migrations.push(Migration { sql: sql.leak() });
    }
    Box::leak(Box::new(ModuleDeclaration {
        name,
        tables: tables.leak(),
        fts5_tables: &[],
        migrations: migrations.leak(),
        matrix_sections: &[],
        tools: &[],
    }))
}

fn probe() -> &'static ModuleDeclaration {
    module(
        "probe",
        vec![
            Table {
                name: "items",
                data_types: &[DataType::ShoppingList],
                fields: ITEM_FIELDS,
            },
            Table {
                name: "places",
                data_types: &[DataType::HouseholdOther],
                fields: PLACE_FIELDS,
            },
        ],
        None,
    )
}

fn registry_of(modules: Vec<&'static ModuleDeclaration>) -> Registry {
    Registry::new(modules.leak()).expect("a valid registry")
}

/// A new migrated file of `module` and its write handle.
fn open_new(module: &'static ModuleDeclaration, label: &str) -> (ModuleFile, Handle<Write>) {
    let file = create_migrated(module, &scratch_dir(label), &KEY).expect("create and migrate");
    let handle = registry_of(vec![module])
        .open::<Write>(&file, &KEY)
        .expect("open");
    (file, handle)
}

fn adult() -> Id {
    "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
        .parse()
        .expect("test id")
}

fn noon() -> UtcMillis {
    UtcMillis::parse_rfc3339("2026-10-21T12:00:00Z").expect("valid")
}

fn uuid(last: u8) -> Id {
    let mut random = [0x5a; 10];
    random[9] = last;
    Id::new_v7(noon(), random).expect("after the epoch")
}

/// A valid envelope of a new record of a table declaring `data_types`, in the stored forms the
/// row writer checks.
fn envelope_of(data_types: &[DataType], id: Id) -> Vec<(&'static str, Value)> {
    ENVELOPE
        .iter()
        .map(|column| {
            let value = match rule(column.name).expect("every envelope column has a rule") {
                EnvelopeRule::Id => Value::Blob(id.to_bytes().to_vec()),
                EnvelopeRule::Source => Value::Text(Source::System.to_string()),
                EnvelopeRule::Taint => Value::Text(Taint::External.as_str().into()),
                EnvelopeRule::DataTypes => Value::Text(data_types_text(data_types)),
                EnvelopeRule::Author => Value::Null,
                EnvelopeRule::Instant => Value::Integer(noon().as_millis()),
                EnvelopeRule::Rev => Value::Integer(1),
            };
            (column.name, value)
        })
        .collect()
}

/// A valid envelope of a new `items` record.
fn envelope(id: Id) -> Vec<(&'static str, Value)> {
    envelope_of(&[DataType::ShoppingList], id)
}

fn with_envelope(
    mut envelope: Vec<(&'static str, Value)>,
    name: &str,
    value: Value,
) -> Vec<(&'static str, Value)> {
    let slot = envelope
        .iter_mut()
        .find(|(column, _)| *column == name)
        .expect("an envelope column");
    slot.1 = value;
    envelope
}

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

/// An `items` record within its declaration, every field given.
fn item() -> Vec<(&'static str, Value)> {
    vec![
        ("label", text("Pommes")),
        ("status", text("open")),
        ("quantity", Value::Integer(3)),
        ("due_on", text("2026-10-30")),
        ("reminded_at", Value::Integer(noon().as_millis())),
        ("list_id", Value::Blob(uuid(1).to_bytes().to_vec())),
        ("room", text("Cuisine")),
    ]
}

fn with(
    mut fields: Vec<(&'static str, Value)>,
    name: &str,
    value: Value,
) -> Vec<(&'static str, Value)> {
    let slot = fields
        .iter_mut()
        .find(|(field, _)| *field == name)
        .expect("a field of the record");
    slot.1 = value;
    fields
}

/// Every row of every table of the file, the Core's and SQLite's own included.
fn content(handle: &Handle<Write>) -> Vec<Vec<Vec<SqlValue>>> {
    handle
        .schema()
        .expect("schema")
        .tables
        .iter()
        .filter(|table| matches!(table.kind, TableKind::Ordinary | TableKind::Shadow))
        .map(|table| {
            handle
                .query_values(&format!("SELECT * FROM \"{}\"", table.name), &[])
                .expect("read a table")
        })
        .collect()
}

fn rows(handle: &Handle<Write>, sql: &str) -> Vec<Vec<SqlValue>> {
    handle.query_values(sql, &[]).expect("read rows")
}

/// The refusal of `fields` inserted into `table`, with every table of the file unchanged.
fn refused_insert(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    table: &str,
    id: Id,
    fields: &[(&'static str, Value)],
) -> RecordError {
    let before = content(handle);
    let data_types = module
        .table(table)
        .map_or(&[][..], |table| table.data_types);
    let error = insert(handle, module, table, &envelope_of(data_types, id), fields)
        .expect_err("a write outside its declaration is refused");
    assert_eq!(
        content(handle),
        before,
        "the refused write left the file unchanged"
    );
    error
}

fn invalid(error: &RecordError) -> Option<(&'static str, &'static str, ValueError)> {
    match error {
        RecordError::Invalid {
            table,
            column,
            error,
        } => Some((table, column, *error)),
        _ => None,
    }
}

fn confirm(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    vocabulary: &str,
    label: &str,
) {
    confirm_label(handle, module, vocabulary, label, adult(), noon()).expect("confirm a label");
}

/// The happy path: every kind within its declaration is stored as given, byte for byte.
#[test]
fn a_write_within_its_declaration_is_stored_as_given() {
    let probe = probe();
    let (_, handle) = open_new(probe, "stored");
    confirm(&handle, probe, "rooms", "Cuisine");
    let record = with(item(), "label", text("été\t\"x';--\n"));
    insert(&handle, probe, "items", &envelope(uuid(2)), &record).expect("accepted");
    let stored = rows(
        &handle,
        "SELECT label, status, quantity, due_on, reminded_at, list_id, room FROM items",
    );
    let expected: Vec<SqlValue> = record
        .iter()
        .map(|(_, value)| match value {
            Value::Integer(number) => SqlValue::Integer(*number),
            Value::Text(text) => SqlValue::Text(text.clone()),
            Value::Blob(bytes) => SqlValue::Blob(bytes.clone()),
            other => panic!("not in the record: {other:?}"),
        })
        .collect();
    assert_eq!(stored, [expected]);
    let required_only = vec![("label", text("Poires")), ("status", text("done"))];
    insert(&handle, probe, "items", &envelope(uuid(3)), &required_only)
        .expect("optional fields left out are stored NULL");
    let optional = rows(
        &handle,
        "SELECT quantity, room FROM items WHERE label = 'Poires'",
    );
    assert_eq!(optional, [vec![SqlValue::Null, SqlValue::Null]]);
}

/// AC1 (FR-58, DC-53, D98, I40): an unknown enumeration value, a number out of bounds, an invalid
/// date and a malformed UUIDv7 each refuse the whole write with a typed error, and nothing is
/// stored; a value of another storage class is refused, never converted.
#[test]
fn a_value_outside_its_closed_type_refuses_the_whole_write() {
    let probe = probe();
    let (_, handle) = open_new(probe, "closed-type");
    confirm(&handle, probe, "rooms", "Cuisine");
    let mut v4 = uuid(4).to_bytes();
    v4[6] = (v4[6] & 0x0f) | 0x40;
    let cases = [
        ("status", text("archived"), ValueError::NotInEnumeration),
        ("status", text("Open"), ValueError::NotInEnumeration),
        ("quantity", Value::Integer(1000), ValueError::OutOfRange),
        ("quantity", Value::Integer(-1), ValueError::OutOfRange),
        ("due_on", text("2026-02-30"), ValueError::InvalidDate),
        ("due_on", text("30/10/2026"), ValueError::InvalidDate),
        (
            "reminded_at",
            Value::Integer(UtcMillis::MAX.as_millis() + 1),
            ValueError::OutOfRange,
        ),
        ("list_id", Value::Blob(v4.to_vec()), ValueError::InvalidUuid),
        ("list_id", Value::Blob(vec![1; 15]), ValueError::InvalidUuid),
        (
            "quantity",
            text("12"),
            ValueError::StorageClass {
                expected: SqlType::Integer,
            },
        ),
        (
            "quantity",
            Value::Real(12.0),
            ValueError::StorageClass {
                expected: SqlType::Integer,
            },
        ),
        (
            "list_id",
            text(&uuid(5).to_string()),
            ValueError::StorageClass {
                expected: SqlType::Blob,
            },
        ),
        (
            "status",
            Value::Blob(b"open".to_vec()),
            ValueError::StorageClass {
                expected: SqlType::Text,
            },
        ),
        ("status", Value::Null, ValueError::Null),
    ];
    for (index, (field, value, rule)) in cases.into_iter().enumerate() {
        let error = refused_insert(
            &handle,
            probe,
            "items",
            uuid(10),
            &with(item(), field, value),
        );
        assert_eq!(
            invalid(&error),
            Some(("items", field, rule)),
            "case {index}: {error}"
        );
    }
    assert!(rows(&handle, "SELECT id FROM items").is_empty());
}

/// AC2 (FR-58, I40): a value longer than its maximum is refused, structured or free text, and
/// never truncated: no prefix of it is stored.
#[test]
fn a_value_longer_than_its_maximum_is_refused_never_truncated() {
    let probe = probe();
    let (_, handle) = open_new(probe, "length");
    let longest = "Œ".repeat(VOCABULARY_LABEL_MAX_LEN);
    confirm(&handle, probe, "rooms", &longest);
    for (field, value, max_len) in [
        ("label", text("abcdefghijklm"), 12),
        ("label", text(&"é".repeat(13)), 12),
        (
            "room",
            text(&format!("{longest}x")),
            VOCABULARY_LABEL_MAX_LEN,
        ),
    ] {
        let error = refused_insert(
            &handle,
            probe,
            "items",
            uuid(10),
            &with(item(), field, value),
        );
        assert_eq!(
            invalid(&error),
            Some(("items", field, ValueError::TooLong { max_len })),
            "{error}"
        );
    }
    assert!(
        rows(&handle, "SELECT id FROM items").is_empty(),
        "no truncated copy"
    );
    let at_most = with(
        with(item(), "label", text(&"é".repeat(12))),
        "room",
        text(&longest),
    );
    insert(&handle, probe, "items", &envelope(uuid(11)), &at_most).expect("at the maximum");
    assert_eq!(
        rows(&handle, "SELECT label, room FROM items"),
        [vec![
            SqlValue::Text("é".repeat(12)),
            SqlValue::Text(longest)
        ]]
    );
}

/// AC3 (DC-59, D104, I40): a label not among the confirmed labels of its vocabulary, longer than
/// 32 characters or outside the restricted alphabet is refused; a confirmed label of at most 32
/// characters from the alphabet is accepted.
#[test]
fn only_confirmed_labels_of_the_restricted_alphabet_are_accepted() {
    let probe = probe();
    let (_, handle) = open_new(probe, "labels");
    let longest = "Salle d'eau de l'étage du haut 2".to_owned();
    assert_eq!(longest.chars().count(), VOCABULARY_LABEL_MAX_LEN);
    for label in ["Cuisine", "Chambre d'Ella", longest.as_str()] {
        confirm(&handle, probe, "rooms", label);
    }
    for (index, label) in ["Cuisine", "Chambre d'Ella", longest.as_str()]
        .into_iter()
        .enumerate()
    {
        let id = uuid(20 + u8::try_from(index).expect("small"));
        insert(
            &handle,
            probe,
            "items",
            &envelope(id),
            &with(item(), "room", text(label)),
        )
        .expect("a confirmed label");
    }
    for label in ["Salon", "cuisine", "CUISINE", "Cuisin", "Chambre d'Elle"] {
        let error = refused_insert(
            &handle,
            probe,
            "items",
            uuid(30),
            &with(item(), "room", text(label)),
        );
        assert!(
            matches!(
                error,
                RecordError::UnconfirmedLabel {
                    table: "items",
                    column: "room",
                    vocabulary: "rooms"
                }
            ),
            "{label}: {error}"
        );
    }
    for label in [
        "Cuisine ",
        "Cuisine:",
        "Cui\u{200b}sine",
        "Cuisine\n",
        "Cuisine_1",
        "",
    ] {
        let error = refused_insert(
            &handle,
            probe,
            "items",
            uuid(30),
            &with(item(), "room", text(label)),
        );
        assert_eq!(
            invalid(&error),
            Some(("items", "room", ValueError::InvalidLabel)),
            "{label:?}: {error}"
        );
    }
    let error = refused_insert(
        &handle,
        probe,
        "items",
        uuid(30),
        &with(item(), "room", text(&format!("{longest}x"))),
    );
    assert_eq!(
        invalid(&error),
        Some((
            "items",
            "room",
            ValueError::TooLong {
                max_len: VOCABULARY_LABEL_MAX_LEN
            }
        ))
    );
    assert_eq!(rows(&handle, "SELECT id FROM items").len(), 3);
}

/// AC3: a label is confirmed in one vocabulary of one file; the same text in another vocabulary
/// of the module, or in another file of it (another partition), is not confirmed.
#[test]
fn a_label_is_confirmed_only_in_its_own_vocabulary_and_file() {
    let probe = probe();
    let (_, handle) = open_new(probe, "scope");
    confirm(&handle, probe, "sides", "Nord");
    let place = |room: &str, side: &str| {
        vec![
            ("name", text("Garage")),
            ("room", text(room)),
            ("side", text(side)),
        ]
    };
    let error = refused_insert(&handle, probe, "places", uuid(40), &place("Nord", "Nord"));
    assert!(
        matches!(
            error,
            RecordError::UnconfirmedLabel {
                column: "room",
                vocabulary: "rooms",
                ..
            }
        ),
        "{error}"
    );
    confirm(&handle, probe, "rooms", "Garage");
    insert(
        &handle,
        probe,
        "places",
        &envelope_of(&[DataType::HouseholdOther], uuid(41)),
        &place("Garage", "Nord"),
    )
    .expect("each label confirmed in its own vocabulary");

    let (_, other_file) = open_new(probe, "scope-other-file");
    let error = refused_insert(
        &other_file,
        probe,
        "places",
        uuid(42),
        &place("Garage", "Nord"),
    );
    assert!(
        matches!(error, RecordError::UnconfirmedLabel { column: "room", .. }),
        "{error}"
    );
}

/// AC3, AC5: confirming a label checks its form and that the module declares the vocabulary;
/// the Core alone records it (the `_vocabulary` refusals of module SQL are storage tests).
#[test]
fn label_confirmation_checks_the_label_and_the_vocabulary() {
    let probe = probe();
    let (_, handle) = open_new(probe, "confirm");
    let before = content(&handle);
    for (label, rule) in [
        ("Cuisine ", ValueError::InvalidLabel),
        ("cuisine\u{301}", ValueError::InvalidLabel),
        ("", ValueError::InvalidLabel),
        (
            "Une très longue étiquette de pièce",
            ValueError::TooLong {
                max_len: VOCABULARY_LABEL_MAX_LEN,
            },
        ),
    ] {
        let error = confirm_label(&handle, probe, "rooms", label, adult(), noon())
            .expect_err("a label outside the form is not confirmed");
        assert!(
            matches!(error, RecordError::InvalidLabel { vocabulary: "rooms", error } if error == rule),
            "{label:?}: {error}"
        );
    }
    let error = confirm_label(&handle, probe, "aisles", "Fruits", adult(), noon())
        .expect_err("a vocabulary the module does not declare");
    assert!(
        matches!(error, RecordError::UnknownVocabulary { module: "probe" }),
        "{error}"
    );
    assert_eq!(content(&handle), before, "nothing was confirmed");
    confirm(&handle, probe, "rooms", "Cuisine");
    assert!(handle.is_confirmed_label("rooms", "Cuisine").expect("read"));
}

/// The fields a write gives.
type Fields = Vec<(&'static str, Value)>;

/// A write and the refusal it must meet.
type Refusal = (Fields, fn(&RecordError) -> bool);

/// An update is held to the declaration like an insert, and the refused update leaves the record
/// as it was; a record's id never changes.
#[test]
fn an_update_is_held_to_the_declaration_too() {
    let probe = probe();
    let (_, handle) = open_new(probe, "update");
    confirm(&handle, probe, "rooms", "Cuisine");
    let id = uuid(50);
    insert(&handle, probe, "items", &envelope(id), &item()).expect("insert");
    let refusals: [Refusal; 7] = [
        (vec![("status", text("archived"))], |error| {
            invalid(error) == Some(("items", "status", ValueError::NotInEnumeration))
        }),
        (vec![("label", text("abcdefghijklm"))], |error| {
            invalid(error) == Some(("items", "label", ValueError::TooLong { max_len: 12 }))
        }),
        (vec![("label", Value::Null)], |error| {
            invalid(error) == Some(("items", "label", ValueError::Null))
        }),
        (vec![("room", text("Salon"))], |error| {
            matches!(error, RecordError::UnconfirmedLabel { column: "room", .. })
        }),
        (
            vec![
                ("quantity", Value::Integer(5)),
                ("quantity", Value::Integer(6)),
            ],
            |error| {
                matches!(
                    error,
                    RecordError::DuplicateColumn {
                        column: "quantity",
                        ..
                    }
                )
            },
        ),
        (vec![("unknown", Value::Integer(5))], |error| {
            matches!(error, RecordError::UnknownColumn { table: "items" })
        }),
        (Vec::new(), |error| {
            matches!(error, RecordError::EmptyUpdate { table: "items" })
        }),
    ];
    for (fields, expected) in refusals {
        let before = content(&handle);
        let error = update(&handle, probe, "items", id, &[], &fields).expect_err("refused");
        assert!(expected(&error), "{error}");
        assert_eq!(content(&handle), before);
    }
    let id_column = ENVELOPE
        .iter()
        .find(|column| column.primary_key)
        .expect("id");
    let error = update(
        &handle,
        probe,
        "items",
        id,
        &[(id_column.name, Value::Blob(uuid(51).to_bytes().to_vec()))],
        &[],
    )
    .expect_err("an id never changes");
    assert!(
        matches!(error, RecordError::IdChanged { table: "items" }),
        "{error}"
    );
    let error = update(
        &handle,
        probe,
        "items",
        uuid(52),
        &[],
        &[("quantity", Value::Integer(7))],
    )
    .expect_err("no such record");
    assert!(
        matches!(error, RecordError::RecordNotFound { table: "items" }),
        "{error}"
    );
    update(
        &handle,
        probe,
        "items",
        id,
        &[],
        &[("quantity", Value::Null), ("status", text("done"))],
    )
    .expect("a change within the declaration");
    assert_eq!(
        rows(&handle, "SELECT quantity, status FROM items"),
        [vec![SqlValue::Null, SqlValue::Text("done".into())]]
    );
}

/// A write names declared columns only, each once, every required field and every envelope
/// column on insert, each envelope column of its SQL type.
#[test]
fn a_write_names_declared_columns_once_and_every_required_one() {
    let probe = probe();
    let (_, handle) = open_new(probe, "columns");
    confirm(&handle, probe, "rooms", "Cuisine");
    let before = content(&handle);
    let attempt = |table: &str, envelope: &[(&str, Value)], fields: &[(&str, Value)]| {
        insert(&handle, probe, table, envelope, fields).expect_err("refused")
    };
    let full = envelope(uuid(60));
    let error = attempt("missing_table", &full, &item());
    assert!(
        matches!(error, RecordError::UnknownTable { module: "probe" }),
        "{error}"
    );
    let mut fields = item();
    fields.retain(|(name, _)| *name != "status");
    let error = attempt("items", &full, &fields);
    assert!(
        matches!(
            error,
            RecordError::MissingColumn {
                column: "status",
                ..
            }
        ),
        "{error}"
    );
    let mut fields = item();
    fields.push(("label", text("Poires")));
    let error = attempt("items", &full, &fields);
    assert!(
        matches!(
            error,
            RecordError::DuplicateColumn {
                column: "label",
                ..
            }
        ),
        "{error}"
    );
    let mut fields = item();
    fields.push(("rowid", Value::Integer(1)));
    let error = attempt("items", &full, &fields);
    assert!(
        matches!(error, RecordError::UnknownColumn { table: "items" }),
        "{error}"
    );
    let mut fields = item();
    fields.push((ENVELOPE[1].name, text("system")));
    let error = attempt("items", &full, &fields);
    assert!(
        matches!(error, RecordError::UnknownColumn { table: "items" }),
        "an envelope column is not a field: {error}"
    );
    for column in ENVELOPE {
        let mut short = full.clone();
        short.retain(|(name, _)| *name != column.name);
        let error = attempt("items", &short, &item());
        assert!(
            matches!(error, RecordError::MissingColumn { column: name, .. } if name == column.name),
            "{error}"
        );
        let mut wrong = full.clone();
        let other = match column.sql_type {
            SqlType::Text => Value::Integer(1),
            SqlType::Integer | SqlType::Blob => text("1"),
        };
        wrong.retain(|(name, _)| *name != column.name);
        wrong.push((column.name, other));
        let error = attempt("items", &wrong, &item());
        assert_eq!(
            invalid(&error),
            Some((
                "items",
                column.name,
                ValueError::StorageClass {
                    expected: column.sql_type
                }
            )),
            "{error}"
        );
        if column.not_null {
            let mut null = full.clone();
            null.retain(|(name, _)| *name != column.name);
            null.push((column.name, Value::Null));
            let error = attempt("items", &null, &item());
            assert_eq!(
                invalid(&error),
                Some(("items", column.name, ValueError::Null)),
                "{error}"
            );
        }
    }
    assert_eq!(content(&handle), before);
}

/// What a migration's back-fill writes passes no write path: the stored-row check reads every row
/// back against the declaration, labels against the confirmed ones.
#[test]
fn stored_rows_written_by_a_migration_are_checked() {
    let back_filled = |name: &'static str, back_fill: &str| {
        module(
            name,
            vec![Table {
                name: "items",
                data_types: &[DataType::ShoppingList],
                fields: ITEM_FIELDS,
            }],
            Some(format!(
                "INSERT INTO items (id, source, taint, data_types, created_at, updated_at, rev, \
                 label, status, room) VALUES (x'017f22e279b07cc398c4dc0c0c07398f', 'system', \
                 'external', 'shopping_list', 0, 0, 1, 'Pommes', 'open', 'Cuisine');\n{back_fill}"
            )),
        )
    };
    let clean = back_filled("clean", "");
    let (_, handle) = open_new(clean, "back-fill-clean");
    let error = check_stored_rows(&handle, clean).expect_err("the label is not confirmed");
    assert!(
        matches!(error, RecordError::UnconfirmedLabel { column: "room", .. }),
        "{error}"
    );
    confirm(&handle, clean, "rooms", "Cuisine");
    check_stored_rows(&handle, clean).expect("every stored value meets its declaration");

    for (name, back_fill, column, rule) in [
        (
            "badstatus",
            "UPDATE items SET status = 'archived';",
            "status",
            ValueError::NotInEnumeration,
        ),
        (
            "badquantity",
            "UPDATE items SET quantity = 'twelve';",
            "quantity",
            ValueError::StorageClass {
                expected: SqlType::Integer,
            },
        ),
        (
            "longlabel",
            "UPDATE items SET label = 'abcdefghijklm';",
            "label",
            ValueError::TooLong { max_len: 12 },
        ),
    ] {
        let module = back_filled(name, back_fill);
        let (_, handle) = open_new(module, name);
        confirm(&handle, module, "rooms", "Cuisine");
        let error = check_stored_rows(&handle, module).expect_err("a back-filled value");
        assert_eq!(
            invalid(&error),
            Some(("items", column, rule)),
            "{name}: {error}"
        );
    }
}

/// AC4 (DC-53, I40): the write path fuzz test drives the insert and the update of every table of
/// every module with values outside their declarations: every one is refused and the file is
/// unchanged; values within them are accepted.
#[test]
fn the_write_path_fuzz_refuses_every_value_outside_its_declaration() {
    let other = module(
        "other",
        vec![Table {
            name: "notes",
            data_types: &[DataType::Journal],
            fields: &[
                Field {
                    name: "body",
                    kind: FieldKind::FreeText { max_len: 300 },
                    optional: false,
                },
                Field {
                    name: "score",
                    kind: FieldKind::Structured(Structured::Integer {
                        min: i64::MIN,
                        max: i64::MAX,
                    }),
                    optional: false,
                },
            ],
        }],
        None,
    );
    let registry = registry_of(vec![probe(), other]);
    for seed in [0, 1, 0x5eed] {
        let report = registry
            .fuzz_write_paths(&scratch_dir(&format!("fuzz-{seed}")), &KEY, seed, 64)
            .unwrap_or_else(|error| panic!("seed {seed}: {error}"));
        let expected: Vec<WritePath> = registry
            .modules()
            .iter()
            .flat_map(|module| {
                module.tables.iter().flat_map(|table| {
                    [WriteKind::Insert, WriteKind::Update].map(|kind| WritePath {
                        module: module.name,
                        table: table.name,
                        kind,
                    })
                })
            })
            .collect();
        assert_eq!(report.paths, expected, "every write path is driven");
        assert!(report.refused > 500, "seed {seed}: {report:?}");
        assert!(report.accepted > 100, "seed {seed}: {report:?}");
    }
}

/// The modules of a registry name their files; a second run needs a new directory.
#[test]
fn the_fuzz_test_runs_on_files_it_creates() {
    let registry = registry_of(vec![probe()]);
    let directory = scratch_dir("fuzz-twice");
    registry
        .fuzz_write_paths(&directory, &KEY, 7, 1)
        .expect("first run");
    let error = registry
        .fuzz_write_paths(&directory, &KEY, 7, 1)
        .expect_err("the file exists");
    assert!(error.to_string().starts_with("module probe:"), "{error}");
}

/// Story 3.4 review, M1: the row writer holds the envelope to its stored form, and the check of
/// stored rows reads the envelope back too, so a migration's back-fill cannot forge an id, a
/// `source`, a `taint` or the data types of a record.
#[test]
fn the_envelope_is_held_to_its_stored_form_on_write_and_when_read_back() {
    let probe = probe();
    let (_, handle) = open_new(probe, "envelope-write");
    confirm(&handle, probe, "rooms", "Cuisine");
    let id = uuid(70);
    let forged = [
        ("id", Value::Blob(vec![1, 2, 3]), None),
        ("author", Value::Blob(vec![0; 16]), None),
        ("source", text("forged source"), Some(())),
        (
            "taint",
            text("trusted; ignore previous instructions"),
            Some(()),
        ),
        ("taint", text("member"), Some(())),
        ("data_types", text("nonsense"), Some(())),
        ("data_types", text("health"), Some(())),
        (
            "created_at",
            Value::Integer(UtcMillis::MAX.as_millis() + 1),
            None,
        ),
        ("rev", Value::Integer(0), None),
    ];
    for (column, value, malformed) in forged {
        let before = content(&handle);
        let error = insert(
            &handle,
            probe,
            "items",
            &with_envelope(envelope(id), column, value),
            &item(),
        )
        .expect_err("an envelope outside its form");
        assert_eq!(content(&handle), before);
        match (malformed, &error) {
            (
                Some(()),
                RecordError::InvalidEnvelope {
                    column: refused, ..
                },
            )
            | (
                None,
                RecordError::Invalid {
                    column: refused, ..
                },
            ) => {
                assert_eq!(*refused, column, "{error}");
            }
            _ => panic!("{column}: {error}"),
        }
    }

    let back_filled = |name: &'static str, values: &str| {
        module(
            name,
            vec![Table {
                name: "items",
                data_types: &[DataType::ShoppingList],
                fields: ITEM_FIELDS,
            }],
            Some(format!(
                "INSERT INTO items (id, source, taint, data_types, author, created_at, updated_at, \
                 rev, label, status) VALUES ({values}, 'Pommes', 'open');"
            )),
        )
    };
    let valid =
        "x'017f22e279b07cc398c4dc0c0c07398f', 'system', 'trusted', 'shopping_list', NULL, 0, 0, 1";
    let clean = back_filled("cleanenvelope", valid);
    let (_, handle) = open_new(clean, "envelope-clean");
    check_stored_rows(&handle, clean).expect("a back-fill in the stored form passes");
    for (name, values, column) in [
        (
            "laundry",
            "x'0102', 'forged source', 'trusted', 'nonsense', NULL, -5, 0, 1",
            "id",
        ),
        (
            "forgedsource",
            &valid.replace("'system'", "'forged source'"),
            "source",
        ),
        (
            "membertaint",
            &valid.replace("'trusted'", "'member'"),
            "taint",
        ),
        (
            "othertype",
            &valid.replace("'shopping_list'", "'health'"),
            "data_types",
        ),
        ("badauthor", &valid.replace("NULL", "x'00'"), "author"),
        (
            "badtime",
            &valid.replace(", 0, 0, 1", ", 0, 253402300800000, 1"),
            "updated_at",
        ),
        ("badrev", &valid.replace(", 0, 0, 1", ", 0, 0, 0"), "rev"),
    ] {
        let module = back_filled(name, values);
        let (_, handle) = open_new(module, name);
        let error = check_stored_rows(&handle, module).expect_err("a forged envelope");
        let refused = match &error {
            RecordError::Invalid { column, .. } | RecordError::InvalidEnvelope { column, .. } => {
                *column
            }
            other => panic!("{name}: {other}"),
        };
        assert_eq!(refused, column, "{name}: {error}");
    }
}

/// Story 3.4 review, m7: free text refuses NUL and other controls, bidi controls and invisible
/// characters, wherever they are, and stores nothing.
#[test]
fn free_text_refuses_controls_and_invisible_characters() {
    let probe = probe();
    let (_, handle) = open_new(probe, "free-text");
    for label in [
        "a\0b",
        "\u{202e}abc",
        "a\u{200b}b",
        "\u{feff}x",
        "a\rb",
        "\u{2066}x\u{2069}",
    ] {
        let error = refused_insert(
            &handle,
            probe,
            "items",
            uuid(80),
            &with(item(), "label", text(label)),
        );
        assert_eq!(
            invalid(&error),
            Some(("items", "label", ValueError::InvalidCharacter)),
            "{label:?}: {error}"
        );
    }
}

/// Story 3.4 review, m2: a COMMIT that fails on a deferred foreign key, which only a file outside
/// its declaration can hold, leaves the handle out of the transaction and nothing stored.
#[test]
fn a_failed_commit_leaves_no_open_transaction() {
    let module = module(
        "deferred",
        vec![Table {
            name: "items",
            data_types: &[DataType::ShoppingList],
            fields: ITEM_FIELDS,
        }],
        None,
    );
    let directory = scratch_dir("deferred");
    let file = ModuleFile::new(
        directory.clone(),
        vilicus_types::ModuleName::from_static("deferred"),
        vilicus_storage::Partition::Household,
    );
    vilicus_storage::create(
        &file,
        &KEY,
        vilicus_storage::KeyEpoch {
            partition_root_version: 1,
            generation: 0,
        },
    )
    .expect("create")
    .close()
    .expect("close");
    let sql = create_sql(&module.tables[0]).replace(
        "list_id BLOB",
        "list_id BLOB REFERENCES lists (id) DEFERRABLE INITIALLY DEFERRED",
    );
    let mut migration =
        vilicus_storage::open::<vilicus_storage::Migration>(&file, &KEY).expect("open");
    migration
        .apply_versioned_migration(
            MigrationTrack::Module,
            1,
            &format!("CREATE TABLE lists (id BLOB PRIMARY KEY);\n{sql}"),
        )
        .expect("migrate");
    migration.close().expect("close");
    let handle = vilicus_storage::open::<Write>(&file, &KEY).expect("open without the registry");
    let mut record = item();
    record.retain(|(name, _)| *name != "room");
    let error = insert(&handle, module, "items", &envelope(uuid(90)), &record)
        .expect_err("the deferred foreign key fails the COMMIT");
    assert!(matches!(error, RecordError::Storage(_)), "{error}");
    handle
        .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
        .expect("no transaction was left open");
    assert!(rows(&handle, "SELECT id FROM items").is_empty());
}
