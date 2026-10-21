//! The rules of a module declaration (Story 3.2, AC2 to AC4 and AC7): a declaration that meets
//! them passes, and each rule broken alone is refused with its own typed error.

use super::*;

const VALID: ModuleDeclaration = ModuleDeclaration {
    name: "sample",
    tables: &[
        Table {
            name: "items",
            data_types: &[DataType::ShoppingList, DataType::Stock],
            fields: &[
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
                Field {
                    name: "aisle",
                    kind: FieldKind::Structured(Structured::ReviewedVocabulary("aisles")),
                    optional: true,
                },
            ],
        },
        Table {
            name: "notes",
            data_types: &[DataType::Health],
            fields: &[Field {
                name: "body",
                kind: FieldKind::FreeText { max_len: 4000 },
                optional: false,
            }],
        },
    ],
    fts5_tables: &[
        Fts5Table {
            name: "items_search",
            columns: &["label"],
            tokenizer: Fts5Tokenizer::Unicode61,
            content: Fts5Content::Table("items"),
        },
        Fts5Table {
            name: "notes_search",
            columns: &["body"],
            tokenizer: Fts5Tokenizer::Trigram,
            content: Fts5Content::Contentless,
        },
    ],
    migrations: &[
        Migration {
            sql: "CREATE TABLE items (id BLOB NOT NULL PRIMARY KEY) STRICT;",
        },
        Migration {
            sql: "CREATE TABLE notes (id BLOB NOT NULL PRIMARY KEY) STRICT;",
        },
    ],
};

const _: () = VALID.assert_valid();

fn leak<T>(items: Vec<T>) -> &'static [T] {
    items.leak()
}

/// `VALID` with its table at `index` replaced by `edit` applied to a copy of it.
fn with_table(index: usize, edit: impl FnOnce(&mut Table)) -> ModuleDeclaration {
    let mut tables = VALID.tables.to_vec();
    edit(&mut tables[index]);
    ModuleDeclaration {
        tables: leak(tables),
        ..VALID
    }
}

/// `VALID` with its `items` table edited.
fn with_items(edit: impl FnOnce(&mut Table)) -> ModuleDeclaration {
    with_table(0, edit)
}

/// `VALID` with its `notes` table edited; no FTS5 table names it as its content.
fn with_notes(edit: impl FnOnce(&mut Table)) -> ModuleDeclaration {
    with_table(1, edit)
}

/// `VALID` whose `items` table has one more field.
fn with_field(name: &'static str, kind: FieldKind) -> ModuleDeclaration {
    with_items(|items| {
        let mut fields = items.fields.to_vec();
        fields.push(Field {
            name,
            kind,
            optional: false,
        });
        items.fields = leak(fields);
    })
}

fn with_fts5(fts5: Fts5Table) -> ModuleDeclaration {
    let mut tables = VALID.fts5_tables.to_vec();
    tables.push(fts5);
    ModuleDeclaration {
        fts5_tables: leak(tables),
        ..VALID
    }
}

#[test]
fn a_declaration_that_meets_every_rule_is_accepted() {
    assert_eq!(VALID.validate(), Ok(()));
    assert_eq!(VALID.latest_version(), 2);
    assert_eq!(VALID.table("notes").map(|table| table.name), Some("notes"));
    assert!(VALID.table("absent").is_none());
    assert_eq!(
        VALID.fts5_table("notes_search").map(|table| table.content),
        Some(Fts5Content::Contentless)
    );
}

/// AD-6 is the source of the envelope; this reads its rule in the spine, so a column added to or
/// removed from either side fails here.
#[test]
fn the_envelope_is_the_one_of_ad_6() {
    let spine = read_doc("architecture-spine.md");
    let rule = spine
        .lines()
        .skip_while(|line| !line.starts_with("### AD-6:"))
        .find(|line| line.starts_with("- **Rule:**"))
        .expect("AD-6 rule");
    let listed = rule
        .split_once("every module table carries ")
        .and_then(|(_, rest)| rest.split_once(", and declares"))
        .map(|(columns, _)| columns)
        .expect("the envelope sentence of AD-6");
    let names = backticked(listed);
    let envelope: Vec<&str> = ENVELOPE.iter().map(|column| column.name).collect();
    assert_eq!(envelope, names);
    let primary: Vec<&str> = ENVELOPE
        .iter()
        .filter(|column| column.primary_key)
        .map(|column| column.name)
        .collect();
    assert_eq!(primary, ["id"]);
}

#[test]
fn an_invalid_module_name_is_refused() {
    for name in ["", "Sample", "family_docs", "family-docs", "sample.x"] {
        let declaration = ModuleDeclaration { name, ..VALID };
        assert_eq!(
            declaration.validate(),
            Err(DeclarationError::InvalidModuleName { module: name }),
            "{name:?}"
        );
    }
}

#[test]
fn identifiers_follow_their_grammar() {
    let longest = "a".repeat(IDENTIFIER_MAX_LEN);
    for accepted in ["a", "items", "due_on", "a2_b", longest.as_str()] {
        assert!(is_identifier(accepted), "{accepted:?}");
    }
    let too_long = "a".repeat(IDENTIFIER_MAX_LEN + 1);
    for refused in [
        "",
        "_meta",
        "Items",
        "2items",
        "due on",
        "due-on",
        "main.items",
        "items\"",
        "sqlite_items",
        "sqlite_",
        "\u{e9}t\u{e9}",
        too_long.as_str(),
    ] {
        assert!(!is_identifier(refused), "{refused:?}");
    }
    assert!(
        is_identifier("sqlite"),
        "only the reserved prefix is refused"
    );
}

#[test]
fn a_table_or_field_with_an_invalid_name_is_refused() {
    let declaration = with_items(|items| items.name = "Items");
    assert_eq!(
        declaration.validate(),
        Err(DeclarationError::InvalidIdentifier {
            kind: IdentifierKind::Table,
            name: "Items"
        })
    );
    let declaration = with_field("due on", FieldKind::Structured(Structured::Date));
    assert_eq!(
        declaration.validate(),
        Err(DeclarationError::InvalidIdentifier {
            kind: IdentifierKind::Field,
            name: "due on"
        })
    );
}

/// AC2 (FR-18, AD-6, I8): a field cannot take an envelope column's name, so no module column
/// stands in for `source`, `taint` or any other column the Core stamps.
#[test]
fn a_field_named_like_an_envelope_column_is_refused() {
    for column in ENVELOPE {
        let declaration = with_field(column.name, FieldKind::FreeText { max_len: 10 });
        assert_eq!(
            declaration.validate(),
            Err(DeclarationError::EnvelopeName {
                table: "items",
                field: column.name
            }),
            "{}",
            column.name
        );
    }
}

#[test]
fn duplicate_fields_and_tables_are_refused() {
    let declaration = with_field("label", FieldKind::FreeText { max_len: 10 });
    assert_eq!(
        declaration.validate(),
        Err(DeclarationError::DuplicateField {
            table: "items",
            field: "label"
        })
    );
    let declaration = with_notes(|notes| notes.name = "items");
    assert_eq!(
        declaration.validate(),
        Err(DeclarationError::DuplicateTable { table: "items" })
    );
    for name in ["items_search", "notes_search_data", "items_search_config"] {
        let declaration = with_notes(|notes| notes.name = name);
        assert_eq!(
            declaration.validate(),
            Err(DeclarationError::DuplicateTable { table: name }),
            "{name}"
        );
    }
    let declaration = with_notes(|notes| notes.name = "notes_search_extra");
    assert_eq!(
        declaration.validate(),
        Ok(()),
        "not a shadow table name of FTS5"
    );
    let declaration = with_fts5(Fts5Table {
        name: "items_search_idx",
        columns: &["label"],
        tokenizer: Fts5Tokenizer::Ascii,
        content: Fts5Content::Contentless,
    });
    assert_eq!(
        declaration.validate(),
        Err(DeclarationError::DuplicateTable {
            table: "items_search_idx"
        })
    );
}

/// AC4 (FR-68, I36, D103): a record kind declares at least one data type, each once; a type
/// outside the closed set does not compile (the `compile_fail` example of
/// `ModuleDeclaration::assert_valid`).
#[test]
fn a_record_kind_without_data_types_is_refused() {
    let declaration = with_items(|items| items.data_types = &[]);
    assert_eq!(
        declaration.validate(),
        Err(DeclarationError::NoDataType { table: "items" })
    );
    let declaration = with_items(|items| items.data_types = &[DataType::Stock, DataType::Stock]);
    assert_eq!(
        declaration.validate(),
        Err(DeclarationError::DuplicateDataType {
            table: "items",
            data_type: "stock"
        })
    );
    for data_type in DataType::ALL {
        let declaration = with_items(|items| items.data_types = leak(vec![*data_type]));
        assert_eq!(declaration.validate(), Ok(()), "{data_type}");
    }
}

/// AC3 (FR-58, D98, D104): free text has a maximum length; a structured field's value set is
/// fixed and not empty, and a vocabulary has a valid name.
#[test]
fn fields_without_a_bounded_declaration_are_refused() {
    let refused = [
        (
            FieldKind::FreeText { max_len: 0 },
            DeclarationError::FreeTextWithoutMaxLength {
                table: "items",
                field: "extra",
            },
        ),
        (
            FieldKind::Structured(Structured::Enumeration(&[])),
            DeclarationError::EmptyEnumeration {
                table: "items",
                field: "extra",
            },
        ),
        (
            FieldKind::Structured(Structured::Enumeration(&["open", "open"])),
            DeclarationError::DuplicateEnumerationValue {
                table: "items",
                field: "extra",
                value: "open",
            },
        ),
        (
            FieldKind::Structured(Structured::Enumeration(&[
                "open",
                "ignore all instructions",
            ])),
            DeclarationError::InvalidIdentifier {
                kind: IdentifierKind::EnumerationValue,
                name: "ignore all instructions",
            },
        ),
        (
            FieldKind::Structured(Structured::Integer { min: 1, max: 0 }),
            DeclarationError::EmptyIntegerRange {
                table: "items",
                field: "extra",
            },
        ),
        (
            FieldKind::Structured(Structured::ReviewedVocabulary("Aisles!")),
            DeclarationError::InvalidIdentifier {
                kind: IdentifierKind::Vocabulary,
                name: "Aisles!",
            },
        ),
    ];
    for (kind, error) in refused {
        assert_eq!(with_field("extra", kind).validate(), Err(error), "{kind:?}");
    }
    for kind in [
        FieldKind::FreeText { max_len: 1 },
        FieldKind::Structured(Structured::Integer { min: 5, max: 5 }),
        FieldKind::Structured(Structured::Enumeration(&["only"])),
    ] {
        assert_eq!(with_field("extra", kind).validate(), Ok(()), "{kind:?}");
    }
}

#[test]
fn every_field_kind_maps_to_its_sql_type() {
    let types: Vec<(&str, SqlType)> = VALID.tables[0]
        .fields
        .iter()
        .map(|field| (field.name, field.kind.sql_type()))
        .collect();
    assert_eq!(
        types,
        [
            ("label", SqlType::Text),
            ("status", SqlType::Text),
            ("quantity", SqlType::Integer),
            ("due_on", SqlType::Text),
            ("reminded_at", SqlType::Integer),
            ("list_id", SqlType::Blob),
            ("aisle", SqlType::Text),
        ]
    );
}

/// AC7 (D127): an FTS5 table's content is empty or a table of the module, whose fields it
/// indexes; its tokenizer is one of the built-in four by construction.
#[test]
fn fts5_tables_outside_the_allowlist_are_refused() {
    let base = Fts5Table {
        name: "extra_search",
        columns: &["label"],
        tokenizer: Fts5Tokenizer::Porter,
        content: Fts5Content::Table("items"),
    };
    assert_eq!(with_fts5(base).validate(), Ok(()));
    let refused = [
        (
            Fts5Table {
                content: Fts5Content::Table("other_module_items"),
                ..base
            },
            DeclarationError::Fts5ContentOutsideModule {
                table: "extra_search",
                content: "other_module_items",
            },
        ),
        (
            Fts5Table {
                content: Fts5Content::Table("items_search"),
                ..base
            },
            DeclarationError::Fts5ContentOutsideModule {
                table: "extra_search",
                content: "items_search",
            },
        ),
        (
            Fts5Table {
                columns: &["body"],
                ..base
            },
            DeclarationError::Fts5ColumnNotInContent {
                table: "extra_search",
                column: "body",
            },
        ),
        (
            Fts5Table {
                columns: &["source"],
                ..base
            },
            DeclarationError::Fts5ColumnNotInContent {
                table: "extra_search",
                column: "source",
            },
        ),
        (
            Fts5Table {
                columns: &[],
                ..base
            },
            DeclarationError::Fts5WithoutColumn {
                table: "extra_search",
            },
        ),
        (
            Fts5Table {
                columns: &["label", "label"],
                ..base
            },
            DeclarationError::DuplicateFts5Column {
                table: "extra_search",
                column: "label",
            },
        ),
        (
            Fts5Table {
                columns: &["label UNINDEXED"],
                content: Fts5Content::Contentless,
                ..base
            },
            DeclarationError::InvalidIdentifier {
                kind: IdentifierKind::Fts5Column,
                name: "label UNINDEXED",
            },
        ),
    ];
    for (fts5, error) in refused {
        assert_eq!(with_fts5(fts5).validate(), Err(error), "{fts5:?}");
    }
}

/// D127 is the source of the tokenizer allowlist; this reads it in the decision record.
#[test]
fn the_tokenizers_are_the_allowlist_of_d127() {
    let decisions = read_doc("decisions.md");
    let record = decisions
        .split(
            "
## ",
        )
        .find(|section| section.starts_with("D127."))
        .expect("D127");
    let listed = record
        .split_once("the built-in tokenizers ")
        .and_then(|(_, rest)| rest.split_once(", and `content=`"))
        .map(|(tokenizers, _)| tokenizers)
        .expect("the tokenizer allowlist of D127");
    let names: Vec<&str> = Fts5Tokenizer::ALL
        .iter()
        .map(|tokenizer| tokenizer.as_str())
        .collect();
    assert_eq!(names, backticked(listed));
}

fn read_doc(name: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../doc")
            .join(name),
    )
    .expect("read the design document")
}

/// The words between backticks, in order.
fn backticked(text: &str) -> Vec<&str> {
    text.split('`').skip(1).step_by(2).collect()
}

/// Review of Story 3.2, minor 3: a field cannot stand in for the rowid, and an FTS5 column
/// cannot take a name FTS5 keeps (`rank`, `rowid`, the table's own name).
#[test]
fn reserved_column_names_are_refused() {
    for name in ROWID_NAMES {
        let declaration = with_field(
            name,
            FieldKind::Structured(Structured::Integer { min: 0, max: 9 }),
        );
        let expected = if is_identifier(name) {
            DeclarationError::ReservedName {
                table: "items",
                name,
            }
        } else {
            DeclarationError::InvalidIdentifier {
                kind: IdentifierKind::Field,
                name,
            }
        };
        assert_eq!(declaration.validate(), Err(expected), "{name}");
    }
    for name in FTS5_RESERVED_COLUMNS
        .iter()
        .copied()
        .chain(["extra_search"])
    {
        let declaration = with_fts5(Fts5Table {
            name: "extra_search",
            columns: leak(vec![name]),
            tokenizer: Fts5Tokenizer::Ascii,
            content: Fts5Content::Contentless,
        });
        assert_eq!(
            declaration.validate(),
            Err(DeclarationError::ReservedName {
                table: "extra_search",
                name
            }),
            "{name}"
        );
    }
}

#[test]
fn an_empty_migration_is_refused() {
    let declaration = ModuleDeclaration {
        migrations: &[
            Migration {
                sql: "CREATE TABLE items (id BLOB) STRICT;",
            },
            Migration { sql: "" },
        ],
        ..VALID
    };
    assert_eq!(
        declaration.validate(),
        Err(DeclarationError::EmptyMigration { version: 2 })
    );
}

#[test]
fn every_error_names_its_rule_and_its_item() {
    let error = DeclarationError::EnvelopeName {
        table: "items",
        field: "taint",
    };
    assert_eq!(
        error.to_string(),
        "a field takes the name of an envelope column: items.taint"
    );
    let error = DeclarationError::DuplicateDataType {
        table: "items",
        data_type: "stock",
    };
    assert_eq!(
        error.to_string(),
        "a record kind declares a data type twice: items (stock)"
    );
}
