//! The write path fuzz test of D98 and I40 (Story 3.4, AC4): every write path of every module of
//! a registry, the insert and the update of each table, driven with values outside their
//! declarations. Each such write must be refused with the typed error of the rule it breaks, and
//! the file must hold exactly what it held before; values within the declarations, generated the
//! same way, must be accepted, so the test cannot pass by refusing everything.
//!
//! It runs on new files it creates and migrates under a scratch directory, never on a member's
//! file, and confirms the vocabulary labels of those files itself. The generator is a seeded
//! pseudo-random sequence, so a failure replays from its seed; it is not coverage-guided, and not
//! for cryptographic use.

use core::fmt;
use std::path::Path;

use vilicus_module_api::{
    DataType, ENVELOPE, EnvelopeColumn, Field, FieldKind, ModuleDeclaration, SqlType, Structured,
    Table, VOCABULARY_LABEL_MAX_LEN, VOCABULARY_LABEL_SEPARATORS, Value, ValueError,
    check_vocabulary_label, is_free_text_character, is_vocabulary_label_letter,
};
use vilicus_storage::{CORE_PRIVATE_TABLES, Handle, SqlValue, TableKind, Write};
use vilicus_types::{Id, RecordLabels, Source, Taint, TextTaint, UtcMillis};

use super::envelope::{EnvelopeRule, data_types_text, rule};
use super::{RecordError, check_stored_rows, confirm_label, declared_vocabularies, insert, update};
use crate::registry::{FileError, Registry, create_migrated};

/// Longest free text the generator writes within a declaration; past a maximum, it writes one
/// character more than any declared maximum, which `FREE_TEXT_MAX_LEN` bounds.
const FREE_TEXT_FUZZ_MAX: u32 = 1 << 16;

/// Labels confirmed per vocabulary in each fuzzed file.
const LABELS_PER_VOCABULARY: usize = 4;

/// Fields made invalid at once in a random round, at most.
const INVALID_FIELDS_PER_ROUND: usize = 3;

/// One write path: the insert or the update of one table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WritePath {
    /// The module.
    pub module: &'static str,
    /// The table.
    pub table: &'static str,
    /// The write.
    pub kind: WriteKind,
}

/// A write of the record API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WriteKind {
    /// A new record.
    Insert,
    /// A change of an existing record.
    Update,
}

impl fmt::Display for WritePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            WriteKind::Insert => "insert",
            WriteKind::Update => "update",
        };
        write!(formatter, "{kind} into {}.{}", self.module, self.table)
    }
}

/// What a fuzz run drove.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteFuzzReport {
    /// Every write path driven.
    pub paths: Vec<WritePath>,
    /// Writes with values outside their declarations, each refused with nothing stored.
    pub refused: u64,
    /// Writes with values within their declarations, each accepted.
    pub accepted: u64,
}

/// A failure of the write path fuzz test. A case is named by its column and the rule its value
/// breaks, never by the value.
#[derive(Debug)]
#[non_exhaustive]
pub enum WriteFuzzError {
    /// A module's file could not be created, migrated or opened.
    Setup {
        /// The module.
        module: &'static str,
        /// What failed.
        error: Box<FileError>,
    },
    /// Reading the file's content, or confirming a label, failed.
    Storage {
        /// The module.
        module: &'static str,
        /// What failed.
        error: Box<RecordError>,
    },
    /// A write with a value outside its declaration was accepted.
    Accepted {
        /// The write path.
        path: WritePath,
        /// The case.
        case: String,
    },
    /// A write with a value outside its declaration was refused for another reason than the rule
    /// its value breaks.
    WrongRefusal {
        /// The write path.
        path: WritePath,
        /// The case.
        case: String,
        /// The refusal.
        error: Box<RecordError>,
    },
    /// A refused write changed the file.
    Changed {
        /// The write path.
        path: WritePath,
        /// The case.
        case: String,
    },
    /// A write with values within their declarations was refused.
    ValidRefused {
        /// The write path.
        path: WritePath,
        /// The refusal.
        error: Box<RecordError>,
    },
    /// A row stored by an accepted write does not meet the declaration when read back.
    StoredRowRefused {
        /// The module.
        module: &'static str,
        /// The refusal.
        error: Box<RecordError>,
    },
}

impl fmt::Display for WriteFuzzError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setup { module, error } => write!(formatter, "module {module}: {error}"),
            Self::Storage { module, error } => write!(formatter, "module {module}: {error}"),
            Self::Accepted { path, case } => {
                write!(
                    formatter,
                    "{path}: accepted a value outside its declaration ({case})"
                )
            }
            Self::WrongRefusal { path, case, error } => {
                write!(formatter, "{path}: {case} refused as {error}")
            }
            Self::Changed { path, case } => {
                write!(
                    formatter,
                    "{path}: the refused write changed the file ({case})"
                )
            }
            Self::ValidRefused { path, error } => {
                write!(
                    formatter,
                    "{path}: refused a write within its declaration: {error}"
                )
            }
            Self::StoredRowRefused { module, error } => {
                write!(
                    formatter,
                    "module {module}: a stored row was refused: {error}"
                )
            }
        }
    }
}

impl std::error::Error for WriteFuzzError {}

impl Registry {
    /// The write path fuzz test of D98 and I40: for each module, creates its file in the household
    /// partition under `directory` with `key`, applies its migrations, confirms a few generated
    /// labels of each of its reviewed vocabularies, then drives the insert and the update of
    /// every table:
    ///
    /// - once with each value outside its field's declaration that the generator knows for that
    ///   field kind (another storage class, `NULL` for a required field, a value outside the
    ///   enumeration or the range, an invalid date or UUIDv7, free text one character too long or
    ///   holding a refused character, an unconfirmed label, one confirmed in another vocabulary
    ///   only, a malformed label), with a missing required field, an undeclared column and a
    ///   column given twice;
    /// - once with each envelope value outside its stored form the generator knows (an id or
    ///   author that is not a UUIDv7, a forged `source`, a `taint` or `text_taint` outside its
    ///   stored set, a `text_taint` below the `taint`, data types the record kind does not
    ///   declare or out of their form, a time out of range, a `rev` below 1, another storage
    ///   class, `NULL`), with an update that changes the id and an update of a record the table
    ///   does not hold;
    /// - `rounds` times with up to three fields made invalid at once, and with a write within
    ///   the declarations.
    ///
    /// Each invalid write must be refused with the error of a rule it breaks and leave every
    /// table of the file unchanged; each valid write must be accepted; at the end every stored row
    /// must meet the declaration. `seed` fixes the generated values. `directory` holds no file of
    /// these modules beforehand; the files stay there.
    pub fn fuzz_write_paths(
        &self,
        directory: &Path,
        key: &[u8; 32],
        seed: u64,
        rounds: u32,
    ) -> Result<WriteFuzzReport, WriteFuzzError> {
        let mut rng = Rng(seed);
        let mut report = WriteFuzzReport::default();
        for &module in self.modules() {
            let setup = |error| WriteFuzzError::Setup {
                module: module.name,
                error: Box::new(error),
            };
            let file = create_migrated(module, directory, key).map_err(setup)?;
            let handle = self.open::<Write>(&file, key).map_err(setup)?;
            let labels = confirm_labels(&handle, module, &mut rng)?;
            for table in module.tables {
                let mut fuzz = TableFuzz {
                    handle: &handle,
                    module,
                    table,
                    labels: &labels,
                    rng: &mut rng,
                    report: &mut report,
                };
                fuzz.run(rounds)?;
            }
            check_stored_rows(&handle, module).map_err(|error| {
                WriteFuzzError::StoredRowRefused {
                    module: module.name,
                    error: Box::new(error),
                }
            })?;
            handle
                .close()
                .map_err(|error| setup(FileError::Storage(error)))?;
        }
        Ok(report)
    }
}

/// The labels confirmed for each vocabulary of the module, one of them the longest allowed.
fn confirm_labels(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    rng: &mut Rng,
) -> Result<Vec<(&'static str, Vec<String>)>, WriteFuzzError> {
    let mut labels: Vec<(&'static str, Vec<String>)> = Vec::new();
    for vocabulary in declared_vocabularies(module) {
        if labels.iter().any(|(declared, _)| *declared == vocabulary) {
            continue;
        }
        let mut confirmed = vec![rng.label(VOCABULARY_LABEL_MAX_LEN)];
        while confirmed.len() < LABELS_PER_VOCABULARY {
            let label = rng.any_label();
            if !confirmed.contains(&label) {
                confirmed.push(label);
            }
        }
        for label in &confirmed {
            confirm_label(handle, module, vocabulary, label, rng.id(), rng.instant()).map_err(
                |error| WriteFuzzError::Storage {
                    module: module.name,
                    error: Box::new(error),
                },
            )?;
        }
        labels.push((vocabulary, confirmed));
    }
    Ok(labels)
}

/// The refusal a case expects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expected {
    Invalid(ValueError),
    Envelope,
    Unconfirmed,
    Missing,
    Unknown,
    Duplicate,
    IdChanged,
    NotFound,
}

/// One value outside its column's declaration: the field or envelope column, the rule broken,
/// the value (`None` for a field left out) and the refusal expected.
#[derive(Clone, Debug)]
struct Case {
    column: &'static str,
    envelope: bool,
    rule: &'static str,
    value: Option<Value>,
    expected: Expected,
}

impl Case {
    fn new(field: &Field, rule: &'static str, value: Value, expected: Expected) -> Self {
        Self {
            column: field.name,
            envelope: false,
            rule,
            value: Some(value),
            expected,
        }
    }

    fn envelope(
        column: &'static EnvelopeColumn,
        rule: &'static str,
        value: Value,
        expected: Expected,
    ) -> Self {
        Self {
            column: column.name,
            envelope: true,
            rule,
            value: Some(value),
            expected,
        }
    }

    fn matches(&self, error: &RecordError) -> bool {
        match (self.expected, error) {
            (Expected::Invalid(expected), RecordError::Invalid { column, error, .. }) => {
                *column == self.column && *error == expected
            }
            (Expected::Envelope, RecordError::InvalidEnvelope { column, .. })
            | (Expected::Unconfirmed, RecordError::UnconfirmedLabel { column, .. })
            | (Expected::Missing, RecordError::MissingColumn { column, .. })
            | (Expected::Duplicate, RecordError::DuplicateColumn { column, .. }) => {
                *column == self.column
            }
            (Expected::Unknown, RecordError::UnknownColumn { .. })
            | (Expected::IdChanged, RecordError::IdChanged { .. })
            | (Expected::NotFound, RecordError::RecordNotFound { .. }) => true,
            _ => false,
        }
    }

    fn describe(cases: &[Case]) -> String {
        cases
            .iter()
            .map(|case| format!("{}: {}", case.column, case.rule))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// The fuzzing of one table's write paths.
struct TableFuzz<'a> {
    handle: &'a Handle<Write>,
    module: &'static ModuleDeclaration,
    table: &'static Table,
    labels: &'a [(&'static str, Vec<String>)],
    rng: &'a mut Rng,
    report: &'a mut WriteFuzzReport,
}

impl TableFuzz<'_> {
    fn path(&self, kind: WriteKind) -> WritePath {
        WritePath {
            module: self.module.name,
            table: self.table.name,
            kind,
        }
    }

    fn run(&mut self, rounds: u32) -> Result<(), WriteFuzzError> {
        let id = self.accept_insert()?;
        self.report.paths.push(self.path(WriteKind::Insert));
        self.report.paths.push(self.path(WriteKind::Update));
        for field in self.table.fields {
            for case in self.invalid_cases(field) {
                let mut insert = self.valid_fields();
                apply(&mut insert, std::slice::from_ref(&case));
                self.refuse(WriteKind::Insert, id, &insert, std::slice::from_ref(&case))?;
                let update = vec![(field.name, case.value.clone().unwrap_or(Value::Null))];
                self.refuse(WriteKind::Update, id, &update, &[case])?;
            }
            if !field.optional {
                let mut insert = self.valid_fields();
                insert.retain(|(name, _)| *name != field.name);
                let case = Case {
                    column: field.name,
                    envelope: false,
                    rule: "a required field left out",
                    value: None,
                    expected: Expected::Missing,
                };
                self.refuse(WriteKind::Insert, id, &insert, &[case])?;
            }
            let value = self.valid_value(field);
            let case = Case::new(
                field,
                "a field given twice",
                value.clone(),
                Expected::Duplicate,
            );
            for kind in [WriteKind::Insert, WriteKind::Update] {
                let mut fields = match kind {
                    WriteKind::Insert => self.valid_fields(),
                    WriteKind::Update => Vec::new(),
                };
                fields.retain(|(name, _)| *name != field.name);
                fields.push((field.name, value.clone()));
                fields.push((field.name, value.clone()));
                self.refuse(kind, id, &fields, std::slice::from_ref(&case))?;
            }
        }
        let undeclared = Case {
            column: "undeclared",
            envelope: false,
            rule: "a column the table does not declare",
            value: Some(Value::Integer(0)),
            expected: Expected::Unknown,
        };
        for kind in [WriteKind::Insert, WriteKind::Update] {
            let mut fields = self.valid_fields();
            fields.push(("undeclared", Value::Integer(0)));
            self.refuse(kind, id, &fields, std::slice::from_ref(&undeclared))?;
        }
        self.refuse_envelopes(id)?;
        let missing = Case {
            column: "id",
            envelope: false,
            rule: "an update of a record the table does not hold",
            value: None,
            expected: Expected::NotFound,
        };
        if let Some(field) = self.table.fields.first() {
            let changes = vec![(field.name, self.valid_value(field))];
            let other = self.rng.id();
            self.refuse(WriteKind::Update, other, &changes, &[missing])?;
        }
        for _ in 0..rounds {
            self.random_round(id)?;
        }
        Ok(())
    }

    /// A random round: a write with up to three invalid fields, refused on both paths, then a
    /// valid insert and a valid update, accepted.
    fn random_round(&mut self, id: Id) -> Result<(), WriteFuzzError> {
        let fields = self.table.fields;
        if !fields.is_empty() {
            let count = 1 + self.rng.index(INVALID_FIELDS_PER_ROUND.min(fields.len()));
            let mut cases: Vec<Case> = Vec::new();
            while cases.len() < count {
                let field = &fields[self.rng.index(fields.len())];
                if cases.iter().any(|case| case.column == field.name) {
                    continue;
                }
                let mut candidates = self.invalid_cases(field);
                if candidates.is_empty() {
                    break;
                }
                cases.push(candidates.swap_remove(self.rng.index(candidates.len())));
            }
            if !cases.is_empty() {
                let mut insert = self.valid_fields();
                apply(&mut insert, &cases);
                self.refuse(WriteKind::Insert, id, &insert, &cases)?;
                let update: Vec<(&'static str, Value)> = cases
                    .iter()
                    .map(|case| (case.column, case.value.clone().unwrap_or(Value::Null)))
                    .collect();
                self.refuse(WriteKind::Update, id, &update, &cases)?;
            }
        }
        self.accept_insert()?;
        let changes: Vec<(&'static str, Value)> = self
            .valid_fields()
            .into_iter()
            .filter(|_| self.rng.chance(1, 2))
            .collect();
        if !changes.is_empty() {
            update(
                self.handle,
                self.module,
                self.table.name,
                id,
                &[],
                &changes,
                &[],
            )
            .map_err(|error| WriteFuzzError::ValidRefused {
                path: self.path(WriteKind::Update),
                error: Box::new(error),
            })?;
            self.report.accepted += 1;
        }
        Ok(())
    }

    /// Inserts a record within the declarations, which must be accepted; its id.
    fn accept_insert(&mut self) -> Result<Id, WriteFuzzError> {
        let id = self.rng.id();
        let envelope = self.envelope(id);
        let fields = self.valid_fields();
        insert(
            self.handle,
            self.module,
            self.table.name,
            &envelope,
            &fields,
            &[],
        )
        .map_err(|error| WriteFuzzError::ValidRefused {
            path: self.path(WriteKind::Insert),
            error: Box::new(error),
        })?;
        self.report.accepted += 1;
        Ok(id)
    }

    /// Each envelope value outside its stored form, on the insert (beside valid fields) and on the
    /// update; an update that gives the id is refused whatever the id.
    fn refuse_envelopes(&mut self, id: Id) -> Result<(), WriteFuzzError> {
        for case in self.envelope_cases() {
            let fields = self.valid_fields();
            self.refuse(WriteKind::Insert, id, &fields, std::slice::from_ref(&case))?;
            let column = ENVELOPE
                .iter()
                .find(|column| column.name == case.column)
                .expect("an envelope column");
            let case = if column.primary_key {
                Case::envelope(
                    column,
                    "an update that gives the id",
                    case.value.clone().unwrap_or(Value::Null),
                    Expected::IdChanged,
                )
            } else {
                case
            };
            self.refuse(WriteKind::Update, id, &[], &[case])?;
        }
        let label_column = |wanted| {
            ENVELOPE
                .iter()
                .find(|column| rule(column.name) == Some(wanted))
                .expect("the envelope has both labels")
        };
        let below = [
            Case::envelope(
                label_column(EnvelopeRule::Taint),
                "a taint above the text label",
                Value::Text(Taint::External.as_str().into()),
                Expected::Envelope,
            ),
            Case::envelope(
                label_column(EnvelopeRule::TextTaint),
                "a text label below the taint",
                Value::Text(TextTaint::Trusted.as_str().into()),
                Expected::Envelope,
            ),
        ];
        let fields = self.valid_fields();
        self.refuse(WriteKind::Insert, id, &fields, &below)?;
        self.refuse(WriteKind::Update, id, &[], &below)?;
        let id_column = ENVELOPE
            .iter()
            .find(|column| column.primary_key)
            .expect("the envelope has an id");
        let valid_id = Value::Blob(self.rng.id().to_bytes().to_vec());
        let case = Case::envelope(
            id_column,
            "an update that gives a valid id",
            valid_id,
            Expected::IdChanged,
        );
        self.refuse(WriteKind::Update, id, &[], &[case])
    }

    /// The values of each envelope column outside its stored form, by the column's rule.
    fn envelope_cases(&mut self) -> Vec<Case> {
        let mut cases = Vec::new();
        for column in ENVELOPE {
            if column.not_null {
                cases.push(Case::envelope(
                    column,
                    "null for a required envelope column",
                    Value::Null,
                    Expected::Invalid(ValueError::Null),
                ));
            }
            let other_class = Expected::Invalid(ValueError::StorageClass {
                expected: column.sql_type,
            });
            for value in [
                Value::Integer(1),
                Value::Text("1".into()),
                Value::Blob(vec![1]),
                Value::Real(1.0),
            ] {
                let same = matches!(
                    (&value, column.sql_type),
                    (Value::Integer(_), SqlType::Integer)
                        | (Value::Text(_), SqlType::Text)
                        | (Value::Blob(_), SqlType::Blob)
                );
                if !same {
                    cases.push(Case::envelope(
                        column,
                        "an envelope value of another class",
                        value,
                        other_class,
                    ));
                }
            }
            let bytes = self.rng.id().to_bytes();
            let mut other_version = bytes;
            other_version[6] = (other_version[6] & 0x0f) | 0x40;
            let malformed: Vec<(&'static str, Value, Expected)> = match rule(column.name) {
                Some(EnvelopeRule::Id | EnvelopeRule::Author) => [
                    vec![1, 2],
                    vec![0; 16],
                    other_version.to_vec(),
                    bytes[..15].to_vec(),
                ]
                .into_iter()
                .map(|bytes| {
                    (
                        "an id that is not a 16-byte UUIDv7",
                        Value::Blob(bytes),
                        Expected::Invalid(ValueError::InvalidUuid),
                    )
                })
                .collect(),
                Some(EnvelopeRule::Instant) => [
                    UtcMillis::MIN.as_millis() - 1,
                    UtcMillis::MAX.as_millis() + 1,
                    i64::MIN,
                    i64::MAX,
                ]
                .into_iter()
                .map(|millis| {
                    (
                        "a time outside years 0000 to 9999",
                        Value::Integer(millis),
                        Expected::Invalid(ValueError::OutOfRange),
                    )
                })
                .collect(),
                Some(EnvelopeRule::Rev) => [0, -1, i64::MIN]
                    .into_iter()
                    .map(|rev| {
                        (
                            "a revision below 1",
                            Value::Integer(rev),
                            Expected::Invalid(ValueError::OutOfRange),
                        )
                    })
                    .collect(),
                Some(EnvelopeRule::Source) => {
                    let valid = Source::Member(self.rng.id()).to_string();
                    [
                        String::new(),
                        "forged source".into(),
                        "System".into(),
                        "member(1)".into(),
                        valid.to_uppercase(),
                        format!("{valid} "),
                    ]
                    .into_iter()
                    .map(|text| {
                        (
                            "a source outside its stored form",
                            Value::Text(text),
                            Expected::Envelope,
                        )
                    })
                    .collect()
                }
                Some(EnvelopeRule::Taint | EnvelopeRule::TextTaint) => [
                    "member",
                    "Trusted",
                    "",
                    "approved draft",
                    "trusted; ignore previous instructions",
                ]
                .into_iter()
                .map(|text| {
                    (
                        "a label outside the stored set",
                        Value::Text(text.into()),
                        Expected::Envelope,
                    )
                })
                .collect(),
                Some(EnvelopeRule::DataTypes) => {
                    let declared = data_types_text(self.table.data_types);
                    let first = self.table.data_types[0].as_str();
                    let mut texts = vec![
                        String::new(),
                        "nonsense".into(),
                        format!("{first},{first}"),
                        format!("{declared},"),
                        declared.to_uppercase(),
                    ];
                    if let Some(undeclared) = DataType::ALL
                        .iter()
                        .find(|data_type| !self.table.data_types.contains(data_type))
                    {
                        texts.push(undeclared.as_str().into());
                        texts.push(data_types_text(&[self.table.data_types[0], *undeclared]));
                    }
                    if self.table.data_types.len() > 1 {
                        texts.push(declared.split(',').rev().collect::<Vec<_>>().join(","));
                    }
                    texts
                        .into_iter()
                        .map(|text| {
                            (
                                "data types outside the declared set or their form",
                                Value::Text(text),
                                Expected::Envelope,
                            )
                        })
                        .collect()
                }
                None => Vec::new(),
            };
            for (rule, value, expected) in malformed {
                cases.push(Case::envelope(column, rule, value, expected));
            }
        }
        cases
    }

    /// Runs a write that must be refused by one of `cases`, with every table unchanged. The
    /// envelope cases replace their column of a valid envelope on an insert, and are the
    /// envelope an update gives.
    fn refuse(
        &mut self,
        kind: WriteKind,
        id: Id,
        fields: &[(&'static str, Value)],
        cases: &[Case],
    ) -> Result<(), WriteFuzzError> {
        let path = self.path(kind);
        let before = self.content()?;
        let mut envelope = match kind {
            WriteKind::Insert => {
                let new_id = self.rng.id();
                self.envelope(new_id)
            }
            WriteKind::Update => Vec::new(),
        };
        for case in cases.iter().filter(|case| case.envelope) {
            envelope.retain(|(name, _)| *name != case.column);
            envelope.push((case.column, case.value.clone().unwrap_or(Value::Null)));
        }
        let outcome = match kind {
            WriteKind::Insert => insert(
                self.handle,
                self.module,
                self.table.name,
                &envelope,
                fields,
                &[],
            ),
            WriteKind::Update => update(
                self.handle,
                self.module,
                self.table.name,
                id,
                &envelope,
                fields,
                &[],
            ),
        };
        let case = Case::describe(cases);
        match outcome {
            Ok(()) => return Err(WriteFuzzError::Accepted { path, case }),
            Err(error) if !cases.iter().any(|expected| expected.matches(&error)) => {
                return Err(WriteFuzzError::WrongRefusal {
                    path,
                    case,
                    error: Box::new(error),
                });
            }
            Err(_) => {}
        }
        if self.content()? != before {
            return Err(WriteFuzzError::Changed { path, case });
        }
        self.report.refused += 1;
        Ok(())
    }

    /// Every row of every table of the file, the Core's and SQLite's own included, but the Core
    /// tables no handle reads, which the row writer the fuzz test drives never writes: only a
    /// call's transaction journals (Story 3.6).
    fn content(&self) -> Result<Vec<Vec<Vec<SqlValue>>>, WriteFuzzError> {
        let storage = |error| WriteFuzzError::Storage {
            module: self.module.name,
            error: Box::new(RecordError::Storage(error)),
        };
        let schema = self.handle.schema().map_err(storage)?;
        schema
            .tables
            .iter()
            .filter(|table| matches!(table.kind, TableKind::Ordinary | TableKind::Shadow))
            .filter(|table| !CORE_PRIVATE_TABLES.contains(&table.name.as_str()))
            .map(|table| {
                let name = table.name.replace('"', "\"\"");
                self.handle
                    .query_values(&format!("SELECT * FROM \"{name}\""), &[])
                    .map_err(storage)
            })
            .collect()
    }

    /// A valid envelope for the record `id`, in the stored forms of `envelope::check`.
    fn envelope(&mut self, id: Id) -> Vec<(&'static str, Value)> {
        let labels = RecordLabels::of(*self.rng.pick(Taint::ALL), *self.rng.pick(TextTaint::ALL));
        ENVELOPE
            .iter()
            .map(|column| {
                let value = match rule(column.name) {
                    Some(EnvelopeRule::Id) => Value::Blob(id.to_bytes().to_vec()),
                    Some(EnvelopeRule::Author) if self.rng.chance(1, 2) => Value::Null,
                    Some(EnvelopeRule::Author) => Value::Blob(self.rng.id().to_bytes().to_vec()),
                    Some(EnvelopeRule::Source) => {
                        Value::Text(Source::Member(self.rng.id()).to_string())
                    }
                    Some(EnvelopeRule::Taint) => Value::Text(labels.taint().as_str().into()),
                    Some(EnvelopeRule::TextTaint) => {
                        Value::Text(labels.text_taint().as_str().into())
                    }
                    Some(EnvelopeRule::DataTypes) => {
                        Value::Text(data_types_text(self.table.data_types))
                    }
                    Some(EnvelopeRule::Instant) => Value::Integer(self.rng.instant().as_millis()),
                    Some(EnvelopeRule::Rev) => Value::Integer(self.rng.within(1, i64::MAX)),
                    None => Value::Null,
                };
                (column.name, value)
            })
            .collect()
    }

    /// Every field within its declaration, each optional one sometimes left out or `NULL`.
    fn valid_fields(&mut self) -> Vec<(&'static str, Value)> {
        let mut fields = Vec::with_capacity(self.table.fields.len());
        for field in self.table.fields {
            if field.optional && self.rng.chance(1, 4) {
                if self.rng.chance(1, 2) {
                    fields.push((field.name, Value::Null));
                }
                continue;
            }
            let value = self.valid_value(field);
            fields.push((field.name, value));
        }
        fields
    }

    fn valid_value(&mut self, field: &Field) -> Value {
        match field.kind {
            FieldKind::FreeText { max_len } => {
                let max_len = max_len.min(FREE_TEXT_FUZZ_MAX) as usize;
                let len = if self.rng.chance(1, 4) {
                    max_len
                } else {
                    self.rng.index(max_len.min(64) + 1)
                };
                Value::Text(self.rng.text(len))
            }
            FieldKind::Structured(Structured::Enumeration(values)) => {
                Value::Text((*self.rng.pick(values)).into())
            }
            FieldKind::Structured(Structured::Integer { min, max }) => {
                Value::Integer(self.rng.within(min, max))
            }
            FieldKind::Structured(Structured::Date) => {
                Value::Text(self.rng.instant().to_string()[..10].into())
            }
            FieldKind::Structured(Structured::Timestamp) => {
                Value::Integer(self.rng.instant().as_millis())
            }
            FieldKind::Structured(Structured::Uuid) => {
                Value::Blob(self.rng.id().to_bytes().to_vec())
            }
            FieldKind::Structured(Structured::ReviewedVocabulary(vocabulary)) => {
                let confirmed = confirmed_labels(self.labels, vocabulary);
                Value::Text(self.rng.pick(confirmed).clone())
            }
        }
    }

    /// The values outside `field`'s declaration the generator knows for its kind, each with the
    /// refusal it must meet.
    fn invalid_cases(&mut self, field: &Field) -> Vec<Case> {
        let class = field.kind.sql_type();
        let mut cases = Vec::new();
        if !field.optional {
            cases.push(Case::new(
                field,
                "null for a required field",
                Value::Null,
                Expected::Invalid(ValueError::Null),
            ));
        }
        let other_class = Expected::Invalid(ValueError::StorageClass { expected: class });
        let valid = self.valid_value(field);
        for (rule, value) in self.other_classes(&valid) {
            cases.push(Case::new(field, rule, value, other_class));
        }
        match field.kind {
            FieldKind::FreeText { max_len } => {
                let max_len = max_len as usize;
                let character = *self.rng.pick(&['a', 'é', '日', '\u{1f600}']);
                cases.push(Case::new(
                    field,
                    "free text one character too long",
                    Value::Text(character.to_string().repeat(max_len + 1)),
                    Expected::Invalid(ValueError::TooLong { max_len }),
                ));
                let refused = self.rng.refused_character();
                let len = self.rng.index(max_len.min(16) + 1);
                let text = self.rng.text(len);
                let position = self.rng.index(text.chars().count() + 1);
                let mut with_refused: String = text.chars().take(position).collect();
                with_refused.push(refused);
                with_refused.extend(text.chars().skip(position));
                cases.push(Case::new(
                    field,
                    "free text holding a refused character",
                    Value::Text(with_refused),
                    Expected::Invalid(ValueError::InvalidCharacter),
                ));
            }
            FieldKind::Structured(Structured::Enumeration(values)) => {
                let value = *self.rng.pick(values);
                let outside = [
                    format!("{value}x"),
                    format!(" {value}"),
                    format!("{value} "),
                    value.to_uppercase(),
                    value[..value.len() - 1].to_owned(),
                    String::new(),
                    self.rng.any_label(),
                ];
                for text in outside {
                    if !values.contains(&text.as_str()) {
                        cases.push(Case::new(
                            field,
                            "text outside the enumeration",
                            Value::Text(text),
                            Expected::Invalid(ValueError::NotInEnumeration),
                        ));
                    }
                }
            }
            FieldKind::Structured(Structured::Integer { min, max }) => {
                let below = (min > i64::MIN)
                    .then(|| [min - 1, i64::MIN, self.rng.within(i64::MIN, min - 1)]);
                let above = (max < i64::MAX)
                    .then(|| [max + 1, i64::MAX, self.rng.within(max + 1, i64::MAX)]);
                for number in below.into_iter().chain(above).flatten() {
                    cases.push(Case::new(
                        field,
                        "an integer outside the range",
                        Value::Integer(number),
                        Expected::Invalid(ValueError::OutOfRange),
                    ));
                }
            }
            FieldKind::Structured(Structured::Date) => {
                let date = self.rng.instant().to_string()[..10].to_owned();
                let year = &date[..4];
                let outside = [
                    format!("{year}-13-01"),
                    format!("{year}-00-10"),
                    format!("{year}-02-30"),
                    format!("{year}-04-31"),
                    format!("{year}-10-32"),
                    format!("{date}T00:00:00Z"),
                    format!("{date} "),
                    format!("+{date}"),
                    date.replace('-', "/"),
                    date.replace('-', ""),
                    date[..9].to_owned(),
                    String::new(),
                ];
                for text in outside {
                    cases.push(Case::new(
                        field,
                        "text that is not a calendar date",
                        Value::Text(text),
                        Expected::Invalid(ValueError::InvalidDate),
                    ));
                }
            }
            FieldKind::Structured(Structured::Timestamp) => {
                let earliest = UtcMillis::MIN.as_millis();
                let latest = UtcMillis::MAX.as_millis();
                for millis in [earliest - 1, latest + 1, i64::MIN, i64::MAX] {
                    cases.push(Case::new(
                        field,
                        "an instant outside years 0000 to 9999",
                        Value::Integer(millis),
                        Expected::Invalid(ValueError::OutOfRange),
                    ));
                }
            }
            FieldKind::Structured(Structured::Uuid) => {
                let bytes = self.rng.id().to_bytes();
                let mut other_version = bytes;
                other_version[6] = (other_version[6] & 0x0f) | 0x40;
                let mut other_variant = bytes;
                other_variant[8] &= 0x3f;
                let mut longer = bytes.to_vec();
                longer.push(0);
                let outside = [
                    other_version.to_vec(),
                    other_variant.to_vec(),
                    bytes[..15].to_vec(),
                    longer,
                    Vec::new(),
                ];
                for bytes in outside {
                    cases.push(Case::new(
                        field,
                        "bytes that are not a 16-byte UUIDv7",
                        Value::Blob(bytes),
                        Expected::Invalid(ValueError::InvalidUuid),
                    ));
                }
            }
            FieldKind::Structured(Structured::ReviewedVocabulary(vocabulary)) => {
                let confirmed = confirmed_labels(self.labels, vocabulary);
                let label = self.rng.pick(confirmed).clone();
                let mut unconfirmed = vec![label.to_uppercase(), label.to_lowercase()];
                unconfirmed.push(self.rng.any_label());
                for (other, labels) in self.labels {
                    if *other != vocabulary {
                        unconfirmed.extend(labels.iter().cloned());
                    }
                }
                for text in unconfirmed {
                    if check_vocabulary_label(&text).is_ok() && !confirmed.contains(&text) {
                        cases.push(Case::new(
                            field,
                            "a label no adult confirmed",
                            Value::Text(text),
                            Expected::Unconfirmed,
                        ));
                    }
                }
                let longest = confirmed
                    .iter()
                    .find(|label| label.chars().count() == VOCABULARY_LABEL_MAX_LEN)
                    .cloned()
                    .unwrap_or_else(|| self.rng.label(VOCABULARY_LABEL_MAX_LEN));
                cases.push(Case::new(
                    field,
                    "a label one character too long",
                    Value::Text(format!("{longest}x")),
                    Expected::Invalid(ValueError::TooLong {
                        max_len: VOCABULARY_LABEL_MAX_LEN,
                    }),
                ));
                let position = self.rng.index(label.chars().count() + 1);
                for inserted in [
                    "_", ":", ".", "\"", "\n", "\0", "\u{301}", "\u{200b}", "\u{202e}",
                ] {
                    let mut text: String = label.chars().take(position).collect();
                    text.push_str(inserted);
                    text.extend(label.chars().skip(position));
                    if text.chars().count() <= VOCABULARY_LABEL_MAX_LEN {
                        cases.push(Case::new(
                            field,
                            "a label outside the restricted alphabet",
                            Value::Text(text),
                            Expected::Invalid(ValueError::InvalidLabel),
                        ));
                    }
                }
                for text in [format!(" {label}"), format!("{label} "), String::new()] {
                    if text.chars().count() <= VOCABULARY_LABEL_MAX_LEN {
                        cases.push(Case::new(
                            field,
                            "a label with a separator at an end",
                            Value::Text(text),
                            Expected::Invalid(ValueError::InvalidLabel),
                        ));
                    }
                }
            }
        }
        cases
    }

    /// The valid value in each storage class but its own: its text, its bytes, its number, a
    /// real number. A value of another class is refused even when it reads as a valid one.
    fn other_classes(&mut self, valid: &Value) -> Vec<(&'static str, Value)> {
        let as_text = match valid {
            Value::Integer(number) => number.to_string(),
            Value::Blob(bytes) => <[u8; 16]>::try_from(bytes.as_slice())
                .ok()
                .and_then(|bytes| Id::from_bytes(bytes).ok())
                .map_or_else(|| self.rng.text(8), |id| id.to_string()),
            Value::Text(text) => text.clone(),
            Value::Null | Value::Real(_) => self.rng.text(8),
        };
        let as_number = match valid {
            Value::Integer(number) => *number,
            Value::Text(text) => text.parse().unwrap_or_else(|_| self.rng.number()),
            _ => self.rng.number(),
        };
        let candidates = [
            (
                "text where another class is declared",
                Value::Text(as_text.clone()),
            ),
            (
                "bytes where another class is declared",
                Value::Blob(as_text.into_bytes()),
            ),
            (
                "an integer where another class is declared",
                Value::Integer(as_number),
            ),
            // An integral value as a float, which a conversion would turn into the integer.
            (
                "a real number, which no field accepts",
                Value::Real(as_number as f64),
            ),
        ];
        candidates
            .into_iter()
            .filter(|(_, value)| !same_class(value, valid))
            .collect()
    }
}

/// The labels confirmed for `vocabulary` in the fuzzed file.
fn confirmed_labels<'a>(
    labels: &'a [(&'static str, Vec<String>)],
    vocabulary: &str,
) -> &'a [String] {
    labels
        .iter()
        .find(|(declared, _)| *declared == vocabulary)
        .map(|(_, confirmed)| confirmed.as_slice())
        .unwrap_or_default()
}

fn same_class(left: &Value, right: &Value) -> bool {
    core::mem::discriminant(left) == core::mem::discriminant(right)
}

/// Replaces in `fields` the value of each case's field, or removes it for a case without one.
fn apply(fields: &mut Vec<(&'static str, Value)>, cases: &[Case]) {
    for case in cases {
        fields.retain(|(name, _)| *name != case.column);
        if let Some(value) = &case.value {
            fields.push((case.column, value.clone()));
        }
    }
}

/// A seeded SplitMix64 sequence.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A uniform index in `0..len`; `len` is not 0. The modulo bias does not matter here.
    fn index(&mut self, len: usize) -> usize {
        // The generator's lengths are small, far below u64::MAX.
        (self.next() % len as u64) as usize
    }

    fn chance(&mut self, numerator: u64, denominator: u64) -> bool {
        self.next() % denominator < numerator
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.index(items.len())]
    }

    fn number(&mut self) -> i64 {
        self.next() as i64
    }

    /// An integer in `min..=max`, often one of the two bounds.
    fn within(&mut self, min: i64, max: i64) -> i64 {
        match self.next() % 4 {
            0 => min,
            1 => max,
            _ => {
                let span = (i128::from(max) - i128::from(min) + 1) as u128;
                let offset = u128::from(self.next()) << 64 | u128::from(self.next());
                // `min + offset % span` lies in `min..=max`, so it fits an i64.
                (i128::from(min) + (offset % span) as i128) as i64
            }
        }
    }

    fn instant(&mut self) -> UtcMillis {
        let millis = self.within(UtcMillis::MIN.as_millis(), UtcMillis::MAX.as_millis());
        UtcMillis::from_millis(millis).expect("an instant of the range")
    }

    fn id(&mut self) -> Id {
        let created_at = self.within(0, UtcMillis::MAX.as_millis());
        let mut random = [0; 10];
        random[..8].copy_from_slice(&self.next().to_le_bytes());
        random[8..].copy_from_slice(&self.next().to_le_bytes()[..2]);
        Id::new_v7(
            UtcMillis::from_millis(created_at).expect("an instant of the range"),
            random,
        )
        .expect("an instant after the Unix epoch")
    }

    /// `len` characters of free text: ASCII, accented and CJK letters, an emoji and its joiner,
    /// a combining accent, quotes, a tab and a line feed.
    fn text(&mut self, len: usize) -> String {
        const POOL: &[char] = &[
            'a',
            'Z',
            '0',
            ' ',
            '\'',
            '"',
            ';',
            '\n',
            '\t',
            'é',
            'Œ',
            'ß',
            '日',
            '\u{1f600}',
            '\u{200d}',
            '\u{301}',
        ];
        debug_assert!(
            POOL.iter()
                .all(|character| is_free_text_character(*character))
        );
        (0..len).map(|_| *self.pick(POOL)).collect()
    }

    /// A character free text refuses, drawn from the controls and format characters below
    /// U+2070 and the byte order mark.
    fn refused_character(&mut self) -> char {
        let refused: Vec<char> = ('\0'..='\u{2070}')
            .chain(['\u{feff}'])
            .filter(|character| !is_free_text_character(*character))
            .collect();
        *self.pick(&refused)
    }

    /// A label of the restricted alphabet, of `len` characters.
    fn label(&mut self, len: usize) -> String {
        let letters: Vec<char> = ('\0'..='\u{17f}')
            .filter(|character| is_vocabulary_label_letter(*character))
            .collect();
        let mut label = String::new();
        let mut previous_is_letter = false;
        for position in 0..len {
            let inner = position > 0 && position + 1 < len;
            if inner && previous_is_letter && self.chance(1, 5) {
                label.push(*self.pick(VOCABULARY_LABEL_SEPARATORS));
                previous_is_letter = false;
            } else {
                label.push(*self.pick(&letters));
                previous_is_letter = true;
            }
        }
        debug_assert_eq!(check_vocabulary_label(&label), Ok(()));
        label
    }

    /// A label of the restricted alphabet, of any length allowed.
    fn any_label(&mut self) -> String {
        let len = 1 + self.index(VOCABULARY_LABEL_MAX_LEN);
        self.label(len)
    }
}
