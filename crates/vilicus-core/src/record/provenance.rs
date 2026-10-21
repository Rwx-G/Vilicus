//! The provenance the Core stamps on a write (AD-6, AD-7, D45, D70, D99, D103, D104, I9, I21,
//! I35, I43): a record's stored labels, `data_types` and `author`, computed from the [`Call`] and
//! from the records the write is derived from, never chosen by a module or a model.
//!
//! A record has two labels ([`RecordLabels`]): `taint` for its structured fields and `text_taint`
//! for the record read with its free text, never below `taint`. A member's approval stores the
//! structured fields `trusted` while free text drafted in a tainted session keeps an `external`
//! label, `approved_draft` (D99, I9, I35); model text no member approved is `external`, even from
//! a clean session (`doc/architecture.md` section 5.4, rule 2). An update never lowers a label:
//! promoting an `external` record stays with the host CLI (D45, D112), however much of it the
//! update rewrites. And an update that writes no new free text keeps the record's author, while
//! one that does makes the writer the author, so another member's text is never stored as theirs.

use core::fmt;
use std::collections::HashSet;

use vilicus_module_api::{DataType, FieldKind, Table, Value};
use vilicus_types::{EffectiveTaint, Id, Principal, RecordLabels, Taint, TextTaint};

use super::RecordError;
use super::call::{Authority, Call};

/// The length, in words, of a run of the assistant's draft that makes a member-written field
/// `external` when the field repeats it verbatim (D104).
pub const DRAFT_RUN_WORDS: usize = 8;

/// The provenance of a stored record that a write reads: its id, its stored labels, its author,
/// its data types and its free text. The Core reads it from the file in the write transaction,
/// or, for a record of another file, keeps it from the read that served the record to the call;
/// a module never gives one.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordProvenance {
    /// The record's id.
    pub id: Id,
    /// Its stored labels.
    pub labels: RecordLabels,
    /// Its author, if any.
    pub author: Option<Id>,
    /// Its data types.
    pub data_types: Vec<DataType>,
    /// The values of its free-text fields that hold one, which a member's write may not copy
    /// into a `trusted` record when the record is not `trusted` for that member
    /// (`doc/architecture.md` section 5.4, rule 5).
    pub free_text: Vec<String>,
}

/// Leaves the free text out: it is record content (spine conventions, Logging).
impl fmt::Debug for RecordProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordProvenance")
            .field("id", &self.id)
            .field("labels", &self.labels)
            .field("author", &self.author)
            .field("data_types", &self.data_types)
            .field("free_text", &self.free_text.len())
            .finish()
    }
}

impl RecordProvenance {
    /// The label a derivation acting for `viewer` counts this record with: the whole record,
    /// free text included, as `viewer` sees it, a `member` record storing `external` (AD-7).
    fn derived_taint(&self, viewer: Option<Id>) -> Taint {
        stored_taint(EffectiveTaint::for_viewer(
            self.labels.overall(),
            self.author,
            viewer,
        ))
    }
}

/// What an update reads of the record it changes.
pub(crate) struct Stored {
    /// The record's provenance.
    pub(crate) provenance: RecordProvenance,
    /// The values of the record's fields, in declared order.
    pub(crate) held: Vec<Value>,
}

/// The envelope values a write's provenance decides.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Stamp {
    pub(crate) labels: RecordLabels,
    pub(crate) data_types: Vec<DataType>,
    pub(crate) author: Option<Id>,
}

/// True when a write of `call` must declare its inputs: no member made or approved it, and its
/// principal is not one whose writes are content from outside the household, stored `external`
/// whatever their inputs (a plugin, a device adapter).
pub(crate) fn requires_inputs(call: &Call) -> bool {
    matches!(call.authority, Authority::Unapproved { .. }) && !is_outside_content(call.principal)
}

/// The provenance of a write of `fields` into `table` by `call`, derived from `inputs` and, for an
/// update, from the record it changes.
///
/// Data types: a member's own or approved write holds what its kind declares; any other write
/// the union of its inputs' sets, or the kind's set when it has none (a plugin's or an adapter's).
/// Both hold the [`floor`], and an update adds the record's stored set, so a set only grows; a
/// set beyond the kind's declaration is refused, never narrowed (D103).
pub(crate) fn stamp(
    call: &Call,
    table: &'static Table,
    fields: &[(&str, Value)],
    inputs: &[RecordProvenance],
    stored: Option<&Stored>,
) -> Result<Stamp, RecordError> {
    let written = written_labels(call, table, fields, inputs, stored);
    let labels = match stored {
        Some(stored) => written.most_restrictive(stored.provenance.labels),
        None => written,
    };
    let declared = matches!(
        call.authority,
        Authority::OwnAction { .. } | Authority::Approved { .. }
    ) || inputs.is_empty();
    let floor = floor(call, inputs);
    let data_types = union(
        [floor.as_slice()]
            .into_iter()
            .chain(declared.then_some(table.data_types))
            .chain(stored.map(|stored| stored.provenance.data_types.as_slice())),
    );
    if !data_types
        .iter()
        .all(|data_type| table.data_types.contains(data_type))
    {
        return Err(RecordError::UndeclaredDataType { table: table.name });
    }
    let writer = match &call.authority {
        Authority::OwnAction { member } | Authority::Approved { member, .. } => Some(*member),
        Authority::Unapproved { author, .. } => *author,
    };
    let author = match stored {
        Some(stored) if !rewrites_free_text(table, fields, &stored.held) => {
            stored.provenance.author
        }
        _ => writer,
    };
    Ok(Stamp {
        labels,
        data_types,
        author,
    })
}

/// The labels of what the write itself gives, before an update raises them to the record's. An
/// update no member made or approved counts the record it changes as one more input: by its
/// `text_taint` when it gives free text, and by its `taint` when it gives structured fields only,
/// whose label then cannot rise from the record's free text; the record keeps its `text_taint`
/// (an approved draft stays one), raised to the new `taint`. The record named among the inputs
/// too counts this way only.
fn written_labels(
    call: &Call,
    table: &'static Table,
    fields: &[(&str, Value)],
    inputs: &[RecordProvenance],
    stored: Option<&Stored>,
) -> RecordLabels {
    if is_outside_content(call.principal) {
        return RecordLabels::EXTERNAL;
    }
    match &call.authority {
        Authority::OwnAction { member } => {
            let copied = untrusted_text(inputs, *member);
            let text = free_texts(table, fields)
                .map(|text| {
                    if repeats_a_run(text, &copied) {
                        TextTaint::External
                    } else {
                        TextTaint::Trusted
                    }
                })
                .fold(TextTaint::Trusted, TextTaint::most_restrictive);
            RecordLabels::of(Taint::Trusted, text)
        }
        Authority::Approved {
            member,
            written,
            drafts,
        } => {
            let copied = untrusted_text(inputs, *member);
            let text = free_texts(table, fields)
                .map(|text| {
                    if repeats_a_run(text, &copied) {
                        TextTaint::External
                    } else {
                        approved_text_taint(call.session, text, written, drafts)
                    }
                })
                .fold(TextTaint::Trusted, TextTaint::most_restrictive);
            RecordLabels::of(Taint::Trusted, text)
        }
        Authority::Unapproved { acting_for, .. } => {
            let gives_text = free_texts(table, fields).next().is_some();
            let changed = stored.map(|stored| {
                let record = &stored.provenance;
                let counted = if gives_text {
                    record.labels.overall()
                } else {
                    record.labels.taint()
                };
                stored_taint(EffectiveTaint::for_viewer(
                    counted,
                    record.author,
                    *acting_for,
                ))
            });
            let structured = inputs
                .iter()
                .filter(|input| stored.is_none_or(|stored| stored.provenance.id != input.id))
                .map(|input| input.derived_taint(*acting_for))
                .chain(changed)
                .chain(consumes(call).then(|| stored_taint(call.consumed.taint)))
                .fold(call.session, most_restrictive);
            let model_text = call.principal == Principal::AiTask && gives_text;
            let text = if model_text {
                TextTaint::External
            } else {
                structured.into()
            };
            RecordLabels::of(structured, text)
        }
    }
}

/// The data types every write of `call` derived from `inputs` holds whatever else it is: the
/// union of its inputs' sets and, for an AI or plugin session, of what the session consumed.
/// The row writer refuses an envelope below it.
pub(crate) fn floor(call: &Call, inputs: &[RecordProvenance]) -> Vec<DataType> {
    union(
        inputs
            .iter()
            .map(|input| input.data_types.as_slice())
            .chain(consumes(call).then_some(call.consumed.data_types.as_slice())),
    )
}

/// True for the principals whose session's consumption every write of theirs holds (AD-7): an AI
/// task and a plugin, whose inputs are declared by code the model or the plugin drives.
fn consumes(call: &Call) -> bool {
    matches!(call.principal, Principal::AiTask | Principal::Plugin)
}

/// The free text of the inputs that are not `trusted` for `member`: text a member's write may
/// not copy into a record stored `trusted` (`doc/architecture.md` section 5.4, rule 5). An input
/// another member wrote counts, as it does for a derivation (AD-7).
fn untrusted_text(inputs: &[RecordProvenance], member: Id) -> Vec<&str> {
    inputs
        .iter()
        .filter(|input| input.derived_taint(Some(member)) != Taint::Trusted)
        .flat_map(|input| input.free_text.iter().map(String::as_str))
        .collect()
}

/// The union of data type sets, in the order of [`DataType::ALL`].
pub(crate) fn union<'a>(sets: impl IntoIterator<Item = &'a [DataType]>) -> Vec<DataType> {
    let mut held: Vec<DataType> = sets.into_iter().flatten().copied().collect();
    held.sort_by_key(|data_type| DataType::ALL.iter().position(|known| known == data_type));
    held.dedup();
    held
}

/// True when `text` repeats, word for word, a run of [`DRAFT_RUN_WORDS`] consecutive words of one
/// of `sources`, the assistant's drafts or another record's free text (D104): a verbatim test,
/// not an edit ratio, so editing the rest of the text does not matter. Words are the maximal runs
/// of alphanumeric characters, compared in lowercase: spacing, punctuation and case do not break
/// a run.
pub(crate) fn repeats_a_run<S: AsRef<str>>(text: &str, sources: &[S]) -> bool {
    let source_words: Vec<Vec<String>> = sources
        .iter()
        .map(|source| words(source.as_ref()))
        .collect();
    let runs: HashSet<&[String]> = source_words
        .iter()
        .flat_map(|words| words.windows(DRAFT_RUN_WORDS))
        .collect();
    words(text)
        .windows(DRAFT_RUN_WORDS)
        .any(|run| runs.contains(run))
}

fn words(text: &str) -> Vec<String> {
    text.split(|character: char| !character.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// The label of a free text of an approved write (D99, D104): from a tainted session, text
/// drafted, or drafted then edited, is an approved draft, `external` but readable by a planner as
/// quoted data; only text the member wrote in full in an empty field is `trusted`, unless it
/// repeats a run of a draft, which makes it an approved draft too. From a session that is not
/// tainted, the approved text is `trusted`.
fn approved_text_taint(
    session: Taint,
    text: &str,
    written: &[String],
    drafts: &[String],
) -> TextTaint {
    let written_in_full = written.iter().any(|member_text| member_text == text);
    if session == Taint::Trusted || (written_in_full && !repeats_a_run(text, drafts)) {
        TextTaint::Trusted
    } else {
        TextTaint::ApprovedDraft
    }
}

/// True when an update giving `fields` writes free text the record does not hold: a free-text
/// value other than the field's stored one. Only then does the record take the writer as its
/// author: a structured-only edit, or free text given unchanged, keeps the author of the text
/// (D70), and any new text, even appended to the author's own words, is the writer's, so the
/// author's leftover text reads as `member` to them, never theirs as the editor's.
fn rewrites_free_text(table: &'static Table, fields: &[(&str, Value)], held: &[Value]) -> bool {
    table.fields.iter().zip(held).any(|(field, stored)| {
        matches!(field.kind, FieldKind::FreeText { .. })
            && fields.iter().any(|(name, given)| {
                *name == field.name && matches!(given, Value::Text(_)) && given != stored
            })
    })
}

/// The free-text values `fields` gives `table`; a name the table does not declare is the row
/// writer's to refuse.
fn free_texts<'a>(
    table: &'static Table,
    fields: &'a [(&str, Value)],
) -> impl Iterator<Item = &'a str> {
    fields.iter().filter_map(|(name, value)| {
        let field = table.fields.iter().find(|field| field.name == *name)?;
        match (field.kind, value) {
            (FieldKind::FreeText { .. }, Value::Text(text)) => Some(text.as_str()),
            _ => None,
        }
    })
}

/// Content from outside the household: whatever a plugin or a device adapter writes is stored
/// `external`, whatever it claims (AD-7, I21).
fn is_outside_content(principal: Principal) -> bool {
    matches!(principal, Principal::Plugin | Principal::Adapter)
}

/// The stored label of a derived write from an input of effective taint `effective`: any
/// `member` or `external` input stores `external` (AD-7).
fn stored_taint(effective: EffectiveTaint) -> Taint {
    match effective {
        EffectiveTaint::Trusted => Taint::Trusted,
        EffectiveTaint::Member | EffectiveTaint::External => Taint::External,
    }
}

fn most_restrictive(left: Taint, right: Taint) -> Taint {
    if left == Taint::External || right == Taint::External {
        Taint::External
    } else {
        Taint::Trusted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DRAFT: &str = "Buy the organic apples at the market on Saturday morning before ten";

    fn drafts() -> Vec<String> {
        vec![DRAFT.to_owned()]
    }

    #[test]
    fn eight_consecutive_words_of_a_draft_are_a_copy() {
        let eight = "the organic apples at the market on Saturday";
        assert_eq!(eight.split(' ').count(), DRAFT_RUN_WORDS);
        assert!(repeats_a_run(eight, &drafts()));
        assert!(repeats_a_run(
            &format!("Note to self: {eight}, and milk."),
            &drafts()
        ));
        let seven = "the organic apples at the market on";
        assert!(!repeats_a_run(seven, &drafts()));
        assert!(!repeats_a_run("", &drafts()));
        assert!(!repeats_a_run::<&str>(DRAFT, &[]));
    }

    /// Spacing, punctuation and case do not break a run; a word changed or moved does.
    #[test]
    fn a_run_is_compared_word_for_word() {
        assert!(repeats_a_run(
            "THE  organic, apples - at the\nmarket on saturday!",
            &drafts()
        ));
        assert!(!repeats_a_run(
            "the organic pears at the market on Saturday",
            &drafts()
        ));
        assert!(!repeats_a_run(
            "the apples organic at the market on Saturday",
            &drafts()
        ));
    }

    /// Not an edit ratio: a text that keeps almost every word of the draft, but never eight in a
    /// row, is no copy; a text that rewrites almost everything but keeps one run of eight is one.
    #[test]
    fn the_test_is_not_an_edit_ratio() {
        let draft_words: Vec<&str> = DRAFT.split(' ').collect();
        let mostly_kept: Vec<&str> = draft_words
            .iter()
            .enumerate()
            .map(|(index, word)| {
                if index % (DRAFT_RUN_WORDS - 1) == DRAFT_RUN_WORDS - 2 {
                    "x"
                } else {
                    word
                }
            })
            .collect();
        assert!(!repeats_a_run(&mostly_kept.join(" "), &drafts()));
        let mostly_rewritten = format!(
            "{} {} {}",
            "entirely different words written by the member here and there",
            draft_words[1..=DRAFT_RUN_WORDS].join(" "),
            "and many more of their own words after it"
        );
        assert!(repeats_a_run(&mostly_rewritten, &drafts()));
    }

    /// A run is taken from one draft: words that end one draft and start another are not one.
    #[test]
    fn a_run_does_not_span_two_drafts() {
        let two = vec![
            "one two three four".to_owned(),
            "five six seven eight".to_owned(),
        ];
        assert!(!repeats_a_run(
            "one two three four five six seven eight",
            &two
        ));
        assert!(repeats_a_run(
            "one two three four five six seven eight",
            &["one two three four five six seven eight nine".to_owned()]
        ));
    }

    #[test]
    fn non_latin_words_are_words() {
        let draft = "acheter des pommes bio au marché samedi matin avant dix heures";
        assert!(repeats_a_run(
            "Pommes bio au MARCHÉ samedi matin avant dix",
            &[draft.to_owned()]
        ));
    }

    #[test]
    fn the_union_is_in_the_order_of_the_closed_set() {
        let union = union([
            [DataType::Stock, DataType::Health].as_slice(),
            &[DataType::Health, DataType::Budget],
        ]);
        assert_eq!(union, [DataType::Health, DataType::Budget, DataType::Stock]);
    }
}
