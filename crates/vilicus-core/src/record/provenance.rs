//! The provenance the Core stamps on a write (AD-6, AD-7, D70, D99, D103, D104, I9, I21, I35,
//! I43): a record's stored `taint`, `data_types` and `author`, computed from the [`Call`] and
//! from the records the write is derived from, never chosen by a module or a model.
//!
//! A record has one `taint`. A write whose parts carry different labels (structured fields a
//! member approved and free text drafted in a tainted session) stores the most restrictive of
//! them, so no part of a record reads as more trusted than it is; and an update stores at least
//! the record's old label while it keeps fields it does not rewrite.

use std::collections::HashSet;

use vilicus_module_api::{DataType, FieldKind, Table, Value};
use vilicus_types::{EffectiveTaint, Id, Principal, Taint};

use super::RecordError;
use super::call::{Authority, Call};

/// The length, in words, of a run of the assistant's draft that makes a member-written field
/// `external` when the field repeats it verbatim (D104).
pub const DRAFT_RUN_WORDS: usize = 8;

/// The provenance of a stored record that a write reads: its id, its stored taint, its author
/// and its data types. The Core reads it from the file in the write transaction, or, for a record
/// of another file, keeps it from the read that served the record to the call; a module never
/// gives one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordProvenance {
    /// The record's id.
    pub id: Id,
    /// Its stored taint.
    pub taint: Taint,
    /// Its author, if any.
    pub author: Option<Id>,
    /// Its data types.
    pub data_types: Vec<DataType>,
}

/// What an update reads of the record it changes.
pub(crate) struct Stored {
    /// The record's provenance.
    pub(crate) provenance: RecordProvenance,
    /// True when a field the update does not give holds a value, which keeps its old label.
    pub(crate) keeps_content: bool,
}

/// The envelope values a write's provenance decides.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Stamp {
    pub(crate) taint: Taint,
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
pub(crate) fn stamp(
    call: &Call,
    table: &'static Table,
    fields: &[(&str, Value)],
    inputs: &[RecordProvenance],
    stored: Option<&Stored>,
) -> Result<Stamp, RecordError> {
    let taint = if is_outside_content(call.principal) {
        Taint::External
    } else {
        match &call.authority {
            Authority::OwnAction { .. } => kept(Taint::Trusted, stored),
            Authority::Approved {
                written, drafts, ..
            } => {
                let label = |text: &str| approved_text_taint(call.session, text, written, drafts);
                let taint = free_texts(table, fields)
                    .map(label)
                    .fold(Taint::Trusted, most_restrictive);
                kept(taint, stored)
            }
            Authority::Unapproved { acting_for, .. } => inputs
                .iter()
                .chain(stored.map(|stored| &stored.provenance))
                .map(|input| {
                    stored_taint(EffectiveTaint::for_viewer(
                        input.taint,
                        input.author,
                        *acting_for,
                    ))
                })
                .fold(call.session, most_restrictive),
        }
    };
    let derived = if inputs.is_empty() {
        table.data_types.to_vec()
    } else {
        union(inputs.iter().map(|input| input.data_types.as_slice()))
    };
    let data_types = match stored {
        Some(stored) => union([derived.as_slice(), &stored.provenance.data_types]),
        None => derived,
    };
    if !data_types
        .iter()
        .all(|data_type| table.data_types.contains(data_type))
    {
        return Err(RecordError::UndeclaredDataType { table: table.name });
    }
    let author = match &call.authority {
        Authority::OwnAction { member } | Authority::Approved { member, .. } => Some(*member),
        Authority::Unapproved { author, .. } => *author,
    };
    Ok(Stamp {
        taint,
        data_types,
        author,
    })
}

/// The union of data type sets, in the order of [`DataType::ALL`].
pub(crate) fn union<'a>(sets: impl IntoIterator<Item = &'a [DataType]>) -> Vec<DataType> {
    let mut held: Vec<DataType> = sets.into_iter().flatten().copied().collect();
    held.sort_by_key(|data_type| DataType::ALL.iter().position(|known| known == data_type));
    held.dedup();
    held
}

/// True when `text` repeats, word for word, a run of [`DRAFT_RUN_WORDS`] consecutive words of one
/// of `drafts` (D104): a verbatim test, not an edit ratio, so editing the rest of the text does
/// not matter. Words are the maximal runs of alphanumeric characters, compared in lowercase:
/// spacing, punctuation and case do not break a run.
pub(crate) fn copies_draft(text: &str, drafts: &[String]) -> bool {
    let draft_words: Vec<Vec<String>> = drafts.iter().map(|draft| words(draft)).collect();
    let runs: HashSet<&[String]> = draft_words
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

/// The label of a free text of an approved write (D99, D104): text drafted, or drafted then
/// edited, keeps the session's taint; only text the member wrote in full in an empty field is
/// `trusted`, unless it repeats a run of a draft, which is `external` like the draft.
fn approved_text_taint(session: Taint, text: &str, written: &[String], drafts: &[String]) -> Taint {
    let written_in_full = written.iter().any(|member_text| member_text == text);
    if session == Taint::Trusted || (written_in_full && !copies_draft(text, drafts)) {
        Taint::Trusted
    } else {
        Taint::External
    }
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

/// `taint`, raised to the record's old label when the update keeps some of its content.
fn kept(taint: Taint, stored: Option<&Stored>) -> Taint {
    match stored {
        Some(stored) if stored.keeps_content => most_restrictive(taint, stored.provenance.taint),
        _ => taint,
    }
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
        assert!(copies_draft(eight, &drafts()));
        assert!(copies_draft(
            &format!("Note to self: {eight}, and milk."),
            &drafts()
        ));
        let seven = "the organic apples at the market on";
        assert!(!copies_draft(seven, &drafts()));
        assert!(!copies_draft("", &drafts()));
        assert!(!copies_draft(DRAFT, &[]));
    }

    /// Spacing, punctuation and case do not break a run; a word changed or moved does.
    #[test]
    fn a_run_is_compared_word_for_word() {
        assert!(copies_draft(
            "THE  organic, apples - at the\nmarket on saturday!",
            &drafts()
        ));
        assert!(!copies_draft(
            "the organic pears at the market on Saturday",
            &drafts()
        ));
        assert!(!copies_draft(
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
        assert!(!copies_draft(&mostly_kept.join(" "), &drafts()));
        let mostly_rewritten = format!(
            "{} {} {}",
            "entirely different words written by the member here and there",
            draft_words[1..=DRAFT_RUN_WORDS].join(" "),
            "and many more of their own words after it"
        );
        assert!(copies_draft(&mostly_rewritten, &drafts()));
    }

    /// A run is taken from one draft: words that end one draft and start another are not one.
    #[test]
    fn a_run_does_not_span_two_drafts() {
        let two = vec![
            "one two three four".to_owned(),
            "five six seven eight".to_owned(),
        ];
        assert!(!copies_draft(
            "one two three four five six seven eight",
            &two
        ));
        assert!(copies_draft(
            "one two three four five six seven eight",
            &["one two three four five six seven eight nine".to_owned()]
        ));
    }

    #[test]
    fn non_latin_words_are_words() {
        let draft = "acheter des pommes bio au marché samedi matin avant dix heures";
        assert!(copies_draft(
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
