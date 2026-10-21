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

use unicode_normalization::UnicodeNormalization;
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
        Some(stored) if new_free_text(table, fields, Some(stored)).is_empty() => {
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
            let given = new_free_text(table, fields, stored);
            let text = if given.is_empty() {
                TextTaint::Trusted
            } else if repeats_a_run(
                &record_text(table, fields, stored),
                &untrusted_text(inputs, stored, *member),
            ) {
                TextTaint::External
            } else {
                TextTaint::Trusted
            };
            RecordLabels::of(Taint::Trusted, text)
        }
        Authority::Approved {
            member,
            written,
            drafts,
        } => {
            let given = new_free_text(table, fields, stored);
            let record = record_text(table, fields, stored);
            let text = if given.is_empty() {
                TextTaint::Trusted
            } else if repeats_a_run(&record, &untrusted_text(inputs, stored, *member)) {
                TextTaint::External
            } else {
                approved_text_taint(call.session, &given, &record, written, drafts)
            };
            RecordLabels::of(Taint::Trusted, text)
        }
        Authority::Unapproved { acting_for, .. } => {
            let gives_text = !new_free_text(table, fields, stored).is_empty();
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

/// The free text of the inputs, and of the record an update changes, that are not `trusted` for
/// `member`, each record's fields joined into one word sequence: text a member's write may not
/// copy into a record stored `trusted` (`doc/architecture.md` section 5.4, rule 5). A record
/// another member wrote counts, as it does for a derivation (AD-7): an edit that writes new text
/// into it makes the member its author, so 8 of the other member's words it keeps would read as
/// the member's own.
fn untrusted_text(inputs: &[RecordProvenance], stored: Option<&Stored>, member: Id) -> Vec<String> {
    inputs
        .iter()
        .chain(stored.map(|stored| &stored.provenance))
        .filter(|input| input.derived_taint(Some(member)) != Taint::Trusted)
        .map(|input| input.free_text.join("\n"))
        .collect()
}

/// The record's free text once the write is stored, its fields in declared order joined into one
/// word sequence, so a copy split across fields, or across this write and the record's stored
/// text, is still a run (D147): each free-text field the write gives, and the stored value of
/// each it leaves.
fn record_text(table: &'static Table, fields: &[(&str, Value)], stored: Option<&Stored>) -> String {
    table
        .fields
        .iter()
        .enumerate()
        .filter(|(_, field)| matches!(field.kind, FieldKind::FreeText { .. }))
        .filter_map(|(index, field)| {
            let given = fields
                .iter()
                .find(|(name, _)| *name == field.name)
                .map(|(_, value)| value);
            match given.or_else(|| stored.and_then(|stored| stored.held.get(index))) {
                Some(Value::Text(text)) => Some(text.as_str()),
                _ => None,
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
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
/// of alphanumeric characters after NFKC folding, compared in lowercase: spacing, punctuation,
/// case and compatibility forms (fullwidth letters, ligatures) do not break a run. A look-alike
/// from another script and a single changed word do, accepted limits of D104 (D147). The stamp
/// joins a record's fields, an input's fields and a request's drafts into one source each.
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
    let folded: String = text.nfkc().collect();
    folded
        .split(|character: char| !character.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// The label of the free text `given` by an approved write (D99, D104), `record` being the
/// record's free text once stored: from a tainted session, text drafted, or drafted then edited,
/// is an approved draft, `external` but readable by a planner as quoted data; the text is
/// `trusted` only when every value given is one the member wrote in full in an empty field and
/// the record repeats no run of the request's drafts, read as one sequence. From a session that
/// is not tainted, the approved text is `trusted`.
fn approved_text_taint(
    session: Taint,
    given: &[&str],
    record: &str,
    written: &[String],
    drafts: &[String],
) -> TextTaint {
    let written_in_full = given
        .iter()
        .all(|text| written.iter().any(|member_text| member_text == text));
    if session == Taint::Trusted
        || (written_in_full && !repeats_a_run(record, &[drafts.join("\n")]))
    {
        TextTaint::Trusted
    } else {
        TextTaint::ApprovedDraft
    }
}

/// The free-text values `fields` gives `table` that the record does not already hold: every one
/// on insert, and on update each value other than the field's stored one. Only a write giving
/// some is judged as writing text: its labels are computed from it, and an update giving some
/// takes the writer as the record's author. A structured-only edit, or free text given unchanged,
/// keeps the author of the text (D70); any new text, even appended to the author's own words, is
/// the writer's, so the author's leftover text reads as `member` to them.
fn new_free_text<'a>(
    table: &'static Table,
    fields: &'a [(&str, Value)],
    stored: Option<&Stored>,
) -> Vec<&'a str> {
    fields
        .iter()
        .filter_map(|(name, value)| {
            let index = table.fields.iter().position(|field| field.name == *name)?;
            match (table.fields[index].kind, value) {
                (FieldKind::FreeText { .. }, Value::Text(text))
                    if stored.is_none_or(|stored| stored.held.get(index) != Some(value)) =>
                {
                    Some(text.as_str())
                }
                _ => None,
            }
        })
        .collect()
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

    /// NFKC folds compatibility forms before the comparison: fullwidth letters and a ligature are
    /// the words they stand for. A look-alike from another script is not folded (one Cyrillic
    /// `о` here), an accepted limit of D104.
    #[test]
    fn compatibility_forms_are_folded_and_other_scripts_are_not() {
        assert!(repeats_a_run(
            "ｔｈｅ ＯＲＧＡＮＩＣ apples at the market on Saturday",
            &drafts()
        ));
        assert!(repeats_a_run(
            "ﬁne organic apples at the market on Saturday morning",
            &["fine organic apples at the market on Saturday morning"]
        ));
        assert!(!repeats_a_run(
            "the \u{43e}rganic apples at the market on Saturday",
            &drafts()
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
