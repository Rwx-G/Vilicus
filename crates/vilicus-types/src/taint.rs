//! Taint: the stored labels of a record, of its structured fields and of its free text (spine
//! AD-6), and the per-viewer view the Core computes at read time (spine AD-7).

use core::fmt;

use crate::id::Id;

closed_set! {
    /// The taint stored with a record. `member` is not a stored value: it exists only as a
    /// read-time view, [`EffectiveTaint`], which cannot be converted back to this type or
    /// deserialized as it, so a stored record can never carry it.
    pub enum Taint {
        /// Written or approved by a member, or by the Core from trusted inputs.
        Trusted => "trusted",
        /// Came from outside the household, or derived from an `external` or `member` input.
        External => "external",
    }
}

/// The taint of a record as one viewer sees it, computed by the Core at read time: a `trusted`
/// record authored by another member reads as `member` (`doc/architecture.md` section 5.4, rule
/// 4). The order is `trusted` < `member` < `external`, so the most restrictive of several is
/// their maximum.
///
/// It is a view, never stored: it converts from [`Taint`] and not back, and it implements neither
/// `Serialize` nor `Deserialize`, so it can reach neither a stored record nor a stored taint.
///
/// ```compile_fail,E0277
/// fn stored_as<T: serde::Serialize>() {}
/// stored_as::<vilicus_types::EffectiveTaint>();
/// ```
///
/// ```compile_fail,E0277
/// fn read_from_storage<T: serde::de::DeserializeOwned>() {}
/// read_from_storage::<vilicus_types::EffectiveTaint>();
/// ```
///
/// ```compile_fail,E0277
/// let stored: vilicus_types::Taint = vilicus_types::EffectiveTaint::Member.into();
/// ```
///
/// The same lines compile for the stored type, so the three refusals above come from
/// `EffectiveTaint` alone:
///
/// ```
/// fn stored_as<T: serde::Serialize>() {}
/// fn read_from_storage<T: serde::de::DeserializeOwned>() {}
/// stored_as::<vilicus_types::Taint>();
/// read_from_storage::<vilicus_types::Taint>();
/// let view: vilicus_types::EffectiveTaint = vilicus_types::Taint::Trusted.into();
/// let stored: vilicus_types::Taint = vilicus_types::Taint::Trusted.into();
/// # let _ = (view, stored);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EffectiveTaint {
    /// Trusted for this viewer.
    Trusted,
    /// Written by another member: quoted data for this viewer, whose free text taints a session.
    Member,
    /// External content.
    External,
}

impl EffectiveTaint {
    /// The taint a record stored `stored` and written by `author` has for `viewer`, the member a
    /// read or a derivation acts for (`doc/architecture.md` section 5.4, rule 4): a `trusted`
    /// record authored by a member other than the viewer reads as `member`. With no viewer, every
    /// `trusted` record a member authored is another member's. A record without an author keeps
    /// its stored label.
    ///
    /// ```
    /// use vilicus_types::{EffectiveTaint, Id, Taint};
    ///
    /// let ella: Id = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f".parse()?;
    /// let noe: Id = "017f22e2-79b0-7cc3-98c4-dc0c0c07398e".parse()?;
    /// let trusted = EffectiveTaint::for_viewer(Taint::Trusted, Some(ella), Some(ella));
    /// assert_eq!(trusted, EffectiveTaint::Trusted);
    /// let quoted = EffectiveTaint::for_viewer(Taint::Trusted, Some(ella), Some(noe));
    /// assert_eq!(quoted, EffectiveTaint::Member);
    /// # Ok::<(), vilicus_types::IdError>(())
    /// ```
    pub fn for_viewer(stored: Taint, author: Option<Id>, viewer: Option<Id>) -> Self {
        match (stored, author) {
            (Taint::Trusted, Some(author)) if viewer != Some(author) => Self::Member,
            _ => stored.into(),
        }
    }

    /// The name of this view value, for display.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Member => "member",
            Self::External => "external",
        }
    }
}

closed_set! {
    /// The stored label of a record's free text, read together with its structured fields: never
    /// below the record's [`Taint`], and the record's label when a reader or a derivation takes
    /// all of it (spine AD-6). Ordered `trusted` < `approved_draft` < `external`.
    ///
    /// `approved_draft` is `external` for every purpose but one: a member-approved assistant
    /// draft from a tainted session reaches a planner as quoted data within its maximum length,
    /// where other `external` free text reaches it only as typed reader output (D99, D104). A
    /// record whose free text mixes an approved draft with any other `external` text is
    /// `external`.
    pub enum TextTaint {
        /// Written by a member, or computed from `trusted` inputs.
        Trusted => "trusted",
        /// Holds an assistant draft a member approved from a tainted session, and no other
        /// `external` text.
        ApprovedDraft => "approved_draft",
        /// Came from outside the household, from a model no member approved, or derived from an
        /// `external` or `member` input.
        External => "external",
    }
}

impl TextTaint {
    /// The stored label this one counts as wherever no approved draft is told apart: an
    /// approved draft is `external` (D99).
    pub const fn as_taint(self) -> Taint {
        match self {
            Self::Trusted => Taint::Trusted,
            Self::ApprovedDraft | Self::External => Taint::External,
        }
    }

    /// The most restrictive of two labels.
    pub const fn most_restrictive(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Trusted => 0,
            Self::ApprovedDraft => 1,
            Self::External => 2,
        }
    }
}

impl From<Taint> for TextTaint {
    fn from(taint: Taint) -> Self {
        match taint {
            Taint::Trusted => Self::Trusted,
            Taint::External => Self::External,
        }
    }
}

/// The two stored labels of a record (spine AD-6): `taint`, the label of its structured fields,
/// and `text_taint`, the label of the record read with its free text, which is never below
/// `taint`, so the stricter of the two is always `text_taint`. A member's approval of an
/// assistant request from a tainted session stores its structured fields `trusted` while the
/// drafted free text keeps an `external` label (D99, I9, I35).
///
/// ```
/// use vilicus_types::{EffectiveTaint, Id, Projection, RecordLabels, Taint, TextTaint};
///
/// let ella: Id = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f".parse()?;
/// let approved = RecordLabels::of(Taint::Trusted, TextTaint::ApprovedDraft);
/// let structured = approved.for_viewer(Some(ella), Some(ella), Projection::Structured);
/// assert_eq!(structured, EffectiveTaint::Trusted);
/// let with_text = approved.for_viewer(Some(ella), Some(ella), Projection::WithFreeText);
/// assert_eq!(with_text, EffectiveTaint::External);
/// assert!(approved.is_approved_draft());
/// assert!(RecordLabels::new(Taint::External, TextTaint::Trusted).is_none());
/// # Ok::<(), vilicus_types::IdError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecordLabels {
    taint: Taint,
    text_taint: TextTaint,
}

/// What a read or a derivation takes of a record, which decides the label it sees.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Projection {
    /// Structured fields only: the record's `taint`.
    Structured,
    /// Free text too, or the whole record: the stricter label, `text_taint`.
    WithFreeText,
}

impl RecordLabels {
    /// Both labels `trusted`.
    pub const TRUSTED: Self = Self {
        taint: Taint::Trusted,
        text_taint: TextTaint::Trusted,
    };

    /// Both labels `external`.
    pub const EXTERNAL: Self = Self {
        taint: Taint::External,
        text_taint: TextTaint::External,
    };

    /// The labels as stored; `None` when `text_taint` is below `taint`, which no record holds.
    pub fn new(taint: Taint, text_taint: TextTaint) -> Option<Self> {
        (text_taint.most_restrictive(taint.into()) == text_taint)
            .then_some(Self { taint, text_taint })
    }

    /// The labels of a record whose structured fields are `structured` and whose free text alone
    /// is `free_text`: its `text_taint` is the stricter of the two.
    pub fn of(structured: Taint, free_text: TextTaint) -> Self {
        Self {
            taint: structured,
            text_taint: free_text.most_restrictive(structured.into()),
        }
    }

    /// The label of the record's structured fields.
    pub const fn taint(self) -> Taint {
        self.taint
    }

    /// The label of the record read with its free text.
    pub const fn text_taint(self) -> TextTaint {
        self.text_taint
    }

    /// The label of the whole record, the stricter of the two, as a derivation from it counts it
    /// (spine AD-7).
    pub const fn overall(self) -> Taint {
        self.text_taint.as_taint()
    }

    /// True when the record's only `external` free text is assistant drafts a member approved,
    /// which a planner may read as quoted data (D104).
    pub const fn is_approved_draft(self) -> bool {
        matches!(self.text_taint, TextTaint::ApprovedDraft)
    }

    /// The most restrictive labels of two, label by label: what an update that never lowers a
    /// record's labels stores.
    pub const fn most_restrictive(self, other: Self) -> Self {
        let taint = match (self.taint, other.taint) {
            (Taint::Trusted, Taint::Trusted) => Taint::Trusted,
            _ => Taint::External,
        };
        Self {
            taint,
            text_taint: self.text_taint.most_restrictive(other.text_taint),
        }
    }

    /// The effective taint a read of `projection` of this record, written by `author`, has for
    /// `viewer` ([`EffectiveTaint::for_viewer`]): structured fields read as `taint`, free text as
    /// `text_taint`, an approved draft as `external`.
    pub fn for_viewer(
        self,
        author: Option<Id>,
        viewer: Option<Id>,
        projection: Projection,
    ) -> EffectiveTaint {
        let stored = match projection {
            Projection::Structured => self.taint,
            Projection::WithFreeText => self.overall(),
        };
        EffectiveTaint::for_viewer(stored, author, viewer)
    }
}

impl From<Taint> for EffectiveTaint {
    fn from(stored: Taint) -> Self {
        match stored {
            Taint::Trusted => Self::Trusted,
            Taint::External => Self::External,
        }
    }
}

impl fmt::Display for EffectiveTaint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{from_str, to_json};

    #[test]
    fn stored_taint_is_trusted_or_external_only() {
        let names: Vec<&str> = Taint::ALL.iter().map(|taint| taint.as_str()).collect();
        assert_eq!(names, ["trusted", "external"]);
        for taint in Taint::ALL {
            assert_eq!(to_json(taint), Ok(format!("\"{taint}\"")));
            assert_eq!(from_str::<Taint>(taint.as_str()), Ok(*taint));
        }
    }

    #[test]
    fn member_is_refused_as_stored_taint() {
        assert!(from_str::<Taint>(EffectiveTaint::Member.as_str()).is_err());
        for refused in ["Trusted", "EXTERNAL", "", "untrusted", "trusted "] {
            assert!(from_str::<Taint>(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn view_keeps_the_stored_label_and_adds_member() {
        for taint in Taint::ALL {
            assert_eq!(EffectiveTaint::from(*taint).as_str(), taint.as_str());
        }
        assert_eq!(EffectiveTaint::Member.to_string(), "member");
    }

    #[test]
    fn another_members_trusted_record_reads_as_member() {
        let ella = Id::parse("017f22e2-79b0-7cc3-98c4-dc0c0c07398f").expect("an id");
        let noe = Id::parse("017f22e2-79b0-7cc3-98c4-dc0c0c07398e").expect("an id");
        let view = EffectiveTaint::for_viewer;
        assert_eq!(
            view(Taint::Trusted, Some(ella), Some(ella)),
            EffectiveTaint::Trusted
        );
        assert_eq!(
            view(Taint::Trusted, Some(ella), Some(noe)),
            EffectiveTaint::Member
        );
        assert_eq!(
            view(Taint::Trusted, Some(ella), None),
            EffectiveTaint::Member
        );
        for viewer in [Some(ella), Some(noe), None] {
            assert_eq!(view(Taint::Trusted, None, viewer), EffectiveTaint::Trusted);
            for author in [Some(ella), Some(noe), None] {
                assert_eq!(
                    view(Taint::External, author, viewer),
                    EffectiveTaint::External
                );
            }
        }
    }

    #[test]
    fn text_taint_is_trusted_approved_draft_or_external() {
        let names: Vec<&str> = TextTaint::ALL.iter().map(|taint| taint.as_str()).collect();
        assert_eq!(names, ["trusted", "approved_draft", "external"]);
        for refused in ["member", "Trusted", "approved draft", ""] {
            assert!(from_str::<TextTaint>(refused).is_err(), "{refused:?}");
        }
        for taint in Taint::ALL {
            assert_eq!(TextTaint::from(*taint).as_str(), taint.as_str());
            assert_eq!(TextTaint::from(*taint).as_taint(), *taint);
        }
        assert_eq!(TextTaint::ApprovedDraft.as_taint(), Taint::External);
    }

    /// The order is `trusted` < `approved_draft` < `external`, whichever side each stands on.
    #[test]
    fn text_taint_order_is_trusted_draft_external() {
        let order = TextTaint::ALL;
        for (low, low_label) in order.iter().enumerate() {
            for (high, high_label) in order.iter().enumerate() {
                let expected = order[low.max(high)];
                assert_eq!(low_label.most_restrictive(*high_label), expected);
            }
        }
    }

    /// `text_taint` is never below `taint`: the stored pairs below it are refused, and `of`
    /// raises the free text's label to the structured fields'.
    #[test]
    fn text_taint_is_never_below_taint() {
        let mut held = Vec::new();
        for taint in Taint::ALL {
            for text_taint in TextTaint::ALL {
                let below = TextTaint::from(*taint).most_restrictive(*text_taint) != *text_taint;
                let labels = RecordLabels::new(*taint, *text_taint);
                assert_eq!(labels.is_none(), below, "{taint} {text_taint}");
                if let Some(labels) = labels {
                    assert_eq!(labels.taint(), *taint);
                    assert_eq!(labels.text_taint(), *text_taint);
                    assert_eq!(labels.overall(), text_taint.as_taint());
                    held.push(labels);
                }
                let raised = RecordLabels::of(*taint, *text_taint);
                assert_eq!(raised.taint(), *taint);
                assert_eq!(
                    raised.text_taint(),
                    text_taint.most_restrictive((*taint).into())
                );
            }
        }
        assert_eq!(held.len(), 4, "every pair but the two below their taint");
        assert!(RecordLabels::new(Taint::External, TextTaint::ApprovedDraft).is_none());
        assert_eq!(
            RecordLabels::new(Taint::Trusted, TextTaint::Trusted),
            Some(RecordLabels::TRUSTED)
        );
        assert_eq!(
            RecordLabels::new(Taint::External, TextTaint::External),
            Some(RecordLabels::EXTERNAL)
        );
    }

    /// A reader of structured fields sees `taint`; a reader of free text sees `text_taint`, an
    /// approved draft as `external`; another member's `trusted` labels read as `member`.
    #[test]
    fn a_reader_sees_the_label_of_what_it_reads() {
        let ella = Id::parse("017f22e2-79b0-7cc3-98c4-dc0c0c07398f").expect("an id");
        let noe = Id::parse("017f22e2-79b0-7cc3-98c4-dc0c0c07398e").expect("an id");
        let draft = RecordLabels::of(Taint::Trusted, TextTaint::ApprovedDraft);
        let own = |labels: RecordLabels, projection| {
            labels.for_viewer(Some(ella), Some(ella), projection)
        };
        assert_eq!(own(draft, Projection::Structured), EffectiveTaint::Trusted);
        assert_eq!(
            own(draft, Projection::WithFreeText),
            EffectiveTaint::External
        );
        assert!(draft.is_approved_draft());
        assert!(!RecordLabels::EXTERNAL.is_approved_draft());
        let model_text = RecordLabels::of(Taint::Trusted, TextTaint::External);
        assert_eq!(
            own(model_text, Projection::Structured),
            EffectiveTaint::Trusted
        );
        assert_eq!(
            own(model_text, Projection::WithFreeText),
            EffectiveTaint::External
        );
        for projection in [Projection::Structured, Projection::WithFreeText] {
            assert_eq!(
                RecordLabels::TRUSTED.for_viewer(Some(noe), Some(ella), projection),
                EffectiveTaint::Member
            );
        }
        assert_eq!(
            draft.for_viewer(Some(noe), Some(ella), Projection::Structured),
            EffectiveTaint::Member
        );
    }

    /// Label by label, the most restrictive: an update storing it never lowers either label.
    #[test]
    fn labels_combine_label_by_label() {
        let draft = RecordLabels::of(Taint::Trusted, TextTaint::ApprovedDraft);
        let model_text = RecordLabels::of(Taint::Trusted, TextTaint::External);
        assert_eq!(draft.most_restrictive(RecordLabels::TRUSTED), draft);
        assert_eq!(draft.most_restrictive(model_text), model_text);
        assert_eq!(
            RecordLabels::TRUSTED.most_restrictive(RecordLabels::EXTERNAL),
            RecordLabels::EXTERNAL
        );
        for left in [
            RecordLabels::TRUSTED,
            draft,
            model_text,
            RecordLabels::EXTERNAL,
        ] {
            for right in [
                RecordLabels::TRUSTED,
                draft,
                model_text,
                RecordLabels::EXTERNAL,
            ] {
                let combined = left.most_restrictive(right);
                assert_eq!(combined, right.most_restrictive(left));
                assert_eq!(
                    RecordLabels::new(combined.taint(), combined.text_taint()),
                    Some(combined),
                    "a combination is a stored pair"
                );
            }
        }
    }

    #[test]
    fn view_order_is_trusted_member_external() {
        assert!(EffectiveTaint::Trusted < EffectiveTaint::Member);
        assert!(EffectiveTaint::Member < EffectiveTaint::External);
        let most_restrictive = [EffectiveTaint::Member, EffectiveTaint::Trusted]
            .into_iter()
            .max();
        assert_eq!(most_restrictive, Some(EffectiveTaint::Member));
    }
}
