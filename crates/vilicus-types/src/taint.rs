//! Taint: the stored label of a record (spine AD-6) and the per-viewer view the Core computes at
//! read time (spine AD-7).

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
    fn view_order_is_trusted_member_external() {
        assert!(EffectiveTaint::Trusted < EffectiveTaint::Member);
        assert!(EffectiveTaint::Member < EffectiveTaint::External);
        let most_restrictive = [EffectiveTaint::Member, EffectiveTaint::Trusted]
            .into_iter()
            .max();
        assert_eq!(most_restrictive, Some(EffectiveTaint::Member));
    }
}
