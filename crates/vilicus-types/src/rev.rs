//! The revision of a record (spine AD-6, AD-9): what an update names to say which state of the
//! record it changes.

use core::fmt;

/// The revision of a record: 1 when the record is inserted, one more at each update, stamped by
/// the Core. An update names the revision it expects, and the Core refuses it when the stored
/// one differs, so a write never applies to a state its caller did not see (spine AD-9), and an
/// undo is refused once a later write moved the record (spine AD-26).
///
/// Stored as a SQLite `INTEGER`, so its largest value is `i64::MAX`.
///
/// ```
/// use vilicus_types::Rev;
///
/// assert_eq!(Rev::FIRST.get(), 1);
/// assert_eq!(Rev::FIRST.next(), Rev::new(2));
/// assert_eq!(Rev::new(0), None);
/// assert_eq!(Rev::new(i64::MAX).and_then(Rev::next), None);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rev(i64);

impl Rev {
    /// The revision of a record when it is inserted.
    pub const FIRST: Self = Self(1);

    /// The revision `value`; `None` below 1.
    pub const fn new(value: i64) -> Option<Self> {
        if value >= 1 { Some(Self(value)) } else { None }
    }

    /// The revision as stored.
    pub const fn get(self) -> i64 {
        self.0
    }

    /// The revision an update stamps after this one; `None` past `i64::MAX`.
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

impl fmt::Display for Rev {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revisions_start_at_one_and_only_grow() {
        for refused in [0, -1, i64::MIN] {
            assert_eq!(Rev::new(refused), None, "{refused}");
        }
        assert_eq!(Rev::new(1), Some(Rev::FIRST));
        let second = Rev::FIRST.next().expect("2");
        assert!(second > Rev::FIRST);
        assert_eq!(second.get(), 2);
        assert_eq!(second.to_string(), "2");
        assert_eq!(Rev::new(i64::MAX).expect("the largest").next(), None);
    }
}
