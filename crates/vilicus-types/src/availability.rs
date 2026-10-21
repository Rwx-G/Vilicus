//! The availability state of a module file (spine AD-54): what every caller of a module, the
//! event bus and unlock read from the Core instead of guessing whether a file can serve.

use crate::error::RetryClass;

closed_set! {
    /// Where one module file of one partition stands (spine AD-54). Only [`Ready`](Self::Ready)
    /// serves: every other state answers a typed API call with `module_unavailable` and the retry
    /// class of [`retry_class`](Self::retry_class), and keeps the events due to the module's
    /// consumers in their source outbox, without counting a failed delivery (AD-29).
    pub enum AvailabilityState {
        /// The partition key is not in memory.
        Locked => "locked",
        /// The keys are derived and the file is being opened and checked.
        Opening => "opening",
        /// The file is being re-keyed after a rotation or a sub-key revocation.
        ReKeying => "re_keying",
        /// A migration is running on a copy of the file (AD-23).
        Migrating => "migrating",
        /// The file serves.
        Ready => "ready",
        /// A migration of the file failed: the previous file is kept and the module is stopped
        /// for this partition until a forward release (AD-23, D84).
        FailedMigration => "failed_migration",
        /// A handler, undo handler or consumer of the module panicked or exceeded its time
        /// budget on this file (AD-9).
        Faulted => "faulted",
        /// The module is an activatable module that is off for this scope (AD-47).
        Deactivated => "deactivated",
        /// The file's schema is newer than the module's code (D21).
        NewerThanCode => "newer_than_code",
    }
}

impl AvailabilityState {
    /// The retry class a typed API call to a file in this state is answered with, alongside
    /// `module_unavailable`: `retryable` while the file is on its way to serving, `not_retryable`
    /// once it waits for something other than time (a forward release, an adult, an activation);
    /// `None` for [`Ready`](Self::Ready), which serves.
    pub const fn retry_class(self) -> Option<RetryClass> {
        match self {
            Self::Ready => None,
            Self::Locked | Self::Opening | Self::ReKeying | Self::Migrating => {
                Some(RetryClass::Retryable)
            }
            Self::FailedMigration | Self::Faulted | Self::Deactivated | Self::NewerThanCode => {
                Some(RetryClass::NotRetryable)
            }
        }
    }

    /// True for a state that does not end by itself: the events due to a consumer in it are
    /// dead-lettered once they outlive the outbox's retention, so the outbox does not grow
    /// without bound behind a consumer that may never return (D150). The states a file passes
    /// through on its way to serving are never lasting.
    pub const fn is_lasting(self) -> bool {
        matches!(self.retry_class(), Some(RetryClass::NotRetryable))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{from_str, to_json};

    /// Spine AD-54's table, the independent statement the closed set is checked against: each
    /// state with the retry class of its typed API calls, `None` for the one that serves.
    const AD_54: [(&str, Option<&str>); 9] = [
        ("locked", Some("retryable")),
        ("opening", Some("retryable")),
        ("re_keying", Some("retryable")),
        ("migrating", Some("retryable")),
        ("ready", None),
        ("failed_migration", Some("not_retryable")),
        ("faulted", Some("not_retryable")),
        ("deactivated", Some("not_retryable")),
        ("newer_than_code", Some("not_retryable")),
    ];

    /// D150's lasting states, stated independently of the retry classes they follow from.
    const D150_LASTING: [&str; 4] = [
        "deactivated",
        "faulted",
        "failed_migration",
        "newer_than_code",
    ];

    #[test]
    fn the_states_and_their_retry_classes_are_those_of_ad_54() {
        let stated: Vec<(&str, Option<&str>)> = AvailabilityState::ALL
            .iter()
            .map(|state| {
                (
                    state.as_str(),
                    state.retry_class().map(|class| class.as_str()),
                )
            })
            .collect();
        assert_eq!(stated, AD_54);
        for state in AvailabilityState::ALL {
            assert_eq!(to_json(state), Ok(format!("\"{state}\"")));
            assert_eq!(from_str::<AvailabilityState>(state.as_str()), Ok(*state));
        }
        for refused in ["Ready", "re-keying", "failed migration", ""] {
            assert!(
                from_str::<AvailabilityState>(refused).is_err(),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn the_lasting_states_are_those_of_d150() {
        let mut lasting: Vec<&str> = AvailabilityState::ALL
            .iter()
            .filter(|state| state.is_lasting())
            .map(|state| state.as_str())
            .collect();
        lasting.sort_unstable();
        let mut expected = D150_LASTING;
        expected.sort_unstable();
        assert_eq!(lasting, expected);
    }
}
