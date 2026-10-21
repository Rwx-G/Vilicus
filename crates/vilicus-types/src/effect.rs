//! The outcome of an outbound effect (spine AD-28).

closed_set! {
    /// What a plugin reports of an outbound effect the Core asked it to perform, with the
    /// effect's business idempotency key (spine AD-28). The Core records it in the effect intent
    /// of the module file that wrote it. An `unknown` outcome is reported to the member and never
    /// retried blindly; only the Core retries, with the same key.
    pub enum EffectOutcome {
        /// The effect took place.
        Done => "done",
        /// The effect did not take place.
        Failed => "failed",
        /// Whether the effect took place is not known, such as after a lost connection.
        Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{from_str, to_json};

    /// Spine AD-28; the independent statement the closed set is checked against.
    const AD_28_OUTCOMES: [&str; 3] = ["done", "failed", "unknown"];

    #[test]
    fn effect_outcomes_are_the_three_of_ad_28() {
        let names: Vec<&str> = EffectOutcome::ALL
            .iter()
            .map(|outcome| outcome.as_str())
            .collect();
        assert_eq!(names, AD_28_OUTCOMES);
        for outcome in EffectOutcome::ALL {
            assert_eq!(to_json(outcome), Ok(format!("\"{outcome}\"")));
            assert_eq!(from_str::<EffectOutcome>(outcome.as_str()), Ok(*outcome));
        }
        for refused in ["Done", "pending", "timeout", ""] {
            assert!(from_str::<EffectOutcome>(refused).is_err(), "{refused:?}");
        }
    }
}
