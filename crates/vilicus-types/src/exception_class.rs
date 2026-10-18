//! The named exception classes of invariant I13 (`doc/ai-safety.md`; spine AD-48).

closed_set! {
    /// An exception to the rule that an outbound network effect is tier 2. A tool declares at
    /// most one; the registry build check refuses any other value (spine AD-48).
    pub enum ExceptionClass {
        /// Outbound state that can be reverted, such as cart preparation (D44).
        ReversibleExternalState => "reversible_external_state",
        /// A home action undone by restoring the previous state (D56).
        RestorablePhysical => "restorable_physical",
        /// A write to an account the member owns that nobody else sees (D67, D81).
        OwnAccountDelivery => "own_account_delivery",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{from_str, to_json};

    /// Invariant I13 and spine AD-48; the independent statement the closed set is checked against.
    const I13_CLASSES: [&str; 3] = [
        "reversible_external_state",
        "restorable_physical",
        "own_account_delivery",
    ];

    #[test]
    fn exception_classes_are_the_closed_set_of_i13() {
        let names: Vec<&str> = ExceptionClass::ALL
            .iter()
            .map(|class| class.as_str())
            .collect();
        assert_eq!(names, I13_CLASSES);
        for class in ExceptionClass::ALL {
            assert_eq!(to_json(class), Ok(format!("\"{class}\"")));
            assert_eq!(from_str::<ExceptionClass>(class.as_str()), Ok(*class));
        }
        for refused in [
            "system_notification",
            "ReversibleExternalState",
            "reversible-external-state",
            "",
        ] {
            assert!(from_str::<ExceptionClass>(refused).is_err(), "{refused:?}");
        }
    }
}
