//! The principal of a call (spine AD-8).

closed_set! {
    /// Who a call acts as. Each kind is checked against its own authority by the Core (spine
    /// AD-8); a scheduled task acts as [`AiTask`](Principal::AiTask).
    pub enum Principal {
        /// A member's web session.
        Member => "Member",
        /// The administration CLI.
        Cli => "Cli",
        /// An AI task, holding a capability token.
        AiTask => "AiTask",
        /// A plugin, holding a capability token.
        Plugin => "Plugin",
        /// Core event delivery (spine AD-27).
        Event => "Event",
        /// A home rule validated by a human (spine AD-39).
        Rule => "Rule",
        /// A household display (spine AD-40).
        Display => "Display",
        /// A device adapter (spine AD-38).
        Adapter => "Adapter",
        /// A playbook validated by a human (spine AD-45).
        Playbook => "Playbook",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{from_str, to_json};

    /// Spine AD-8; this list is the independent statement the closed set is checked against.
    const AD_8_PRINCIPALS: [&str; 9] = [
        "Member", "Cli", "AiTask", "Plugin", "Event", "Rule", "Display", "Adapter", "Playbook",
    ];

    #[test]
    fn principal_is_the_closed_enum_of_ad_8() {
        let names: Vec<&str> = Principal::ALL
            .iter()
            .map(|principal| principal.as_str())
            .collect();
        assert_eq!(names, AD_8_PRINCIPALS);
        for principal in Principal::ALL {
            assert_eq!(to_json(principal), Ok(format!("\"{principal}\"")));
            assert_eq!(from_str::<Principal>(principal.as_str()), Ok(*principal));
        }
        for refused in ["member", "ai_task", "ScheduledTask", "Root", ""] {
            assert!(from_str::<Principal>(refused).is_err(), "{refused:?}");
        }
    }
}
