//! Action tiers, named as `doc/capability-matrix.md` writes them in its Tier column.

closed_set! {
    /// The tier of an action (glossary of `doc/README.md`).
    pub enum Tier {
        /// Tier 0: a read.
        Read => "0",
        /// Tier 1: a reversible write.
        ReversibleWrite => "1",
        /// Tier 2: an irreversible or third-party effect.
        Irreversible => "2",
        /// Tier H: a human-only action, never a tool (spine AD-8).
        HumanOnly => "H",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{from_str, to_json};

    #[test]
    fn tiers_use_the_capability_matrix_names() {
        let names: Vec<&str> = Tier::ALL.iter().map(|tier| tier.as_str()).collect();
        assert_eq!(names, ["0", "1", "2", "H"]);
        for tier in Tier::ALL {
            assert_eq!(to_json(tier), Ok(format!("\"{tier}\"")));
            assert_eq!(from_str::<Tier>(tier.as_str()), Ok(*tier));
        }
        for refused in ["h", "3", "tier 1", ""] {
            assert!(from_str::<Tier>(refused).is_err(), "{refused:?}");
        }
    }
}
