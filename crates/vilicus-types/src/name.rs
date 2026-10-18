//! Grammars of the short ASCII names the vocabulary carries: module names, error codes and
//! message keys. A name outside its grammar is refused, never normalized, so one name has one
//! spelling and none can carry free text.

use core::fmt;

/// Longest module name accepted.
pub(crate) const MODULE_NAME_MAX_LEN: usize = 32;

/// Longest error code or message key accepted.
pub(crate) const DOTTED_NAME_MAX_LEN: usize = 64;

/// A name refused because it is outside the grammar of its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameError {
    kind: &'static str,
}

impl NameError {
    pub(crate) const fn new(kind: &'static str) -> Self {
        Self { kind }
    }
}

impl fmt::Display for NameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "not a valid {}", self.kind)
    }
}

impl std::error::Error for NameError {}

/// A module name: a lowercase ASCII letter, then lowercase ASCII letters and digits, as in the
/// crate name `vilicus-mod-<module>` and the tool prefix `<module>.` of the spine conventions.
pub(crate) const fn is_module_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > MODULE_NAME_MAX_LEN || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut index = 1;
    while index < bytes.len() {
        if !(bytes[index].is_ascii_lowercase() || bytes[index].is_ascii_digit()) {
            return false;
        }
        index += 1;
    }
    true
}

/// A dotted name: segments separated by single dots, each a lowercase ASCII letter followed by
/// lowercase ASCII letters, digits or underscores.
pub(crate) const fn is_dotted_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > DOTTED_NAME_MAX_LEN {
        return false;
    }
    let mut at_segment_start = true;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if at_segment_start {
            if !byte.is_ascii_lowercase() {
                return false;
            }
            at_segment_start = false;
        } else if byte == b'.' {
            at_segment_start = true;
        } else if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_') {
            return false;
        }
        index += 1;
    }
    !at_segment_start
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_names_follow_their_grammar() {
        for accepted in ["meals", "familydocs", "home", "a", "mod2"] {
            assert!(is_module_name(accepted), "{accepted}");
        }
        let longest = "a".repeat(MODULE_NAME_MAX_LEN);
        assert!(is_module_name(&longest));
        let too_long = "a".repeat(MODULE_NAME_MAX_LEN + 1);
        for refused in [
            "",
            "Meals",
            "2meals",
            "family-docs",
            "family_docs",
            "meals.plan",
            "m\u{e9}als",
            " meals",
            &too_long,
        ] {
            assert!(!is_module_name(refused), "{refused:?}");
        }
    }

    #[test]
    fn dotted_names_follow_their_grammar() {
        for accepted in [
            "policy.denied",
            "error.policy.token_expired",
            "a",
            "a.b2.c_d",
        ] {
            assert!(is_dotted_name(accepted), "{accepted}");
        }
        let longest = "a".repeat(DOTTED_NAME_MAX_LEN);
        assert!(is_dotted_name(&longest));
        let too_long = "a".repeat(DOTTED_NAME_MAX_LEN + 1);
        for refused in [
            "",
            ".policy",
            "policy.",
            "policy..denied",
            "policy._denied",
            "policy.2denied",
            "Policy.denied",
            "policy denied",
            "policy-denied",
            "the token expired.",
            &too_long,
        ] {
            assert!(!is_dotted_name(refused), "{refused:?}");
        }
    }
}
