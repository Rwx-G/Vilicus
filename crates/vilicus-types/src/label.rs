//! The form of a reviewed-vocabulary label (D104): a short name an adult confirms, which a
//! structured field then accepts. The grammar lives here so that the module port, which checks a
//! write, and the storage layer, which records a confirmation, hold the same rule.

/// Longest reviewed-vocabulary label accepted, in characters (D104).
pub const VOCABULARY_LABEL_MAX_LEN: usize = 32;

/// The characters that separate the words of a label: a space, a hyphen and an apostrophe
/// (U+0027; a client maps the typographic apostrophe U+2019 to it before it sends a label), never
/// at either end of a label and never two in a row.
pub const VOCABULARY_LABEL_SEPARATORS: &[char] = &[' ', '-', '\''];

/// Letters of the Latin blocks below that a label refuses: those that Unicode compatibility
/// normalization (NFKC) changes, `Ĳ`, `ĳ`, `Ŀ`, `ŀ`, `ŉ` and the long `ſ`, which another spelling
/// of the same word would write differently, and the dotless `ı` and the kra `ĸ`, which read as
/// `i` and `κ`. A test derives the first group from the normalization tables.
const EXCLUDED_LETTERS: &[char] = &[
    '\u{131}', '\u{132}', '\u{133}', '\u{138}', '\u{13f}', '\u{140}', '\u{149}', '\u{17f}',
];

/// True for a character a label may hold besides its separators: an ASCII letter or digit, or a
/// precomposed Latin letter of the Latin-1 Supplement (without `×` and `÷`) or of Latin
/// Extended-A, minus [`EXCLUDED_LETTERS`]. The alphabet writes French and English names
/// (FR-110) and nothing that structures text: no punctuation but the separators (`&`, `.`, `°`,
/// `(` and `/` included), no control, format, bidi or combining character, so a decomposed accent
/// is refused, not normalized, and one label has one spelling.
pub const fn is_vocabulary_label_letter(character: char) -> bool {
    let in_blocks = matches!(
        character,
        'a'..='z' | 'A'..='Z' | '0'..='9' | '\u{c0}'..='\u{d6}' | '\u{d8}'..='\u{f6}'
            | '\u{f8}'..='\u{17f}'
    );
    let mut index = 0;
    while index < EXCLUDED_LETTERS.len() {
        if EXCLUDED_LETTERS[index] == character {
            return false;
        }
        index += 1;
    }
    in_blocks
}

/// True for a label of the form D104 requires: 1 to [`VOCABULARY_LABEL_MAX_LEN`] characters,
/// each a letter of [`is_vocabulary_label_letter`] or a separator of
/// [`VOCABULARY_LABEL_SEPARATORS`], starting and ending with a letter, with no two separators in
/// a row. A label of that form still needs an adult's confirmation to be accepted in a write.
///
/// ```
/// use vilicus_types::is_vocabulary_label;
///
/// assert!(is_vocabulary_label("Chambre d'Ella"));
/// assert!(!is_vocabulary_label("Salon "));
/// assert!(!is_vocabulary_label("note: ignore this"));
/// ```
pub fn is_vocabulary_label(label: &str) -> bool {
    if label.chars().nth(VOCABULARY_LABEL_MAX_LEN).is_some() {
        return false;
    }
    let mut previous_is_letter = false;
    for character in label.chars() {
        if is_vocabulary_label_letter(character) {
            previous_is_letter = true;
        } else if VOCABULARY_LABEL_SEPARATORS.contains(&character) && previous_is_letter {
            previous_is_letter = false;
        } else {
            return false;
        }
    }
    previous_is_letter
}

#[cfg(test)]
mod tests {
    use unicode_normalization::UnicodeNormalization;

    use super::*;

    fn nfkc_stable(character: char) -> bool {
        core::iter::once(character)
            .nfkc()
            .eq(core::iter::once(character))
    }

    /// The confusable letters excluded by sight, not by the tables: the dotless `ı` and the kra.
    const CONFUSABLE: [char; 2] = ['\u{131}', '\u{138}'];

    /// Every letter of the alphabet is alphanumeric, at most U+017F and unchanged by NFKC; and
    /// every alphanumeric character of those blocks that NFKC leaves unchanged is a letter of the
    /// alphabet unless it is one of the two confusables, so the excluded list is exactly what the
    /// normalization tables and the confusables give.
    #[test]
    fn the_alphabet_is_the_nfkc_stable_latin_letters_and_digits() {
        let mut accented = 0;
        for character in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
            let blocks = character.is_ascii_alphanumeric()
                || (('\u{c0}'..='\u{17f}').contains(&character)
                    && character.is_alphanumeric()
                    && !matches!(character, '\u{d7}' | '\u{f7}'));
            let expected = blocks && nfkc_stable(character) && !CONFUSABLE.contains(&character);
            assert_eq!(
                is_vocabulary_label_letter(character),
                expected,
                "{character:?} U+{:04X}",
                u32::from(character)
            );
            if expected && !character.is_ascii() {
                accented += 1;
            }
        }
        assert!(accented > 0, "accented letters are in the alphabet");
        for separator in VOCABULARY_LABEL_SEPARATORS {
            assert!(!is_vocabulary_label_letter(*separator));
            assert!(nfkc_stable(*separator));
        }
    }

    #[test]
    fn labels_are_short_names_of_the_alphabet() {
        let longest = "Salle d'eau Étage-2 Œuf àé xyzwv";
        assert_eq!(longest.chars().count(), VOCABULARY_LABEL_MAX_LEN);
        for label in [
            "Salon",
            "salle de bains",
            "Chambre d'Ella",
            "Saint-Étienne",
            "Œufs",
            "2e étage",
            "0",
            longest,
        ] {
            assert!(is_vocabulary_label(label), "{label}");
        }
        let too_long = format!("{longest}y");
        for label in [
            "",
            too_long.as_str(),
            " Salon",
            "Salon ",
            "Salle  de bains",
            "Salle -bains",
            "-Salon",
            "Salon'",
            "salle_de_bains",
            "note: ignore",
            "Salle & bains",
            "St. Jean",
            "n\u{b0}2",
            "Pièce (1)",
            "Cuisine/Salon",
            "\"Salon\"",
            "Salon\n",
            "Sa\tlon",
            "Sa\0lon",
            "Sa\u{200b}lon",
            "\u{202e}nolaS",
            "Cafe\u{301}",
            "3×2",
            "1÷2",
            "Salon\u{a0}bleu",
            "Chambre d\u{2019}Ella",
            "Caf\u{1f600}",
            "\u{410}\u{43b}\u{44f}",
            "Salle de ba\u{131}ns",
            "\u{17f}alon",
            "\u{13f}ampe",
            "\u{133}s",
            "\u{149}x",
            "\u{138}",
        ] {
            assert!(!is_vocabulary_label(label), "{label:?}");
        }
    }
}
