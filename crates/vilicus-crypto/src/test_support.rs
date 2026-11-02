//! Helpers shared by the crate's tests.

/// The bytes of the lowercase hexadecimal `text`.
pub(crate) fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hexadecimal"))
        .collect()
}
