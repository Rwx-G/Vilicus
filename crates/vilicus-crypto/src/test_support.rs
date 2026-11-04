//! Helpers shared by the crate's tests.

/// The bytes of the lowercase hexadecimal `text`.
pub(crate) fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hexadecimal"))
        .collect()
}

/// Hardens the test process and locks its key pool once, as the Core's start does.
pub(crate) fn key_memory() {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        crate::harden_process().expect("hardened");
        match crate::lock_key_memory() {
            Ok(()) | Err(crate::KeyMemoryError::AlreadyLocked) => {}
            Err(error) => panic!("the key pool of the tests: {error}"),
        }
    });
}
