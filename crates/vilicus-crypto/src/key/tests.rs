//! AC3 of Story 4.1: every key buffer is wiped when it is dropped, read through the test-only
//! hook [`wiped`](crate::memory::wiped).

use vilicus_types::{Id, UtcMillis};

use super::*;
use crate::derive::derive_key;
use crate::{Kdf, KekDerivation, Label, WrapParams, Wrapper};

const LABEL: Label = crate::label!("vilicus/v1/test/");
const PURPOSE: Label = crate::label!("vilicus/v1/wrap/test");

fn params() -> WrapParams {
    WrapParams::new(
        Kdf::None,
        KekDerivation::Direct,
        Vec::new(),
        UtcMillis::UNIX_EPOCH,
        Id::new_v7(UtcMillis::UNIX_EPOCH, [1; 10]).expect("id"),
    )
    .expect("params")
}

/// Drops `key` and returns what the hook saw of its buffer: its address before the drop, and
/// the buffer's bytes once wiped.
fn dropped(key: SymmetricKey) -> (usize, Vec<(usize, [u8; KEY_LEN])>) {
    let (address, bytes) = key
        .slot()
        .with_key(|bytes| (bytes.as_ptr().addr(), *bytes))
        .expect("not wiped");
    assert_ne!(bytes, [0; KEY_LEN], "the key held bytes before the drop");
    crate::memory::wiped::take();
    drop(key);
    (address, crate::memory::wiped::take())
}

#[test]
fn every_key_wipes_its_buffer_when_dropped() {
    let generated = SymmetricKey::generate().expect("generate");
    let derived = derive_key(&generated, LABEL, &[b"context"]).expect("derive");
    let kek = SymmetricKey::generate().expect("generate");
    let wrapper = Wrapper::wrap_key(&kek, &derived, PURPOSE, params(), b"context").expect("wrap");
    let unwrapped = wrapper
        .unwrap_key(&kek, PURPOSE, b"context")
        .expect("unwrap");
    for (made_by, key) in [
        ("generate", generated),
        ("derive_key", derived),
        ("unwrap_key", unwrapped),
    ] {
        let (address, seen) = dropped(key);
        assert_eq!(seen, vec![(address, [0; KEY_LEN])], "{made_by}");
    }
}

#[test]
fn the_buffers_of_a_wrap_and_of_a_failed_open_are_wiped() {
    let kek = SymmetricKey::generate().expect("generate");
    let key = SymmetricKey::generate().expect("generate");
    crate::memory::wiped::take();
    let wrapper = Wrapper::wrap_key(&kek, &key, PURPOSE, params(), b"context").expect("wrap");
    let seen = crate::memory::wiped::take();
    assert_eq!(seen.len(), 1, "the seal's working buffer");
    assert_eq!(seen[0].1, [0; KEY_LEN]);

    let other = SymmetricKey::generate().expect("generate");
    crate::memory::wiped::take();
    assert!(matches!(
        wrapper.unwrap_key(&other, PURPOSE, b"context"),
        Err(CryptoError::Open)
    ));
    let seen = crate::memory::wiped::take();
    assert_eq!(seen.len(), 1, "the buffer the refused open wrote into");
    assert_eq!(seen[0].1, [0; KEY_LEN]);
}

/// Review finding 12: the key text is SQLCipher's raw key form of the key, the format
/// `vilicus-storage` keys files with today: `x'`, the 64 lowercase hex digits, `'`.
#[test]
fn the_sqlcipher_key_text_is_the_raw_key_form() {
    let mut slot = Slot::new().expect("slot");
    slot.with_key_mut(|bytes| {
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from(index * 8 + 3).expect("small");
        }
    })
    .expect("not wiped");
    let key = SymmetricKey::from_slot(slot);
    let expected: String = (0..KEY_LEN)
        .map(|index| format!("{:02x}", index * 8 + 3))
        .collect();
    let text = key
        .with_sqlcipher_key_text(<[u8]>::to_vec)
        .expect("a text slot");
    assert_eq!(text, format!("x'{expected}'").into_bytes());
    assert_eq!(text.len(), crate::SQLCIPHER_KEY_TEXT_LEN);
}

#[test]
fn hex_digits_are_lowercase_ascii() {
    for nibble in 0..16_u8 {
        assert_eq!(
            char::from(hex_digit(nibble)),
            char::from_digit(u32::from(nibble), 16).expect("digit"),
            "{nibble}"
        );
    }
}
