//! AC3 of Story 4.1: every key buffer is wiped when it is dropped, read through the test-only
//! hook [`wiped`].

use vilicus_types::{Id, UtcMillis};

use super::*;
use crate::{Kdf, KekDerivation, Label, WrapParams, Wrapper, derive_key};

const LABEL: Label = Label::new("vilicus/v1/test/");

fn params() -> WrapParams {
    WrapParams {
        kdf: Kdf::None,
        kek_derivation: KekDerivation::Direct,
        kek_reference: Vec::new(),
        created_at: UtcMillis::UNIX_EPOCH,
        id: Id::new_v7(UtcMillis::UNIX_EPOCH, [1; 10]).expect("id"),
    }
}

/// Drops `key` and returns what the hook saw of its buffer: its address before the drop, and
/// the buffer's bytes once wiped.
fn dropped(key: SymmetricKey) -> (usize, Vec<(usize, [u8; KEY_LEN])>) {
    let (address, bytes) = key
        .slot()
        .with_bytes(|bytes| (bytes.as_ptr().addr(), *bytes));
    assert_ne!(bytes, [0; KEY_LEN], "the key held bytes before the drop");
    wiped::take();
    drop(key);
    (address, wiped::take())
}

#[test]
fn every_key_wipes_its_buffer_when_dropped() {
    let generated = SymmetricKey::generate().expect("generate");
    let derived = derive_key(&generated, LABEL, &[b"context"]).expect("derive");
    let kek = SymmetricKey::generate().expect("generate");
    let wrapper = Wrapper::wrap_key(&kek, &derived, params(), b"context").expect("wrap");
    let unwrapped = wrapper.unwrap_key(&kek, b"context").expect("unwrap");
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
    wiped::take();
    let wrapper = Wrapper::wrap_key(&kek, &key, params(), b"context").expect("wrap");
    let seen = wiped::take();
    assert_eq!(seen.len(), 1, "the seal's working buffer");
    assert_eq!(seen[0].1, [0; KEY_LEN]);

    let other = SymmetricKey::generate().expect("generate");
    wiped::take();
    assert!(matches!(
        wrapper.unwrap_key(&other, b"context"),
        Err(CryptoError::Open)
    ));
    let seen = wiped::take();
    assert_eq!(seen.len(), 1, "the buffer the refused open wrote into");
    assert_eq!(seen[0].1, [0; KEY_LEN]);
}
