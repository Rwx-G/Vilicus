//! Domain separation of derivations: labels whose encodings are prefix-free, context parts with
//! their lengths (review of Story 4.1, finding 1).

use super::*;
use crate::test_support::hex;

fn key_from(bytes: [u8; crate::KEY_LEN]) -> SymmetricKey {
    let mut slot = Slot::zeroed();
    slot.with_bytes_mut(|out| *out = bytes);
    SymmetricKey::from_slot(slot)
}

fn same_key(left: &SymmetricKey, right: &SymmetricKey) -> bool {
    left.slot()
        .with_bytes(|left| right.slot().with_bytes(|right| left == right))
}

fn info(label: Label, context: &[&[u8]]) -> Vec<u8> {
    let mut lengths = Vec::new();
    info_parts(label, context, &mut lengths)
        .expect("info")
        .concat()
}

#[test]
fn a_label_is_versioned_named_and_printable() {
    assert_eq!(
        Label::new("vilicus/v1/db/").map(Label::as_str),
        Ok("vilicus/v1/db/")
    );
    for (text, refusal) in [
        ("", LabelError::Unversioned),
        ("vilicus/v", LabelError::Unversioned),
        ("vilicus/v2/db/", LabelError::Unversioned),
        ("Vilicus/v1/db/", LabelError::Unversioned),
        ("vilicus/v1/", LabelError::NoName),
        ("vilicus/v1/db file", LabelError::InvalidByte),
        ("vilicus/v1/db\0", LabelError::InvalidByte),
        ("vilicus/v1/db\u{e9}", LabelError::InvalidByte),
    ] {
        assert_eq!(Label::new(text), Err(refusal), "{text:?}");
    }
}

/// No encoded label is a prefix of another, the shorter label included.
#[test]
fn encoded_labels_are_prefix_free() {
    let labels = [
        label!("vilicus/v1/db"),
        label!("vilicus/v1/db/"),
        label!("vilicus/v1/db/tasks"),
        label!("vilicus/v1/hk/confirm"),
        label!("vilicus/v1/hk/confirm-key/"),
    ];
    for left in labels {
        for right in labels.iter().copied().filter(|right| *right != left) {
            let (left_bytes, right_bytes) = (left.encoded().concat(), right.encoded().concat());
            assert!(
                !right_bytes.starts_with(&left_bytes),
                "{left:?} is a prefix of {right:?}"
            );
        }
    }
}

#[test]
fn the_info_is_the_label_its_end_byte_then_each_part_with_its_length() {
    assert_eq!(
        info(label!("vilicus/v1/x/"), &[b"ab", b"", b"c"]),
        [
            b"vilicus/v1/x/".as_slice(),
            &[0x00],
            &[0x00, 0x02],
            b"ab",
            &[0x00, 0x00],
            &[0x00, 0x01],
            b"c"
        ]
        .concat()
    );
    assert_eq!(info(label!("vilicus/v1/x/"), &[]), b"vilicus/v1/x/\0");
    let longest = vec![7; usize::from(u16::MAX)];
    assert!(info_parts(label!("vilicus/v1/x/"), &[&longest], &mut Vec::new()).is_ok());
    let longer = vec![7; usize::from(u16::MAX) + 1];
    let root = SymmetricKey::generate().expect("generate");
    assert!(matches!(
        derive_key(&root, label!("vilicus/v1/x/"), &[&longer]),
        Err(CryptoError::ContextPartTooLong { len }) if len == longer.len()
    ));
}

/// A label and the parts of a context.
type Derivation<'a> = (Label, &'a [&'a [u8]]);

/// The collisions the review found, and the empty-part cases: each pair now derives two keys.
#[test]
fn no_two_labels_and_contexts_derive_the_same_key() {
    let root = SymmetricKey::generate().expect("generate");
    let pairs: [(Derivation, Derivation); 4] = [
        (
            (label!("vilicus/v1/db"), &[b"/tasks"]),
            (label!("vilicus/v1/db/"), &[b"tasks"]),
        ),
        (
            (label!("vilicus/v1/x/"), &[b"ab", b"c"]),
            (label!("vilicus/v1/x/"), &[b"a", b"bc"]),
        ),
        (
            (label!("vilicus/v1/x/"), &[]),
            (label!("vilicus/v1/x/"), &[b""]),
        ),
        (
            (label!("vilicus/v1/x/"), &[b"", b"a"]),
            (label!("vilicus/v1/x/"), &[b"a", b""]),
        ),
    ];
    for ((left_label, left_context), (right_label, right_context)) in pairs {
        assert_ne!(
            info(left_label, left_context),
            info(right_label, right_context)
        );
        let left = derive_key(&root, left_label, left_context).expect("derive");
        let right = derive_key(&root, right_label, right_context).expect("derive");
        assert!(
            !same_key(&left, &right),
            "{left_label:?} {left_context:?} and {right_label:?} {right_context:?}"
        );
    }
}

/// `derive_key` against a vector computed with Python's `hmac` and `hashlib` over the documented
/// `info` layout, an implementation independent of aws-lc-rs.
#[test]
fn derive_key_matches_a_known_answer() {
    let parent = key_from(core::array::from_fn(|index| {
        u8::try_from(index).expect("small")
    }));
    let derived = derive_key(
        &parent,
        label!("vilicus/v1/test/"),
        &[b"member-0001", &7_u32.to_be_bytes()],
    )
    .expect("derive");
    derived.slot().with_bytes(|bytes| {
        assert_eq!(
            bytes.to_vec(),
            hex("d5411e35d39fdbb3bb240a87df44e332aa1a960e32bca5814ba4b0a0ae3d9dd2")
        );
    });
}
