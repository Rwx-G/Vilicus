//! AC1 and AC2 of Story 4.1: wrappers made with AES-256-GCM and a fresh nonce, carrying every
//! field of `doc/key-management.md` section 9, and refused when their version or an identifier
//! is unknown or older than accepted.

use vilicus_types::{Id, UtcMillis};

use super::*;

const SALT: [u8; 16] = [0x5a; 16];
const COSTS: Argon2idParams = Argon2idParams {
    memory_kib: 0x0006_0000,
    passes: 3,
    lanes: 4,
};

fn created_at() -> UtcMillis {
    UtcMillis::from_millis(1_793_577_600_123).expect("instant")
}

const PURPOSE: Label = crate::label!("vilicus/v1/wrap/test");

fn id() -> Id {
    Id::new_v7(created_at(), [0x3c; 10]).expect("id")
}

fn params(kdf: Kdf, kek_reference: &[u8]) -> WrapParams {
    WrapParams::new(
        kdf,
        KekDerivation::HkdfSha256,
        kek_reference.to_vec(),
        created_at(),
        id(),
    )
    .expect("params")
}

fn passphrase_params() -> WrapParams {
    params(Kdf::Argon2id(COSTS), &SALT)
}

fn keys() -> (SymmetricKey, SymmetricKey) {
    (
        SymmetricKey::generate().expect("generate"),
        SymmetricKey::generate().expect("generate"),
    )
}

fn same_key(left: &SymmetricKey, right: &SymmetricKey) -> bool {
    left.slot()
        .with_bytes(|left| right.slot().with_bytes(|right| left == right))
}

/// The rows of the encoding table of the crate documentation: each field's name and its width,
/// `None` for the reference, whose width is the length before it.
fn documented_layout() -> Vec<(String, Option<usize>)> {
    let crate_root = include_str!("../lib.rs");
    let table = crate_root
        .split("//! | Field | Bytes |\n//! |---|---|\n")
        .nth(1)
        .expect("the encoding table of the crate documentation");
    table
        .lines()
        .map_while(|line| line.strip_prefix("//! | "))
        .map(|row| {
            let cells: Vec<&str> = row.trim_end_matches(" |").split(" | ").collect();
            let width = if cells[1] == "that length" {
                None
            } else {
                Some(cells[1].parse().expect("a width in bytes"))
            };
            (cells[0].to_string(), width)
        })
        .collect()
}

#[test]
fn the_encoding_is_the_documented_layout() {
    let (kek, key) = keys();
    let nonce = [0xa5; NONCE_LEN];
    let wrapper =
        Wrapper::wrap_key_with_nonce(&kek, &key, PURPOSE, passphrase_params(), nonce, b"context")
            .expect("wrap");
    let encoded = wrapper.to_bytes();

    let id = id().to_bytes();
    let header: Vec<Vec<u8>> = vec![
        FORMAT_VERSION.to_be_bytes().to_vec(),
        KDF_ARGON2ID.to_be_bytes().to_vec(),
        KEK_HKDF_SHA256.to_be_bytes().to_vec(),
        AEAD_AES_256_GCM.to_be_bytes().to_vec(),
        ARGON2_VERSION.to_be_bytes().to_vec(),
        COSTS.memory_kib.to_be_bytes().to_vec(),
        COSTS.passes.to_be_bytes().to_vec(),
        COSTS.lanes.to_be_bytes().to_vec(),
        u16::try_from(SALT.len())
            .expect("short")
            .to_be_bytes()
            .to_vec(),
        SALT.to_vec(),
        created_at().as_millis().to_be_bytes().to_vec(),
        id.to_vec(),
        nonce.to_vec(),
    ];
    // The ciphertext and tag the additional data of the documentation gives: the header, then
    // the context.
    let mut additional_data = header.concat();
    additional_data.extend_from_slice(PURPOSE.as_str().as_bytes());
    additional_data.push(0x00);
    additional_data.extend_from_slice(b"context");
    let mut ciphertext = [0; KEY_LEN];
    key.slot()
        .with_bytes(|bytes| ciphertext.copy_from_slice(bytes));
    let tag = kek
        .slot()
        .with_bytes(|kek| aws_lc::seal_aes_256_gcm(kek, nonce, &additional_data, &mut ciphertext))
        .expect("seal");
    let fields: Vec<Vec<u8>> = [header, vec![ciphertext.to_vec(), tag.to_vec()]].concat();

    let layout = documented_layout();
    assert_eq!(layout.len(), fields.len(), "{layout:?}");
    for ((name, width), field) in layout.iter().zip(&fields) {
        assert_eq!(width.unwrap_or(SALT.len()), field.len(), "{name}");
    }
    assert_eq!(encoded, fields.concat());

    // Without Argon2id, its four rows are absent.
    let plain =
        Wrapper::wrap_key(&kek, &key, PURPOSE, params(Kdf::None, &[]), b"member").expect("wrap");
    let argon2_rows = layout
        .iter()
        .filter(|(name, _)| name.starts_with("Argon2"))
        .count();
    assert_eq!(argon2_rows, 4);
    let documented: usize = layout
        .iter()
        .filter(|(name, _)| !name.starts_with("Argon2"))
        .map(|(_, width)| width.unwrap_or(0))
        .sum();
    assert_eq!(plain.to_bytes().len(), documented);
}

#[test]
fn a_wrapper_carries_every_field_and_reads_back_as_written() {
    let (kek, key) = keys();
    let wrapper =
        Wrapper::wrap_key(&kek, &key, PURPOSE, passphrase_params(), b"member").expect("wrap");
    assert_eq!(wrapper.version(), FORMAT_VERSION);
    assert_eq!(wrapper.kdf(), Kdf::Argon2id(COSTS));
    assert_eq!(wrapper.kek_derivation(), KekDerivation::HkdfSha256);
    assert_eq!(wrapper.aead(), Aead::Aes256Gcm);
    assert_eq!(wrapper.kek_reference(), SALT);
    assert_eq!(wrapper.created_at(), created_at());
    assert_eq!(wrapper.id(), id());

    let read = Wrapper::from_bytes(&wrapper.to_bytes()).expect("read");
    assert_eq!(read, wrapper);
    let opened = read.unwrap_key(&kek, PURPOSE, b"member").expect("open");
    assert!(same_key(&opened, &key));

    let plain =
        Wrapper::wrap_key(&kek, &key, PURPOSE, params(Kdf::None, &[]), b"member").expect("wrap");
    assert_eq!(Wrapper::from_bytes(&plain.to_bytes()).expect("read"), plain);
}

/// AC1: a random 96-bit nonce for each wrap, so wrapping the same key twice under the same KEK
/// gives two nonces and two ciphertexts.
#[test]
fn each_wrap_draws_a_fresh_nonce() {
    let (kek, key) = keys();
    let first =
        Wrapper::wrap_key(&kek, &key, PURPOSE, passphrase_params(), b"member").expect("wrap");
    let second =
        Wrapper::wrap_key(&kek, &key, PURPOSE, passphrase_params(), b"member").expect("wrap");
    assert_ne!(first.nonce, second.nonce);
    assert_ne!(first.ciphertext, second.ciphertext);
    for wrapper in [first, second] {
        assert!(same_key(
            &wrapper.unwrap_key(&kek, PURPOSE, b"member").expect("open"),
            &key
        ));
    }
}

#[test]
fn a_wrapper_opens_only_with_its_kek_its_purpose_and_its_context() {
    let (kek, key) = keys();
    let wrapper =
        Wrapper::wrap_key(&kek, &key, PURPOSE, passphrase_params(), b"member 1").expect("wrap");
    assert!(matches!(
        wrapper.unwrap_key(&key, PURPOSE, b"member 1"),
        Err(CryptoError::Open)
    ));
    assert!(matches!(
        wrapper.unwrap_key(&kek, PURPOSE, b"member 2"),
        Err(CryptoError::Open)
    ));
    assert!(matches!(
        wrapper.unwrap_key(&kek, crate::label!("vilicus/v1/wrap/test2"), b"member 1"),
        Err(CryptoError::Open)
    ));
    assert!(wrapper.unwrap_key(&kek, PURPOSE, b"member 1").is_ok());
}

/// The review's probe: the member DEK wraps both the member private key and the personal inbox
/// private key, for the same member. Stored in each other's place, neither opens for the other's
/// purpose.
#[test]
fn two_keys_wrapped_for_one_record_do_not_open_in_each_others_place() {
    const MEMBER_PRIVATE_KEY: Label = crate::label!("vilicus/v1/wrap/member-private-key");
    const INBOX_PRIVATE_KEY: Label = crate::label!("vilicus/v1/wrap/inbox-private-key");
    let (dek, member_private) = keys();
    let inbox_private = SymmetricKey::generate().expect("generate");
    let member_wrapper = Wrapper::wrap_key(
        &dek,
        &member_private,
        MEMBER_PRIVATE_KEY,
        params(Kdf::None, &[]),
        b"member 1",
    )
    .expect("wrap");
    let inbox_wrapper = Wrapper::wrap_key(
        &dek,
        &inbox_private,
        INBOX_PRIVATE_KEY,
        params(Kdf::None, &[]),
        b"member 1",
    )
    .expect("wrap");
    for (stored, purpose) in [
        (&inbox_wrapper, MEMBER_PRIVATE_KEY),
        (&member_wrapper, INBOX_PRIVATE_KEY),
    ] {
        let swapped = Wrapper::from_bytes(&stored.to_bytes()).expect("read");
        assert!(matches!(
            swapped.unwrap_key(&dek, purpose, b"member 1"),
            Err(CryptoError::Open)
        ));
    }
    let opened = member_wrapper
        .unwrap_key(&dek, MEMBER_PRIVATE_KEY, b"member 1")
        .expect("open");
    assert!(same_key(&opened, &member_private));
}

/// An empty context would let two wrappers of one purpose under one KEK open in each other's
/// place, so it is refused on both sides.
#[test]
fn an_empty_context_is_refused() {
    let (kek, key) = keys();
    assert!(matches!(
        Wrapper::wrap_key(&kek, &key, PURPOSE, passphrase_params(), b""),
        Err(CryptoError::EmptyContext)
    ));
    let wrapper =
        Wrapper::wrap_key(&kek, &key, PURPOSE, passphrase_params(), b"member").expect("wrap");
    assert!(matches!(
        wrapper.unwrap_key(&kek, PURPOSE, b""),
        Err(CryptoError::EmptyContext)
    ));
}

/// Every field is authenticated: an edit of any byte that still reads as a valid wrapper does
/// not open.
#[test]
fn an_edited_wrapper_does_not_open() {
    let (kek, key) = keys();
    let encoded = Wrapper::wrap_key(&kek, &key, PURPOSE, passphrase_params(), b"member")
        .expect("wrap")
        .to_bytes();
    let mut read_back = Vec::new();
    for index in 0..encoded.len() {
        let mut edited = encoded.clone();
        edited[index] ^= 0x01;
        // An edit the reader refuses is the other tests' concern; the rest must not open.
        if let Ok(wrapper) = Wrapper::from_bytes(&edited) {
            read_back.push(index);
            assert!(
                matches!(
                    wrapper.unwrap_key(&kek, PURPOSE, b"member"),
                    Err(CryptoError::Open)
                ),
                "byte {index} edited and still opened"
            );
        }
    }
    // Edited, these still read as a wrapper: the Argon2id costs, the salt, the low bytes of the
    // creation time, and every byte from the wrapper id to the tag.
    let costs = 12..24;
    let salt = 26..26 + SALT.len();
    let low_time = salt.end + 4..salt.end + 8;
    let rest = salt.end + 8..encoded.len();
    for index in costs.chain(salt).chain(low_time).chain(rest) {
        assert!(read_back.contains(&index), "byte {index}");
    }
}

/// AC2: a version newer than this Core writes, or an identifier its version does not define, is
/// refused.
#[test]
fn an_unknown_version_or_identifier_is_refused() {
    let (kek, key) = keys();
    let encoded = Wrapper::wrap_key(&kek, &key, PURPOSE, passphrase_params(), b"member")
        .expect("wrap")
        .to_bytes();
    let with = |offset: usize, value: &[u8]| {
        let mut edited = encoded.clone();
        edited[offset..offset + value.len()].copy_from_slice(value);
        Wrapper::from_bytes(&edited)
    };
    let next_version = FORMAT_VERSION + 1;
    assert_eq!(
        with(0, &next_version.to_be_bytes()),
        Err(WrapperError::UnknownVersion {
            version: next_version
        })
    );
    assert_eq!(
        with(0, &u16::MAX.to_be_bytes()),
        Err(WrapperError::UnknownVersion { version: u16::MAX })
    );
    for id in [0, 3, u16::MAX] {
        assert_eq!(
            with(2, &id.to_be_bytes()),
            Err(WrapperError::UnknownKdf { id })
        );
        assert_eq!(
            with(4, &id.to_be_bytes()),
            Err(WrapperError::UnknownKekDerivation { id })
        );
    }
    for id in [0, 2, u16::MAX] {
        assert_eq!(
            with(6, &id.to_be_bytes()),
            Err(WrapperError::UnknownAead { id })
        );
    }
    for version in [0, 0x10, 0x14] {
        assert_eq!(
            with(8, &u32::to_be_bytes(version)),
            Err(WrapperError::UnknownArgon2Version { version })
        );
    }
}

/// AC2: a version older than the oldest this Core accepts is refused as a downgrade, although
/// the rest of the bytes would read as the current version.
#[test]
fn a_version_older_than_accepted_is_refused_not_downgraded() {
    let (kek, key) = keys();
    let mut encoded = Wrapper::wrap_key(&kek, &key, PURPOSE, passphrase_params(), b"member")
        .expect("wrap")
        .to_bytes();
    for version in 0..OLDEST_ACCEPTED_FORMAT_VERSION {
        encoded[..2].copy_from_slice(&version.to_be_bytes());
        assert_eq!(
            Wrapper::from_bytes(&encoded),
            Err(WrapperError::OlderThanAccepted { version })
        );
    }
}

#[test]
fn a_malformed_encoding_is_refused() {
    let (kek, key) = keys();
    let encoded = Wrapper::wrap_key(&kek, &key, PURPOSE, passphrase_params(), b"member")
        .expect("wrap")
        .to_bytes();
    for len in 0..encoded.len() {
        assert_eq!(
            Wrapper::from_bytes(&encoded[..len]),
            Err(WrapperError::Truncated),
            "{len} bytes"
        );
    }
    let mut longer = encoded.clone();
    longer.push(0);
    assert_eq!(
        Wrapper::from_bytes(&longer),
        Err(WrapperError::TrailingBytes)
    );

    let reference_len = 24;
    let mut edited = encoded.clone();
    let too_long = u16::try_from(MAX_KEK_REFERENCE_LEN + 1).expect("short");
    edited[reference_len..reference_len + 2].copy_from_slice(&too_long.to_be_bytes());
    assert_eq!(
        Wrapper::from_bytes(&edited),
        Err(WrapperError::KekReferenceTooLong {
            len: MAX_KEK_REFERENCE_LEN + 1
        })
    );

    let created = reference_len + 2 + SALT.len();
    let mut edited = encoded.clone();
    edited[created..created + 8].copy_from_slice(&i64::MAX.to_be_bytes());
    assert_eq!(
        Wrapper::from_bytes(&edited),
        Err(WrapperError::InvalidCreationTime)
    );

    let id_version = created + 8 + 6;
    let mut edited = encoded;
    edited[id_version] = 0x40;
    assert_eq!(Wrapper::from_bytes(&edited), Err(WrapperError::InvalidId));
}

#[test]
fn a_kek_reference_over_the_maximum_is_refused_in_the_parameters() {
    let (kek, key) = keys();
    let longest = vec![7; MAX_KEK_REFERENCE_LEN];
    let wrapper = Wrapper::wrap_key(&kek, &key, PURPOSE, params(Kdf::None, &longest), b"member")
        .expect("wrap");
    assert_eq!(
        Wrapper::from_bytes(&wrapper.to_bytes())
            .expect("read")
            .kek_reference(),
        longest
    );
    let longer = vec![7; MAX_KEK_REFERENCE_LEN + 1];
    assert!(matches!(
        WrapParams::new(Kdf::None, KekDerivation::Direct, longer, created_at(), id()),
        Err(CryptoError::KekReferenceTooLong { len }) if len == MAX_KEK_REFERENCE_LEN + 1
    ));
}
