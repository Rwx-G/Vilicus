//! Error paths and edge behaviours the review relies on (REVIEW.md), each pinned by a test.

mod common;

use common::{CaseRng, QueuedBytes, hex, independent, to_hex};
use hpke::{Deserializable, HpkeError, Kem, OpModeR, OpModeS, Serializable};
use hpke_review::{
    EncappedKey, PrivateKey, Refused, SuiteAead, SuiteKdf, SuiteKem, derive_backup_keypair,
    is_canonical_public_key, open_into, seal,
};
use hpke_rs::HpkePrivateKey;

/// X25519 u-coordinates of small order, encoded with bit 255 clear: 0, 1, the two points of
/// order 8, p - 1, and p and p + 1 (unreduced encodings of 0 and 1). Clamped scalars are
/// multiples of 8, so each yields the all-zero DH output that RFC 9180 section 7.1.4 requires
/// to be refused. `small_order_points` adds each with bit 255 set, which X25519 masks.
const SMALL_ORDER_BIT_255_CLEAR: [&str; 7] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

/// The other entries of the libsodium blocklist: small-order values plus p, which set bit 255.
/// RFC 7748 section 5 masks bit 255 of a u-coordinate before use, so these decode to other,
/// non-small-order points; libsodium refuses them as a policy, RFC 9180 does not require it.
/// Both implementations must treat them alike.
const HIGH_BIT_BLOCKLIST_ENTRIES: [&str; 5] = [
    "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
    "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
    "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];

/// Every small-order encoding: each entry of `SMALL_ORDER_BIT_255_CLEAR`, then the same with
/// bit 255 set.
fn small_order_points() -> Vec<Vec<u8>> {
    let clear: Vec<Vec<u8>> = SMALL_ORDER_BIT_255_CLEAR.iter().map(|p| hex(p)).collect();
    let set: Vec<Vec<u8>> = clear
        .iter()
        .map(|p| {
            let mut q = p.clone();
            q[31] |= 0x80;
            q
        })
        .collect();
    clear.into_iter().chain(set).collect()
}

fn recipient(rng: &mut CaseRng) -> (PrivateKey, <SuiteKem as Kem>::PublicKey) {
    SuiteKem::derive_keypair(&rng.array32())
}

/// The household key wrap of key management section 2: `info` binds the member and the HK
/// version, the additional data is the permanent MAC tag.
fn hk_wrap_info(member_id: &[u8; 16], hk_version: u32) -> Vec<u8> {
    let mut info = b"vilicus/v1/hk/wrap/".to_vec();
    info.extend_from_slice(member_id);
    info.extend_from_slice(&hk_version.to_be_bytes());
    info
}

#[test]
fn small_order_encapsulated_keys_are_refused_by_both() {
    let mut rng = CaseRng::new(1);
    let (sk, _) = recipient(&mut rng);
    for point in small_order_points() {
        let shown = to_hex(&point);
        let enc = EncappedKey::from_bytes(&point).expect("32 bytes");
        let result =
            hpke::setup_receiver::<SuiteAead, SuiteKdf, SuiteKem>(&OpModeR::Base, &sk, &enc, b"");
        assert!(
            matches!(result, Err(HpkeError::DecapError)),
            "hpke accepted small-order point {shown}"
        );
        let independent_sk = HpkePrivateKey::new(sk.to_bytes().to_vec());
        assert!(
            independent(&[])
                .setup_receiver(&point, &independent_sk, b"", None, None, None)
                .is_err(),
            "hpke-rs accepted small-order point {shown}"
        );
    }
}

#[test]
fn high_bit_blocklist_entries_are_treated_alike_by_both() {
    let mut rng = CaseRng::new(8);
    let (sk, _) = recipient(&mut rng);
    let independent_sk = HpkePrivateKey::new(sk.to_bytes().to_vec());
    for point in HIGH_BIT_BLOCKLIST_ENTRIES {
        let enc = EncappedKey::from_bytes(&hex(point)).expect("32 bytes");
        let hpke_refuses =
            hpke::setup_receiver::<SuiteAead, SuiteKdf, SuiteKem>(&OpModeR::Base, &sk, &enc, b"")
                .is_err();
        let independent_refuses = independent(&[])
            .setup_receiver(&hex(point), &independent_sk, b"", None, None, None)
            .is_err();
        assert!(
            !hpke_refuses,
            "hpke refused {point}, which RFC 7748 decodes to a full-order point"
        );
        assert_eq!(
            hpke_refuses, independent_refuses,
            "implementations disagree on {point}"
        );
    }
}

#[test]
fn sealing_to_a_small_order_public_key_is_refused() {
    for point in small_order_points() {
        let shown = to_hex(&point);
        let pk = <SuiteKem as Kem>::PublicKey::from_bytes(&point).expect("32 bytes");
        // The crate itself refuses the all-zero DH output.
        let raw = hpke::single_shot_seal::<SuiteAead, SuiteKdf, SuiteKem, _>(
            &OpModeS::Base,
            &pk,
            b"",
            b"hk",
            b"",
            &mut QueuedBytes::new(&[7u8; 32]),
        );
        assert!(
            matches!(raw, Err(HpkeError::EncapError)),
            "hpke sealed to small-order point {shown}"
        );
        // The profile refuses it too, before the DH when the encoding is not canonical.
        let bytes: [u8; 32] = point.clone().try_into().expect("32 bytes");
        let expected = if is_canonical_public_key(&bytes) {
            HpkeError::EncapError
        } else {
            HpkeError::ValidationError
        };
        let profile = seal(&pk, b"", b"", b"hk", &mut QueuedBytes::new(&[7u8; 32]));
        assert_eq!(profile.err(), Some(expected), "profile on {shown}");
    }
}

#[test]
fn non_canonical_recipient_keys_seal_but_never_open_and_the_profile_refuses_them() {
    let mut rng = CaseRng::new(9);
    let (sk, pk) = recipient(&mut rng);
    let mut canonical = [0u8; 32];
    pk.write_exact(&mut canonical);
    assert!(is_canonical_public_key(&canonical));

    // Bit 255 set: same DH output, other bytes in kem_context.
    let mut high_bit = canonical;
    high_bit[31] |= 0x80;
    let pk_high = <SuiteKem as Kem>::PublicKey::from_bytes(&high_bit).expect("32 bytes");
    let (enc, ct) = hpke::single_shot_seal::<SuiteAead, SuiteKdf, SuiteKem, _>(
        &OpModeS::Base,
        &pk_high,
        b"info",
        b"secret",
        b"aad",
        &mut QueuedBytes::new(&rng.bytes(32)),
    )
    .expect("the crate seals to a non-canonical key");
    let mut out = vec![0u8; 6];
    assert_eq!(
        open_into(&sk, &enc.to_bytes(), b"info", b"aad", &ct, &mut out),
        Err(Refused),
        "the recipient cannot open a seal to the non-canonical form of its key"
    );
    assert!(!is_canonical_public_key(&high_bit));
    let refused = seal(
        &pk_high,
        b"info",
        b"aad",
        b"secret",
        &mut QueuedBytes::new(&rng.bytes(32)),
    );
    assert_eq!(refused.err(), Some(HpkeError::ValidationError));

    // Bit 255 clear but u >= p: p + 9, an unreduced encoding of the base point.
    let mut unreduced = [0xffu8; 32];
    unreduced[0] = 0xed + 9;
    unreduced[31] = 0x7f;
    assert!(!is_canonical_public_key(&unreduced));
    let pk_unreduced = <SuiteKem as Kem>::PublicKey::from_bytes(&unreduced).expect("32 bytes");
    let refused = seal(
        &pk_unreduced,
        b"",
        b"",
        b"x",
        &mut QueuedBytes::new(&rng.bytes(32)),
    );
    assert_eq!(refused.err(), Some(HpkeError::ValidationError));

    // The boundary: p - 1 is canonical, p is not.
    let mut boundary = [0xffu8; 32];
    boundary[0] = 0xec;
    boundary[31] = 0x7f;
    assert!(is_canonical_public_key(&boundary));
    boundary[0] = 0xed;
    assert!(!is_canonical_public_key(&boundary));
}

#[test]
fn every_binding_input_is_checked_on_open() {
    let mut rng = CaseRng::new(2);
    let (sk, pk) = recipient(&mut rng);
    let (other_sk, _) = recipient(&mut rng);
    let member = [0x11u8; 16];
    let info = hk_wrap_info(&member, 3);
    let mac_tag = rng.bytes(32);
    let hk = rng.bytes(32);
    let sealed = seal(
        &pk,
        &info,
        &mac_tag,
        &hk,
        &mut QueuedBytes::new(&rng.bytes(32)),
    )
    .expect("seal");

    let mut out = vec![0u8; hk.len()];
    open_into(
        &sk,
        &sealed.enc,
        &info,
        &mac_tag,
        &sealed.ciphertext_and_tag,
        &mut out,
    )
    .expect("open");
    assert_eq!(out, hk);

    let other_member = hk_wrap_info(&[0x22u8; 16], 3);
    let other_version = hk_wrap_info(&member, 4);
    let other_mac = rng.bytes(32);
    let attempts: [(&str, &PrivateKey, &[u8], &[u8]); 4] = [
        ("another recipient key", &other_sk, &info, &mac_tag),
        ("another member in info", &sk, &other_member, &mac_tag),
        ("another HK version in info", &sk, &other_version, &mac_tag),
        ("another MAC tag as aad", &sk, &info, &other_mac),
    ];
    for (what, key, info, aad) in attempts {
        let mut out = vec![0u8; hk.len()];
        let result = open_into(
            key,
            &sealed.enc,
            info,
            aad,
            &sealed.ciphertext_and_tag,
            &mut out,
        );
        assert_eq!(result, Err(Refused), "{what}");
        assert_ne!(out, hk, "{what}: plaintext released on failure");
    }
}

#[test]
fn failed_open_leaves_the_ciphertext_in_the_buffer() {
    // aes-gcm 0.10.3 verifies the tag before decrypting, so a failed open never writes
    // unauthenticated plaintext into the caller's buffer (RUSTSEC-2023-0096 was the opposite).
    let mut rng = CaseRng::new(3);
    let (sk, pk) = recipient(&mut rng);
    let plaintext = rng.bytes(64);
    let sealed = seal(
        &pk,
        b"info",
        b"aad",
        &plaintext,
        &mut QueuedBytes::new(&rng.bytes(32)),
    )
    .expect("seal");
    let mut tampered = sealed.ciphertext_and_tag.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let mut out = vec![0u8; plaintext.len()];
    assert_eq!(
        open_into(&sk, &sealed.enc, b"info", b"aad", &tampered, &mut out),
        Err(Refused)
    );
    assert_eq!(
        out,
        tampered[..plaintext.len()],
        "flipped tag: buffer holds the ciphertext, untouched"
    );

    let mut out = vec![0u8; plaintext.len()];
    assert_eq!(
        open_into(
            &sk,
            &sealed.enc,
            b"info",
            b"another aad",
            &sealed.ciphertext_and_tag,
            &mut out
        ),
        Err(Refused)
    );
    assert_eq!(
        out,
        sealed.ciphertext_and_tag[..plaintext.len()],
        "wrong aad: buffer holds the ciphertext, untouched"
    );
}

#[test]
fn malformed_lengths_are_refused_without_panic() {
    let mut rng = CaseRng::new(4);
    let (sk, pk) = recipient(&mut rng);
    let sealed = seal(
        &pk,
        b"",
        b"",
        b"value",
        &mut QueuedBytes::new(&rng.bytes(32)),
    )
    .expect("seal");
    let mut out = vec![0u8; 5];
    assert_eq!(
        open_into(
            &sk,
            &sealed.enc[..31],
            b"",
            b"",
            &sealed.ciphertext_and_tag,
            &mut out
        ),
        Err(Refused)
    );
    assert_eq!(
        open_into(
            &sk,
            &sealed.enc,
            b"",
            b"",
            &sealed.ciphertext_and_tag[..15],
            &mut out
        ),
        Err(Refused)
    );
    for size in [4, 6] {
        let mut wrong_size = vec![0u8; size];
        assert_eq!(
            open_into(
                &sk,
                &sealed.enc,
                b"",
                b"",
                &sealed.ciphertext_and_tag,
                &mut wrong_size
            ),
            Err(Refused),
            "output buffer of {size} bytes for a 5-byte plaintext"
        );
    }
    assert!(PrivateKey::from_bytes(&[0u8; 33]).is_err());
    assert!(<SuiteKem as Kem>::PublicKey::from_bytes(&[0u8; 31]).is_err());
}

#[test]
fn empty_plaintext_info_and_aad_round_trip() {
    let mut rng = CaseRng::new(5);
    let (sk, pk) = recipient(&mut rng);
    let sealed = seal(&pk, b"", b"", b"", &mut QueuedBytes::new(&rng.bytes(32))).expect("seal");
    assert_eq!(sealed.ciphertext_and_tag.len(), hpke_review::TAG_LEN);
    let mut out = [0u8; 0];
    open_into(
        &sk,
        &sealed.enc,
        b"",
        b"",
        &sealed.ciphertext_and_tag,
        &mut out,
    )
    .expect("open");
}

#[test]
fn private_keys_are_not_clamped_on_serialization() {
    // Finding F3: RFC 9180 section 7.1.2 says SerializePrivateKey MUST clamp its output and
    // DeserializePrivateKey MUST clamp its input; hpke 0.13.0 stores and returns the raw bytes
    // and clamps only inside the DH operation. Keys that differ only in the clamped bits act
    // the same but do not compare equal.
    let mut rng = CaseRng::new(6);
    let mut raw = rng.array32();
    raw[0] |= 0b0000_0111;
    raw[31] |= 0b1000_0000;
    let mut clamped = raw;
    clamped[0] &= 0b1111_1000;
    clamped[31] &= 0b0111_1111;
    clamped[31] |= 0b0100_0000;
    assert_ne!(raw, clamped);

    let sk_raw = PrivateKey::from_bytes(&raw).expect("raw");
    let sk_clamped = PrivateKey::from_bytes(&clamped).expect("clamped");
    assert_eq!(
        sk_raw.to_bytes().as_slice(),
        raw,
        "serialization returns the unclamped bytes"
    );
    assert_eq!(
        SuiteKem::sk_to_pk(&sk_raw),
        SuiteKem::sk_to_pk(&sk_clamped),
        "same public key"
    );
    assert!(sk_raw != sk_clamped, "equivalent keys compare unequal");

    let pk = SuiteKem::sk_to_pk(&sk_raw);
    let sealed = seal(
        &pk,
        b"i",
        b"a",
        b"same key",
        &mut QueuedBytes::new(&rng.bytes(32)),
    )
    .expect("seal");
    let mut out = vec![0u8; 8];
    open_into(
        &sk_clamped,
        &sealed.enc,
        b"i",
        b"a",
        &sealed.ciphertext_and_tag,
        &mut out,
    )
    .expect("open");
    assert_eq!(out, b"same key");
}

#[test]
fn the_top_bit_of_enc_is_bound_by_the_key_schedule() {
    // X25519 ignores bit 255 of a u-coordinate, so flipping it gives the same DH output; enc
    // enters kem_context as sent, so the shared secret still differs and the open fails.
    let mut rng = CaseRng::new(7);
    let (sk, pk) = recipient(&mut rng);
    let sealed = seal(
        &pk,
        b"",
        b"",
        b"value",
        &mut QueuedBytes::new(&rng.bytes(32)),
    )
    .expect("seal");
    let mut enc = sealed.enc;
    enc[31] ^= 0x80;
    let mut out = vec![0u8; 5];
    assert_eq!(
        open_into(&sk, &enc, b"", b"", &sealed.ciphertext_and_tag, &mut out),
        Err(Refused)
    );
}

#[test]
fn derive_keypair_accepts_any_ikm_length_and_the_profile_takes_32_bytes() {
    // The backup key pair is DeriveKeyPair over an Argon2id output (key management section 2).
    // The crate takes any length; the profile's signature takes exactly 32 bytes (U4).
    let short = SuiteKem::derive_keypair(b"");
    let long = SuiteKem::derive_keypair(&[0u8; 64]);
    assert!(short.1 != long.1);
    let ikm = [0x5au8; 32];
    assert!(derive_backup_keypair(&ikm).1 == SuiteKem::derive_keypair(&ikm).1);
}
