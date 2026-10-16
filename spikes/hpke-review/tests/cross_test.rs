//! Two-way cross-test of the crate under review against the independent implementation
//! (D61, D107): 10 000 random cases of the AD-18 suite in base mode, run once against each
//! provider of `hpke-rs`: RustCrypto (the story's choice) and libcrux, whose X25519 and AES-GCM
//! do not share the dalek and RustCrypto lineage of `hpke` (REVIEW.md F11).
//!
//! For each case, drawn from a recorded seed:
//! - recipient key: from `DeriveKeyPair` on a random `ikm` (as the backup key pair is made) on
//!   even cases, from 32 raw random bytes (as `gen_keypair` output is stored) on odd cases;
//!   both implementations must compute the same public key;
//! - hpke seals, hpke-rs opens; hpke-rs, given the same ephemeral seed, must produce the same
//!   `enc` and ciphertext byte for byte;
//! - hpke-rs seals with another ephemeral seed, hpke opens;
//! - an exported secret from each side's sender equals the other side's receiver export;
//! - one flipped bit in the ciphertext and one in `enc` are refused by both.
//!
//! Every input, ephemeral seeds included, comes from the seed, so a failing case replays
//! exactly. `HPKE_CROSS_TEST_SEED` (hexadecimal) replaces the default seed for exploration;
//! the recorded run uses the default.

mod common;

use common::{
    CaseRng, QueuedBytes, SeededLibcrux, SeededRustCrypto, independent_on, independent_public_key,
    to_hex,
};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use hpke_review::{PrivateKey, SuiteAead, SuiteKdf, SuiteKem};
use hpke_rs::{HpkePrivateKey, HpkePublicKey};
use hpke_rs_crypto::HpkeCrypto;

const CASES: usize = 10_000;
/// "VILICUS1" in ASCII.
const DEFAULT_SEED: u64 = 0x5649_4c49_4355_5331;

struct Case {
    recipient_ikm_or_sk: [u8; 32],
    derived: bool,
    info: Vec<u8>,
    aad: Vec<u8>,
    plaintext: Vec<u8>,
    exporter_context: Vec<u8>,
    export_len: usize,
    ephemeral_a: [u8; 32],
    ephemeral_b: [u8; 32],
    ct_bit: usize,
    enc_bit: usize,
}

fn draw_case(rng: &mut CaseRng, index: usize) -> Case {
    let recipient_ikm_or_sk = rng.array32();
    let info_len = if rng.between(0, 3) == 0 {
        rng.between(0, 8)
    } else {
        rng.between(0, 256)
    };
    let aad_len = if rng.between(0, 3) == 0 {
        rng.between(0, 8)
    } else {
        rng.between(0, 256)
    };
    // Every tenth case carries 32 bytes, the size of the household key wrap.
    let pt_len = if index.is_multiple_of(10) {
        32
    } else {
        rng.between(0, 1500)
    };
    let info = rng.bytes(info_len);
    let aad = rng.bytes(aad_len);
    let plaintext = rng.bytes(pt_len);
    let context_len = rng.between(0, 64);
    let exporter_context = rng.bytes(context_len);
    let export_len = rng.between(1, 96);
    let ephemeral_a = rng.array32();
    let ephemeral_b = rng.array32();
    let ct_bit = rng.between(0, (pt_len + hpke_review::TAG_LEN) * 8 - 1);
    let enc_bit = rng.between(0, hpke_review::ENC_LEN * 8 - 1);
    Case {
        recipient_ikm_or_sk,
        derived: index.is_multiple_of(2),
        info,
        aad,
        plaintext,
        exporter_context,
        export_len,
        ephemeral_a,
        ephemeral_b,
        ct_bit,
        enc_bit,
    }
}

fn flip(bytes: &[u8], bit: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[bit / 8] ^= 1 << (bit % 8);
    out
}

#[derive(Default)]
struct Tally {
    hpke_to_independent: usize,
    independent_to_hpke: usize,
    identical_seals: usize,
    exports_agreed: usize,
    tampered_refused: usize,
}

fn run_case<P: HpkeCrypto<HpkePrng = QueuedBytes> + 'static>(
    seed: u64,
    index: usize,
    c: &Case,
    tally: &mut Tally,
) {
    let independent = independent_on::<P>;
    let at = format!("{}, seed {seed:#018x}, case {index}", P::name());

    // Recipient key pair, computed by both implementations.
    let (sk, pk) = if c.derived {
        SuiteKem::derive_keypair(&c.recipient_ikm_or_sk)
    } else {
        let sk = PrivateKey::from_bytes(&c.recipient_ikm_or_sk).expect("32-byte private key");
        let pk = SuiteKem::sk_to_pk(&sk);
        (sk, pk)
    };
    let sk_bytes = sk.to_bytes().to_vec();
    let pk_bytes = pk.to_bytes().to_vec();
    let independent_sk = if c.derived {
        let pair = independent(&[])
            .derive_key_pair(&c.recipient_ikm_or_sk)
            .expect("hpke-rs DeriveKeyPair");
        assert_eq!(
            pair.public_key().as_slice(),
            pk_bytes,
            "{at}: DeriveKeyPair public key"
        );
        pair.into_keys().0
    } else {
        assert_eq!(
            independent_public_key::<P>(&sk_bytes),
            pk_bytes,
            "{at}: public key of raw sk"
        );
        HpkePrivateKey::new(sk_bytes.clone())
    };
    let independent_pk = HpkePublicKey::new(pk_bytes.clone());

    // Direction 1: hpke seals, hpke-rs opens.
    let mut ephemeral = QueuedBytes::new(&c.ephemeral_a);
    let sealed = hpke_review::seal(&pk, &c.info, &c.aad, &c.plaintext, &mut ephemeral)
        .unwrap_or_else(|e| panic!("{at}: hpke seal: {e}"));
    assert!(
        ephemeral.is_drained(),
        "{at}: hpke drew other than 32 bytes"
    );
    let opened = independent(&[])
        .open(
            &sealed.enc,
            &independent_sk,
            &c.info,
            &c.aad,
            &sealed.ciphertext_and_tag,
            None,
            None,
            None,
        )
        .unwrap_or_else(|e| panic!("{at}: hpke-rs open of hpke seal: {e}"));
    assert_eq!(
        opened, c.plaintext,
        "{at}: hpke-rs opened another plaintext"
    );
    tally.hpke_to_independent += 1;

    // Same ephemeral seed on the independent side: byte-identical output.
    let (enc_same, ct_same) = independent(&c.ephemeral_a)
        .seal(
            &independent_pk,
            &c.info,
            &c.aad,
            &c.plaintext,
            None,
            None,
            None,
        )
        .unwrap_or_else(|e| panic!("{at}: hpke-rs seal: {e}"));
    assert_eq!(
        enc_same, sealed.enc,
        "{at}: enc differs for the same ephemeral seed"
    );
    assert_eq!(
        ct_same, sealed.ciphertext_and_tag,
        "{at}: ciphertext differs for the same ephemeral seed"
    );
    tally.identical_seals += 1;

    // Direction 2: hpke-rs seals, hpke opens.
    let mut hpke_rs = independent(&c.ephemeral_b);
    let (enc_b, ct_b) = hpke_rs
        .seal(
            &independent_pk,
            &c.info,
            &c.aad,
            &c.plaintext,
            None,
            None,
            None,
        )
        .unwrap_or_else(|e| panic!("{at}: hpke-rs seal: {e}"));
    let mut out = vec![0u8; c.plaintext.len()];
    hpke_review::open_into(&sk, &enc_b, &c.info, &c.aad, &ct_b, &mut out).unwrap_or_else(|e| {
        panic!(
            "{at}: hpke open of hpke-rs seal: {e}; enc {}",
            to_hex(&enc_b)
        )
    });
    assert_eq!(out, c.plaintext, "{at}: hpke opened another plaintext");
    tally.independent_to_hpke += 1;

    // Exporter secrets, both directions.
    let mut ephemeral = QueuedBytes::new(&c.ephemeral_a);
    let (enc_x, sender) = hpke::setup_sender::<SuiteAead, SuiteKdf, SuiteKem, _>(
        &OpModeS::Base,
        &pk,
        &c.info,
        &mut ephemeral,
    )
    .expect("hpke setup_sender");
    let mut hpke_export = vec![0u8; c.export_len];
    sender
        .export(&c.exporter_context, &mut hpke_export)
        .expect("hpke export");
    let independent_export = independent(&[])
        .receiver_export(
            &enc_x.to_bytes(),
            &independent_sk,
            &c.info,
            None,
            None,
            None,
            &c.exporter_context,
            c.export_len,
        )
        .unwrap_or_else(|e| panic!("{at}: hpke-rs receiver export: {e}"));
    assert_eq!(independent_export, hpke_export, "{at}: export, hpke sender");

    let (enc_y, independent_send_export) = independent(&c.ephemeral_b)
        .send_export(
            &independent_pk,
            &c.info,
            None,
            None,
            None,
            &c.exporter_context,
            c.export_len,
        )
        .unwrap_or_else(|e| panic!("{at}: hpke-rs sender export: {e}"));
    let encapped = <SuiteKem as Kem>::EncappedKey::from_bytes(&enc_y).expect("enc");
    let receiver = hpke::setup_receiver::<SuiteAead, SuiteKdf, SuiteKem>(
        &OpModeR::Base,
        &sk,
        &encapped,
        &c.info,
    )
    .expect("hpke setup_receiver");
    let mut hpke_receiver_export = vec![0u8; c.export_len];
    receiver
        .export(&c.exporter_context, &mut hpke_receiver_export)
        .expect("hpke export");
    assert_eq!(
        hpke_receiver_export, independent_send_export,
        "{at}: export, hpke-rs sender"
    );
    tally.exports_agreed += 2;

    // Tampering: one flipped bit, in the ciphertext or tag, then in enc.
    for (what, enc, ct) in [
        (
            "ciphertext",
            sealed.enc.to_vec(),
            flip(&sealed.ciphertext_and_tag, c.ct_bit),
        ),
        (
            "enc",
            flip(&sealed.enc, c.enc_bit),
            sealed.ciphertext_and_tag.clone(),
        ),
    ] {
        let mut out = vec![0u8; c.plaintext.len()];
        assert!(
            hpke_review::open_into(&sk, &enc, &c.info, &c.aad, &ct, &mut out).is_err(),
            "{at}: hpke accepted a flipped bit in {what}"
        );
        assert!(
            independent(&[])
                .open(
                    &enc,
                    &independent_sk,
                    &c.info,
                    &c.aad,
                    &ct,
                    None,
                    None,
                    None
                )
                .is_err(),
            "{at}: hpke-rs accepted a flipped bit in {what}"
        );
        tally.tampered_refused += 1;
    }
}

fn run_cross_test<P: HpkeCrypto<HpkePrng = QueuedBytes> + 'static>() {
    let seed = match std::env::var("HPKE_CROSS_TEST_SEED") {
        Ok(text) => u64::from_str_radix(text.trim_start_matches("0x"), 16).expect("hex seed"),
        Err(_) => DEFAULT_SEED,
    };
    let mut rng = CaseRng::new(seed);
    let mut tally = Tally::default();
    for index in 0..CASES {
        let case = draw_case(&mut rng, index);
        run_case::<P>(seed, index, &case, &mut tally);
    }
    assert_eq!(tally.hpke_to_independent, CASES);
    assert_eq!(tally.independent_to_hpke, CASES);
    assert_eq!(tally.identical_seals, CASES);
    assert_eq!(tally.exports_agreed, 2 * CASES);
    assert_eq!(tally.tampered_refused, 2 * CASES);
    println!(
        "cross-test [{}] seed {seed:#018x}: {CASES} cases; hpke->hpke-rs {}, hpke-rs->hpke {}, byte-identical seals {}, exports {}, tampered refused {}",
        P::name(),
        tally.hpke_to_independent,
        tally.independent_to_hpke,
        tally.identical_seals,
        tally.exports_agreed,
        tally.tampered_refused
    );
}

#[test]
fn ten_thousand_cases_agree_with_the_rustcrypto_provider() {
    run_cross_test::<SeededRustCrypto>();
}

#[test]
fn ten_thousand_cases_agree_with_the_libcrux_provider() {
    run_cross_test::<SeededLibcrux>();
}
