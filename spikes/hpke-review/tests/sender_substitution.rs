//! Base mode authenticates no sender (REVIEW.md F12, usage rule U10): anyone who holds a
//! member public key can seal a household key of their choice (HK') to it, and the wrap
//! opens. These tests model a disk writer without HK who replaces the member's HK wrap in
//! `wrappers.db`, and show which confirmation of the opened key refuses it.
//!
//! The permanent MAC follows key management section 2 (key derived from HK with the
//! `vilicus/v1/pubkey-mac/` label, HMAC-SHA-256 over a length-prefixed input); the member
//! commitment is the extra anchor F12 proposes, a MAC over the HK version and HK under a key
//! derived from the member's own DEK, written when the member first receives HK.

mod common;

use common::{CaseRng, QueuedBytes};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hpke::{Kem, Serializable};
use hpke_review::{PrivateKey, PublicKey, SuiteKem, open_into, seal};
use sha2::Sha256;

const MEMBER: [u8; 16] = [0x42; 16];
const HK_VERSION: u32 = 1;

fn context(label: &[u8]) -> Vec<u8> {
    let mut info = label.to_vec();
    info.extend_from_slice(&MEMBER);
    info.extend_from_slice(&HK_VERSION.to_be_bytes());
    info
}

fn derive(key: &[u8], label: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, key)
        .expand(&context(label), &mut out)
        .expect("32 bytes");
    out
}

fn mac(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
    m.update(message);
    m.finalize().into_bytes().into()
}

fn verify(key: &[u8; 32], message: &[u8], tag: &[u8; 32]) -> bool {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
    m.update(message);
    m.verify_slice(tag).is_ok()
}

fn mac_input(member_pk: &PublicKey) -> Vec<u8> {
    let pk = member_pk.to_bytes();
    let mut input = Vec::new();
    input.extend_from_slice(&(MEMBER.len() as u16).to_be_bytes());
    input.extend_from_slice(&MEMBER);
    input.extend_from_slice(&(pk.len() as u16).to_be_bytes());
    input.extend_from_slice(&pk);
    input
}

/// What `wrappers.db` holds for the member, as a disk writer sees it.
struct Record {
    pubkey_mac: [u8; 32],
    enc: [u8; 32],
    hk_wrap: Vec<u8>,
}

/// The adult side: MAC the member's public key under HK, then wrap HK to it with the MAC as
/// additional data. A disk writer who picks HK' runs exactly the same code.
fn wrap(hk: &[u8; 32], member_pk: &PublicKey, rng: &mut CaseRng) -> Record {
    let pubkey_mac = mac(
        &derive(hk, b"vilicus/v1/pubkey-mac/"),
        &mac_input(member_pk),
    );
    let sealed = seal(
        member_pk,
        &context(b"vilicus/v1/hk/wrap/"),
        &pubkey_mac,
        hk,
        &mut QueuedBytes::new(&rng.bytes(32)),
    )
    .expect("seal");
    Record {
        pubkey_mac,
        enc: sealed.enc,
        hk_wrap: sealed.ciphertext_and_tag,
    }
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Accepted([u8; 32]),
    WrapRefused,
    PermanentMacRefused,
    MemberCommitmentRefused,
}

/// The member side at unlock: open the wrap, then confirm the opened key before any use.
fn unlock(
    member_sk: &PrivateKey,
    member_pk: &PublicKey,
    record: &Record,
    member_commitment: Option<(&[u8; 32], &[u8; 32])>,
) -> Outcome {
    let mut hk = [0u8; 32];
    if open_into(
        member_sk,
        &record.enc,
        &context(b"vilicus/v1/hk/wrap/"),
        &record.pubkey_mac,
        &record.hk_wrap,
        &mut hk,
    )
    .is_err()
    {
        return Outcome::WrapRefused;
    }
    let mac_key = derive(&hk, b"vilicus/v1/pubkey-mac/");
    if !verify(&mac_key, &mac_input(member_pk), &record.pubkey_mac) {
        return Outcome::PermanentMacRefused;
    }
    if let Some((dek, commitment)) = member_commitment {
        let commit_key = derive(dek, b"vilicus/v1/hk-commit/");
        if !verify(&commit_key, &hk, commitment) {
            return Outcome::MemberCommitmentRefused;
        }
    }
    Outcome::Accepted(hk)
}

struct Household {
    hk: [u8; 32],
    dek: [u8; 32],
    commitment: [u8; 32],
    member_sk: PrivateKey,
    member_pk: PublicKey,
    honest: Record,
    rng: CaseRng,
}

fn household() -> Household {
    let mut rng = CaseRng::new(0x5ab5);
    let hk = rng.array32();
    let dek = rng.array32();
    let (member_sk, member_pk) = SuiteKem::derive_keypair(&rng.array32());
    let honest = wrap(&hk, &member_pk, &mut rng);
    let commitment = mac(&derive(&dek, b"vilicus/v1/hk-commit/"), &hk);
    Household {
        hk,
        dek,
        commitment,
        member_sk,
        member_pk,
        honest,
        rng,
    }
}

#[test]
fn the_honest_wrap_is_accepted_by_every_confirmation() {
    let h = household();
    let commitment = Some((&h.dek, &h.commitment));
    assert_eq!(
        unlock(&h.member_sk, &h.member_pk, &h.honest, commitment),
        Outcome::Accepted(h.hk)
    );
}

#[test]
fn a_substituted_wrap_opens_but_the_permanent_mac_refuses_it() {
    // The writer seals HK' with the stored MAC tag copied as additional data, and leaves the
    // MAC untouched. HPKE opens it: base mode authenticates no sender.
    let mut h = household();
    let hk_prime = h.rng.array32();
    let sealed = seal(
        &h.member_pk,
        &context(b"vilicus/v1/hk/wrap/"),
        &h.honest.pubkey_mac,
        &hk_prime,
        &mut QueuedBytes::new(&h.rng.bytes(32)),
    )
    .expect("anyone holding the public key can seal");
    let substituted = Record {
        pubkey_mac: h.honest.pubkey_mac,
        enc: sealed.enc,
        hk_wrap: sealed.ciphertext_and_tag,
    };

    let mut opened = [0u8; 32];
    open_into(
        &h.member_sk,
        &substituted.enc,
        &context(b"vilicus/v1/hk/wrap/"),
        &substituted.pubkey_mac,
        &substituted.hk_wrap,
        &mut opened,
    )
    .expect("HPKE opens a wrap sealed by anyone");
    assert_eq!(opened, hk_prime);
    assert_eq!(
        unlock(&h.member_sk, &h.member_pk, &substituted, None),
        Outcome::PermanentMacRefused
    );
}

#[test]
fn a_writer_who_also_rewrites_the_mac_passes_the_mac_but_not_the_member_commitment() {
    // The writer picks HK', so it can compute the permanent MAC under HK' as well: the MAC
    // confirmation alone accepts HK'. Only an anchor the writer cannot compute refuses it.
    let mut h = household();
    let hk_prime = h.rng.array32();
    let forged = wrap(&hk_prime, &h.member_pk, &mut h.rng);
    assert_eq!(
        unlock(&h.member_sk, &h.member_pk, &forged, None),
        Outcome::Accepted(hk_prime),
        "the permanent MAC is no anchor against a writer who chose the key"
    );
    assert_eq!(
        unlock(
            &h.member_sk,
            &h.member_pk,
            &forged,
            Some((&h.dek, &h.commitment))
        ),
        Outcome::MemberCommitmentRefused
    );
}
