//! Unit checks of the pieces the memory scans rely on: the pool wipes, the scanner finds what
//! it should and only that, and the recomputed patterns are the values the libraries use.
//! Run inside the container (the pool needs `RLIMIT_MEMLOCK` of a few pages).

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit};
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use hpke::Serializable;
use hpke::kem::X25519HkdfSha256;

use locked_memory::material::{
    self, DEK, EPH_IKM, HK, HKDF_INFO, HKDF_SALT, HPKE_AAD, HPKE_CT, HPKE_ENC, HPKE_TAG, MEMBER_PK,
    MEMBER_SK, Material,
};
use locked_memory::patterns::{self, CodePath, Pattern};
use locked_memory::pool::{LockedPool, PLANNED_SLOTS, PoolError, SLOT_LEN};
use locked_memory::scan::{Findings, Index, RegionKind};
use locked_memory::subject::POOL_PAGES;

fn material() -> Material {
    let dir = std::env::temp_dir().join(format!("locked-memory-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    Material::generate(&dir.join("material.bin")).expect("material")
}

fn read_back(address: usize, len: usize) -> Vec<u8> {
    // SAFETY: the pool mapping is never unmapped, so a dropped slot's bytes stay readable.
    unsafe { std::slice::from_raw_parts(address as *const u8, len) }.to_vec()
}

/// The pool is one per process, so every pool property is checked in this one test.
#[test]
fn pool_wipes_refuses_and_holds_the_planned_size() {
    let pool = LockedPool::new(POOL_PAGES).expect("pool");
    assert!(matches!(
        LockedPool::new(POOL_PAGES),
        Err(PoolError::AlreadyRegistered)
    ));

    let mut slot = pool.alloc(32).expect("slot");
    slot.bytes_mut().fill(0xa5);
    let address = slot.address();
    drop(slot);
    assert_eq!(read_back(address, SLOT_LEN), vec![0u8; SLOT_LEN]);
    let mut again = pool.alloc(16).expect("slot");
    assert_eq!(again.address(), address);

    again.bytes_mut().fill(0x5a);
    pool.wipe_all();
    assert_eq!(again.bytes(), &[0u8; 16]);
    drop(again);

    assert!(matches!(
        pool.alloc(SLOT_LEN + 1),
        Err(PoolError::TooLong(_))
    ));
    let capacity = pool.range().1 / SLOT_LEN;
    assert!(capacity >= PLANNED_SLOTS, "{capacity} < {PLANNED_SLOTS}");
    let slots: Vec<_> = (0..capacity)
        .map(|_| pool.alloc(32).expect("slot"))
        .collect();
    assert!(matches!(pool.alloc(1), Err(PoolError::Exhausted)));
    drop(slots);
}

fn search(patterns: &[Pattern], data: &[u8]) -> Findings {
    let mut findings = Findings::default();
    Index::new(patterns).search(data, 0x1000, RegionKind::Heap, &mut findings);
    findings
}

#[test]
fn scanner_finds_whole_and_damaged_copies_but_not_short_runs() {
    let key: Vec<u8> = (1..=32).collect();
    let patterns = [Pattern {
        name: "key".to_string(),
        bytes: key.clone(),
    }];

    let mut data = vec![0u8; 256];
    data[40..72].copy_from_slice(&key);
    let whole = search(&patterns, &data);
    assert_eq!(whole.count("key"), 1);
    assert_eq!(whole.hits["key"].keys().next(), Some(&(0x1000 + 40)));

    let mut damaged = data.clone();
    damaged[40..56].fill(0xee);
    assert_eq!(search(&patterns, &damaged).count("key"), 1);

    let mut short = vec![0u8; 256];
    short[100..122].copy_from_slice(&key[9..31]);
    assert_eq!(search(&patterns, &short).count("key"), 0);
    let mut enough = vec![0u8; 256];
    enough[100..123].copy_from_slice(&key[1..24]);
    assert_eq!(search(&patterns, &enough).count("key"), 1);
}

#[test]
fn scanner_attributes_shared_windows_to_one_form() {
    let key: Vec<u8> = (1..=32).collect();
    let mut clamped = key.clone();
    clamped[0] &= 248;
    clamped[31] = (clamped[31] & 127) | 64;
    let patterns = [
        Pattern {
            name: "sk".to_string(),
            bytes: key.clone(),
        },
        Pattern {
            name: "sk-clamped".to_string(),
            bytes: clamped,
        },
    ];
    let findings = search(&patterns, &key);
    assert_eq!(findings.count("sk"), 1);
    assert_eq!(findings.count("sk-clamped"), 0);
}

#[test]
fn hpke_schedule_patterns_open_the_real_wrap() {
    let m = material();
    let enc = m.get32(HPKE_ENC);
    let dh = x25519_dalek::x25519(m.get32(MEMBER_SK), enc);
    let schedule = patterns::hpke_schedule(&dh, &enc, &m.get32(MEMBER_PK));
    let cipher = Aes256Gcm::new(&schedule.key.into());
    let mut plaintext = m.get(HPKE_CT).to_vec();
    cipher
        .decrypt_in_place_detached(
            &schedule.base_nonce.into(),
            HPKE_AAD,
            &mut plaintext,
            m.get(HPKE_TAG).into(),
        )
        .expect("the recomputed AEAD key and nonce open the household key wrap");
    assert_eq!(plaintext, m.get(HK));
}

#[test]
fn ephemeral_patterns_match_hpke_derive_keypair() {
    let m = material();
    let ikm = m.get32(EPH_IKM);
    let (sk, pk) = <X25519HkdfSha256 as hpke::Kem>::derive_keypair(&ikm);
    assert_eq!(sk.to_bytes().as_slice(), patterns::ephemeral_sk(&ikm));
    assert_eq!(pk.to_bytes().as_slice(), patterns::expected_enc(&ikm));
}

struct Len32;

impl KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

#[test]
fn hkdf_patterns_match_aws_lc_rs() {
    let m = material();
    let mut okm = [0u8; 32];
    Salt::new(HKDF_SHA256, HKDF_SALT)
        .extract(m.get(DEK))
        .expand(&[HKDF_INFO], Len32)
        .expect("expand")
        .fill(&mut okm)
        .expect("fill");
    assert_eq!(okm, patterns::hkdf_okm(&m));
}

#[test]
fn passphrase_patterns_match_the_wrap() {
    let m = material();
    let mut kek = [0u8; 32];
    material::argon2()
        .hash_password_into(m.get(material::PASSPHRASE), material::ARGON2_SALT, &mut kek)
        .expect("argon2");
    assert_eq!(kek, m.kek);
    let held = CodePath::Passphrase.held(&m);
    assert!(held.iter().any(|p| p.bytes == m.kek));
}

#[test]
fn every_code_path_has_distinct_pattern_names() {
    let m = material();
    for path in CodePath::ALL {
        let all = path.all(&m);
        let mut names: Vec<&str> = all.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), all.len(), "{}", path.name());
        for held in path.held(&m) {
            assert!(all.contains(&held), "{} holds {}", path.name(), held.name);
        }
    }
}
