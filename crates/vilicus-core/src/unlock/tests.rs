//! Passphrase unlock (Story 4.4, AC2, AC5, AC6): the checks made before anything is queued, which
//! run in every test build, and the derivations at the version 1 cost and at the floor, which lock
//! more memory than a test runner's `RLIMIT_MEMLOCK` allows: those are ignored here and run by the
//! `argon2id` job of `.github/workflows/ci.yml`, in a container whose limit covers them
//! (`oracles/argon2id/run.sh`).

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use vilicus_crypto::testing::{self, block_on, sleep};
use vilicus_crypto::{SymmetricKey, WrapperSetKey};
use vilicus_types::{
    ARGON2ID_CONCURRENCY_LIMIT, ARGON2ID_FLOOR_OPTIONS, ARGON2ID_QUEUE_WAIT,
    PASSPHRASE_ARGON2ID_LANES,
};

use super::*;

fn key_memory() {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        vilicus_crypto::harden_process().expect("hardened");
        match vilicus_crypto::lock_key_memory() {
            Ok(()) | Err(vilicus_crypto::KeyMemoryError::AlreadyLocked) => {}
            Err(error) => panic!("the key pool of the tests: {error}"),
        }
    });
}

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vilicus-core-unlock-{}-{}-{label}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

fn member(last: u8) -> Id {
    let mut bytes = *b"\x01\x7f\x22\xe2\x79\xb0\x7c\xc3\x98\xc4\xdc\x0c\x0c\x07\x39\x00";
    bytes[15] = last;
    Id::from_bytes(bytes).expect("a UUIDv7")
}

fn created(seed: u8) -> (UtcMillis, Id) {
    let at = UtcMillis::from_millis(1_793_577_600_000 + i64::from(seed)).expect("time");
    (at, Id::new_v7(at, [seed; 10]).expect("id"))
}

fn passkey() -> FirstFactor {
    FirstFactor::for_tests(FirstFactorKind::PasskeyLogin)
}

/// `wrappers.db` in a new directory, holding `changes`, sealed under `set_key`.
fn wrappers_with(label: &str, set_key: &WrapperSetKey, changes: &[WrapperChange]) -> Wrappers {
    let mut wrappers = Wrappers::create(&scratch(label)).expect("wrappers.db");
    wrappers.write(set_key, set_key, changes).expect("write");
    wrappers
}

/// A passphrase wrapper of `dek` whose header states `kdf` and `salt`, sealed under a random KEK:
/// what `prepare` reads without deriving anything.
fn stated_wrapper(dek: &MemberDek, kdf: Kdf, salt: &[u8], seed: u8) -> WrapperChange {
    let (at, id) = created(seed);
    let kek = SymmetricKey::generate().expect("kek");
    Wrappers::dek_wrapper_change(
        dek,
        KekKind::Passphrase,
        &kek,
        kdf,
        KekDerivation::Direct,
        salt.to_vec(),
        at,
        id,
    )
    .expect("change")
}

fn dek_bytes(dek: &MemberDek) -> [u8; 32] {
    testing::with_key(dek, |bytes| *bytes).expect("not wiped")
}

/// AC2, AD-9: without a successful first factor the request is refused before anything else is
/// looked at, the member's wrappers included, so no Argon2id starts.
#[test]
fn no_first_factor_no_argon2id() {
    key_memory();
    let hk = testing::household_key(1).expect("household key");
    let set_key = hk.wrapper_set_key().expect("set key");
    let wrappers = wrappers_with("no-factor", &set_key, &[]);
    let gate = UnlockGate::new();
    let now = Instant::now();
    let refused = prepare(&gate, member(1), None, "passphrase", &wrappers, now);
    assert!(matches!(refused, Err(UnlockRefused::NoFirstFactor)));
    let factor = passkey();
    let later = prepare(
        &gate,
        member(1),
        Some(&factor),
        "passphrase",
        &wrappers,
        now,
    );
    assert!(
        matches!(later, Err(UnlockRefused::NoPassphraseWrapper)),
        "with a first factor the request goes on to the wrapper"
    );
    assert!(matches!(
        gate.begin(member(1), None, now),
        Err(UnlockRefused::NoFirstFactor)
    ));
}

/// D128: one request in flight per member; another member is not held up, and the member's next
/// request is admitted once the first ends.
#[test]
fn one_request_in_flight_per_member() {
    let gate = UnlockGate::new();
    let factor = FirstFactor::for_tests(FirstFactorKind::HostCli);
    let now = Instant::now();
    let first = gate.begin(member(1), Some(&factor), now).expect("first");
    assert!(matches!(
        gate.begin(member(1), Some(&factor), now),
        Err(UnlockRefused::InFlight)
    ));
    let other = gate
        .begin(member(2), Some(&factor), now)
        .expect("another member");
    drop(first);
    assert!(gate.begin(member(1), Some(&factor), now).is_ok());
    drop(other);
}

/// D128: after a failed passphrase the member's next attempt waits the base delay, doubled for
/// each further failure up to the maximum; a success clears it.
#[test]
fn a_failed_passphrase_delays_the_next_attempt_exponentially() {
    let gate = UnlockGate::new();
    let factor = passkey();
    let start = Instant::now();
    let mut now = start;
    for failures in 1..=4 {
        let ticket = gate.begin(member(1), Some(&factor), now).expect("admitted");
        ticket.record(false, now);
        drop(ticket);
        let delay = backoff_after(failures);
        assert_eq!(delay, PASSPHRASE_BACKOFF_BASE * (1 << (failures - 1)));
        assert!(matches!(
            gate.begin(
                member(1),
                Some(&factor),
                now + delay - Duration::from_millis(1)
            ),
            Err(UnlockRefused::Backoff)
        ));
        now += delay;
    }
    let ticket = gate
        .begin(member(1), Some(&factor), now)
        .expect("after the delay");
    ticket.record(true, now);
    drop(ticket);
    assert!(
        gate.begin(member(1), Some(&factor), now).is_ok(),
        "a success clears the delay"
    );
    assert_eq!(backoff_after(u32::MAX), PASSPHRASE_BACKOFF_MAX);
    assert!(backoff_after(64) <= PASSPHRASE_BACKOFF_MAX);
}

/// AC5, U6: a header below the floor, above the ceiling, with another salt length or with no
/// KDF, and a passphrase over the maximum length, are refused at once while every slot of the
/// limiter is held, so none of them is queued (as story 1.8's
/// `unlock_refuses_a_bad_header_before_queuing`); a good header is then queued, and refused as
/// busy after the wait bound.
#[test]
fn unlock_refuses_a_bad_header_before_queuing() {
    key_memory();
    let hk = testing::household_key(1).expect("household key");
    let set_key = hk.wrapper_set_key().expect("set key");
    let current = current_cost().expect("cost");
    let held: Vec<_> = (0..ARGON2ID_CONCURRENCY_LIMIT)
        .map(|_| block_on(admit_derivation(&current, sleep)).expect("a slot"))
        .collect();
    let (floor_memory, floor_passes) = ARGON2ID_FLOOR_OPTIONS[1];
    let lanes = PASSPHRASE_ARGON2ID_LANES;
    let below = Argon2idParams {
        memory_kib: floor_memory - 1,
        passes: floor_passes,
        lanes,
    };
    let above = Argon2idParams {
        memory_kib: vilicus_types::ARGON2ID_MAX_MEMORY_KIB + 1,
        passes: 1,
        lanes,
    };
    let floor = Argon2idParams {
        memory_kib: floor_memory,
        passes: floor_passes,
        lanes,
    };
    let factor = passkey();
    let gate = UnlockGate::new();
    for (index, (kdf, salt)) in [
        (Kdf::Argon2id(below), &[1_u8; 16][..]),
        (Kdf::Argon2id(above), &[1; 16][..]),
        (Kdf::Argon2id(floor), &[1; 15][..]),
        (Kdf::None, &[1; 16][..]),
    ]
    .into_iter()
    .enumerate()
    {
        let seed = u8::try_from(index).expect("seed");
        let dek = MemberDek::generate(member(10 + seed), 1).expect("dek");
        let wrappers = wrappers_with(
            "bad-header",
            &set_key,
            &[stated_wrapper(&dek, kdf, salt, seed)],
        );
        let started = Instant::now();
        let refused = prepare(
            &gate,
            dek.member(),
            Some(&factor),
            "passphrase",
            &wrappers,
            started,
        );
        assert!(
            matches!(
                refused,
                Err(UnlockRefused::Cost(CryptoError::Argon2idCost { .. })
                    | UnlockRefused::NotAPassphraseWrapper)
            ),
            "{kdf:?}, {} bytes of salt",
            salt.len()
        );
        assert!(
            started.elapsed() < ARGON2ID_QUEUE_WAIT / 4,
            "refused before the queue"
        );
    }
    let dek = MemberDek::generate(member(20), 1).expect("dek");
    let wrappers = wrappers_with(
        "good-header",
        &set_key,
        &[stated_wrapper(&dek, Kdf::Argon2id(floor), &[1; 16], 9)],
    );
    let too_long = "a".repeat(PASSPHRASE_MAX_LEN + 1);
    assert!(matches!(
        prepare(
            &gate,
            dek.member(),
            Some(&factor),
            &too_long,
            &wrappers,
            Instant::now()
        ),
        Err(UnlockRefused::PassphraseTooLong)
    ));
    let prepared = prepare(
        &gate,
        dek.member(),
        Some(&factor),
        "passphrase",
        &wrappers,
        Instant::now(),
    )
    .expect("a header within the floor and the ceiling");
    let queued = Instant::now();
    let busy = block_on(prepared.admission(sleep));
    assert!(matches!(busy, Err(CryptoError::Argon2idBusy)));
    assert!(
        queued.elapsed() >= ARGON2ID_QUEUE_WAIT,
        "refused after the wait bound"
    );
    assert!(matches!(
        UnlockRefused::from(CryptoError::Argon2idBusy),
        UnlockRefused::Busy
    ));
    drop(held);
}

/// The passphrase of the tests in NFC, and the same text in NFD: one KEK for both (D128).
const NFC: &str = "\u{e9}t\u{e9} \u{e0} No\u{eb}l, cr\u{e8}me br\u{fb}l\u{e9}e";

fn nfd(text: &str) -> String {
    text.nfd().collect()
}

/// AC5: a passphrase wrapper is written at the version 1 cost: Argon2id 0x13, t, p and m the named
/// constants, a 16-byte salt, read back by its header; it opens with the passphrase typed in NFD,
/// normalised to NFC, and with no other passphrase, which starts the member's delay.
#[test]
#[ignore = "locks Argon2id working memory at the floor or the version 1 cost"]
fn a_passphrase_wrapper_is_written_at_the_version_1_cost_and_opens_with_nfc() {
    key_memory();
    let hk = testing::household_key(1).expect("household key");
    let set_key = hk.wrapper_set_key().expect("set key");
    let dek = MemberDek::generate(member(30), 1).expect("dek");
    let (at, id) = created(30);
    let permit =
        block_on(admit_derivation(&current_cost().expect("cost"), sleep)).expect("admitted");
    let change = passphrase_wrapper_change(&permit, &dek, NFC, at, id).expect("change");
    drop(permit);
    let wrappers = wrappers_with("v1", &set_key, &[change]);
    let row = wrappers
        .own_dek_wrapper(dek.member(), KekKind::Passphrase)
        .expect("read")
        .expect("a passphrase wrapper");
    let wrapper = Wrapper::from_bytes(&row.wrapper).expect("a version 1 wrapper");
    assert_eq!(wrapper.kdf(), Kdf::Argon2id(Argon2idParams::PASSPHRASE_V1));
    assert_eq!(wrapper.kek_reference().len(), PASSPHRASE_SALT_LEN);
    assert_eq!(wrapper.kek_derivation(), KekDerivation::Direct);
    assert_eq!(vilicus_crypto::ARGON2_VERSION, 0x13);

    let gate = UnlockGate::new();
    let factor = passkey();
    let typed = nfd(NFC);
    assert_ne!(typed, NFC);
    let now = Instant::now();
    let prepared =
        prepare(&gate, dek.member(), Some(&factor), &typed, &wrappers, now).expect("prepared");
    let permit = block_on(prepared.admission(sleep)).expect("admitted");
    let unlocked = prepared.unlock(&permit, &typed, now).expect("unlocked");
    assert!(!unlocked.needs_rewrap());
    assert_eq!(dek_bytes(unlocked.dek()), dek_bytes(&dek));
    drop((unlocked, permit));

    let prepared = prepare(
        &gate,
        dek.member(),
        Some(&factor),
        "another passphrase",
        &wrappers,
        now,
    )
    .expect("prepared");
    let permit = block_on(prepared.admission(sleep)).expect("admitted");
    assert!(matches!(
        prepared.unlock(&permit, "another passphrase", now),
        Err(UnlockRefused::WrongPassphrase)
    ));
    drop(permit);
    assert!(matches!(
        prepare(&gate, dek.member(), Some(&factor), NFC, &wrappers, now),
        Err(UnlockRefused::Backoff)
    ));
}

/// AC5: a wrapper written at an older cost, the floor, is unlocked with its header's cost and
/// rewritten at the current one at that unlock, under a second admission: two derivations, after
/// which the wrapper states the current cost and opens again.
#[test]
#[ignore = "locks Argon2id working memory at the floor or the version 1 cost"]
fn a_wrapper_at_an_older_cost_is_rewritten_at_its_unlock() {
    key_memory();
    let hk = testing::household_key(1).expect("household key");
    let set_key = hk.wrapper_set_key().expect("set key");
    let dek = MemberDek::generate(member(40), 1).expect("dek");
    let (floor_memory, floor_passes) = ARGON2ID_FLOOR_OPTIONS[1];
    let older = CheckedCost::new(Argon2idParams {
        memory_kib: floor_memory,
        passes: floor_passes,
        lanes: PASSPHRASE_ARGON2ID_LANES,
    })
    .expect("the floor");
    let salt = passphrase_salt().expect("salt");
    let permit = block_on(admit_derivation(&older, sleep)).expect("admitted");
    let kek = derive_passphrase_kek(&permit, &older, NFC.chars(), &salt).expect("kek");
    drop(permit);
    let (at, id) = created(40);
    let change = Wrappers::dek_wrapper_change(
        &dek,
        KekKind::Passphrase,
        &kek,
        Kdf::Argon2id(older.params()),
        KekDerivation::Direct,
        salt.to_vec(),
        at,
        id,
    )
    .expect("change");
    let mut wrappers = wrappers_with("older", &set_key, &[change]);

    let gate = UnlockGate::new();
    let factor = passkey();
    let now = Instant::now();
    let prepared =
        prepare(&gate, dek.member(), Some(&factor), NFC, &wrappers, now).expect("prepared");
    assert_eq!(prepared.cost(), older, "unlocked with its header's cost");
    let first = block_on(prepared.admission(sleep)).expect("first derivation");
    let unlocked = prepared.unlock(&first, NFC, now).expect("unlocked");
    drop(first);
    assert!(unlocked.needs_rewrap());
    let second = block_on(admit_derivation(&current_cost().expect("cost"), sleep)).expect("second");
    let (at, id) = created(41);
    let rewrap = unlocked.rewrap(&second, NFC, at, id).expect("rewrap");
    drop((second, unlocked));
    wrappers
        .write(&set_key, &set_key, &[rewrap])
        .expect("rewritten");

    let row = wrappers
        .own_dek_wrapper(dek.member(), KekKind::Passphrase)
        .expect("read")
        .expect("wrapper");
    let wrapper = Wrapper::from_bytes(&row.wrapper).expect("wrapper");
    assert_eq!(wrapper.kdf(), Kdf::Argon2id(Argon2idParams::PASSPHRASE_V1));
    assert_ne!(wrapper.kek_reference(), salt, "a new salt");
    let prepared =
        prepare(&gate, dek.member(), Some(&factor), NFC, &wrappers, now).expect("prepared");
    let permit = block_on(prepared.admission(sleep)).expect("admitted");
    let again = prepared
        .unlock(&permit, NFC, now)
        .expect("opens at the current cost");
    assert!(!again.needs_rewrap());
    assert_eq!(dek_bytes(again.dek()), dek_bytes(&dek));
}
