//! The key pool, its refusals, its wipe and the stack canary of the guarded calls (Story 4.2,
//! AC1, AC6, AC8 and AC9). The memory inspection of the process, its crash paths and its signals are the
//! regression harness's, `examples/key_memory`, which runs each case in a process of its own.

use std::fs;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use super::*;
use crate::derive::derive_key;
use crate::test_support::key_memory;
use crate::{Kdf, KekDerivation, Label, SymmetricKey, WrapParams, Wrapper};

const LABEL: Label = crate::label!("vilicus/v1/test/");
const PURPOSE: Label = crate::label!("vilicus/v1/wrap/test");

/// A pool of the process's planned size that is not the process's pool, so that a test can fill
/// it while other tests take slots from the registered one.
fn private_pool() -> &'static Pool {
    key_memory();
    Box::leak(Box::new(
        Pool::map(CLASSES).expect("a pool of the planned size"),
    ))
}

fn parse_range(line: &str) -> Option<(usize, usize)> {
    let (start, end) = line.split_whitespace().next()?.split_once('-')?;
    Some((
        usize::from_str_radix(start, 16).ok()?,
        usize::from_str_radix(end, 16).ok()?,
    ))
}

/// Fills class `class` of `pool`, slots of `N` bytes, checks that one more is refused and that a
/// released slot is handed out again, all zeroes.
fn fill_class<const N: usize>(pool: &'static Pool, class: usize, planned: usize) {
    let slots: Vec<Slot<N>> = (0..planned)
        .map(|index| {
            pool.alloc(class)
                .unwrap_or_else(|error| panic!("slot {index} of class {class}: {error}"))
        })
        .collect();
    assert!(matches!(
        pool.alloc::<N>(class),
        Err(KeyMemoryError::Exhausted)
    ));
    let mut slots = slots.into_iter();
    drop(slots.next());
    let again = pool
        .alloc::<N>(class)
        .expect("a released slot is handed out again");
    assert!(again.bytes().iter().all(|byte| *byte == 0));
}

#[test]
fn the_pool_holds_the_planned_slots_and_refuses_one_more() {
    let pool = private_pool();
    fill_class::<KEY_LEN>(pool, KeySlot::CLASS, PLANNED_SLOTS);
    fill_class::<TEXT_SLOT_LEN>(pool, TextSlot::CLASS, PLANNED_TEXT_SLOTS);
}

/// Review finding 12: a SQLCipher key text fits a slot of the text class, which lies inside the
/// locked pages and apart from the key slots.
#[test]
fn the_text_class_holds_a_sqlcipher_key_text_inside_the_pool() {
    let pool = private_pool();
    let text = pool
        .alloc::<TEXT_SLOT_LEN>(TextSlot::CLASS)
        .expect("text slot");
    let key = pool.alloc::<KEY_LEN>(KeySlot::CLASS).expect("key slot");
    let text_range = text.start().addr()..text.start().addr() + TEXT_SLOT_LEN;
    let key_range = key.start().addr()..key.start().addr() + KEY_LEN;
    let base = pool.base.as_ptr().addr();
    for range in [&text_range, &key_range] {
        assert!(
            range.start >= base && range.end <= base + pool.len,
            "{range:?} in the pool"
        );
    }
    assert!(text_range.end <= key_range.start || key_range.end <= text_range.start);
}

#[test]
fn a_wiped_pool_is_zeroes_and_hands_out_no_slot() {
    let pool = private_pool();
    let mut slot = pool.alloc::<KEY_LEN>(KeySlot::CLASS).expect("slot");
    slot.with_key_mut(|bytes| bytes.fill(0x5a))
        .expect("not wiped yet");
    pool.wipe_all(Duration::ZERO);
    assert_eq!(slot.bytes(), &[0; KEY_LEN]);
    assert!(matches!(
        pool.alloc::<KEY_LEN>(KeySlot::CLASS),
        Err(KeyMemoryError::Wiped)
    ));
}

/// Review finding 1: once the pool is wiped, neither accessor lends the bytes.
#[test]
fn an_accessor_after_a_wipe_is_refused() {
    let pool = private_pool();
    let mut slot = pool.alloc::<KEY_LEN>(KeySlot::CLASS).expect("slot");
    pool.wipe_all(Duration::ZERO);
    let mut lent = false;
    assert_eq!(slot.with_key(|_| lent = true), Err(KeyMemoryError::Wiped));
    assert_eq!(
        slot.with_key_mut(|_| lent = true),
        Err(KeyMemoryError::Wiped)
    );
    assert!(!lent, "no closure ran");
}

/// A key of `pool`, drawn from the CSPRNG.
fn key_in(pool: &'static Pool) -> SymmetricKey {
    let mut slot = pool.alloc::<KEY_LEN>(KeySlot::CLASS).expect("slot");
    slot.with_key_mut(|bytes| crate::aws_lc::fill_random(bytes))
        .expect("not wiped")
        .expect("random");
    SymmetricKey::from_slot(slot)
}

fn params() -> WrapParams {
    WrapParams::new(
        Kdf::None,
        KekDerivation::Direct,
        Vec::new(),
        vilicus_types::UtcMillis::UNIX_EPOCH,
        vilicus_types::Id::new_v7(vilicus_types::UtcMillis::UNIX_EPOCH, [1; 10]).expect("id"),
    )
    .expect("params")
}

/// Review finding 1: a KEK wiped while the wrap runs, after its guarded call was admitted and
/// before the seal, makes the wrap fail; it never returns a wrapper sealed under zeroes.
#[test]
fn a_wrap_whose_kek_is_wiped_meanwhile_fails() {
    let pool = private_pool();
    let kek = key_in(pool);
    let key = SymmetricKey::generate().expect("generate");
    test_hooks::set(move |during| {
        if during.address() == pool.address() {
            pool.wipe_all(WIPE_WAIT);
        }
    });
    let started = Instant::now();
    let wrapped = Wrapper::wrap_key(&kek, &key, PURPOSE, params(), b"context");
    test_hooks::clear();
    assert!(
        matches!(wrapped, Err(CryptoError::KeyMemory(KeyMemoryError::Wiped))),
        "{:?}",
        wrapped.map(|wrapper| wrapper.to_bytes())
    );
    assert!(
        started.elapsed() < WIPE_WAIT,
        "a wipe does not wait for its own thread's call"
    );
    assert!(kek.slot().bytes().iter().all(|byte| *byte == 0));
}

/// The thread of [`held_for`] and whether the bytes were still there when its closure woke.
type Held = (
    std::thread::JoinHandle<Result<(), KeyMemoryError>>,
    Arc<AtomicBool>,
);

/// A slot of `pool` holding `0x5a` bytes, and a thread that lends them to a closure which
/// signals it started, sleeps `hold`, then records whether the bytes were still there; the
/// thread returns the guarded call's result.
fn held_for(pool: &'static Pool, hold: Duration) -> Held {
    let mut slot = pool.alloc::<KEY_LEN>(KeySlot::CLASS).expect("slot");
    slot.with_key_mut(|bytes| bytes.fill(0x5a))
        .expect("not wiped");
    let intact = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&intact);
    let (started, start) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        slot.with_key(|bytes| {
            started.send(()).expect("signal");
            std::thread::sleep(hold);
            seen.store(bytes.iter().all(|byte| *byte == 0x5a), Ordering::SeqCst);
        })
    });
    start.recv().expect("the guarded call started");
    (thread, intact)
}

/// Review finding 1: a wipe waits for a guarded call in progress on another thread before it
/// overwrites the pool, and that call's result is discarded.
#[test]
fn a_wipe_waits_for_a_call_in_progress_and_discards_its_result() {
    let pool = private_pool();
    let hold = Duration::from_millis(200);
    let (thread, intact) = held_for(pool, hold);
    let started = Instant::now();
    pool.wipe_all(WIPE_WAIT);
    let waited = started.elapsed();
    assert_eq!(thread.join().expect("thread"), Err(KeyMemoryError::Wiped));
    assert!(
        intact.load(Ordering::SeqCst),
        "the bytes were not overwritten under the call"
    );
    assert!(waited >= hold / 2, "the wipe waited ({waited:?})");
}

/// Review finding 1: past its bound the wipe overwrites the pool anyway, and the call still
/// running returns `Wiped`, its result discarded.
#[test]
fn past_its_bound_a_wipe_proceeds_and_the_call_returns_wiped() {
    let pool = private_pool();
    let hold = Duration::from_millis(400);
    let (thread, intact) = held_for(pool, hold);
    let started = Instant::now();
    pool.wipe_all(Duration::from_millis(50));
    let waited = started.elapsed();
    assert!(
        waited < hold,
        "the wipe did not wait past its bound ({waited:?})"
    );
    assert_eq!(thread.join().expect("thread"), Err(KeyMemoryError::Wiped));
    assert!(
        !intact.load(Ordering::SeqCst),
        "the pool was overwritten under the late call"
    );
}

/// Review finding 10: `CAP_IPC_LOCK` in the effective, permitted or ambient set refuses the pool.
#[test]
fn cap_ipc_lock_in_any_set_is_refused() {
    let status = |eff: &str, prm: &str, amb: &str| {
        format!(
            "Name:\ttest\nCapInh:\t0000000000000000\nCapPrm:\t{prm}\nCapEff:\t{eff}\nCapBnd:\t000001ffffffffff\nCapAmb:\t{amb}\n"
        )
    };
    let none = "0000000000000000";
    let ipc_lock = "0000000000004000";
    let other = "00000000a80425fb";
    assert_eq!(holds_cap_ipc_lock(&status(none, none, none)), Ok(false));
    assert_eq!(holds_cap_ipc_lock(&status(other, other, none)), Ok(false));
    for (eff, prm, amb) in [
        (ipc_lock, none, none),
        (none, ipc_lock, none),
        (none, none, ipc_lock),
    ] {
        assert_eq!(
            holds_cap_ipc_lock(&status(eff, prm, amb)),
            Ok(true),
            "{eff} {prm} {amb}"
        );
    }
    assert!(
        holds_cap_ipc_lock("Name:\ttest\n").is_err(),
        "a missing set is not read as empty"
    );
}

/// AC6: the pages are locked, excluded from core dumps and wiped in fork children
/// (`/proc/self/smaps` flags `lo`, `dd`, `wf`), and the page on each side is `PROT_NONE`.
#[test]
fn the_pool_is_locked_advised_and_between_guard_pages() {
    let pool = private_pool();
    let base = pool.base.as_ptr().addr();
    let smaps = fs::read_to_string("/proc/self/smaps").expect("smaps");
    let mut lines = smaps.lines();
    let mut flags = None;
    while let Some(line) = lines.next() {
        if parse_range(line).is_some_and(|(start, end)| (start..end).contains(&base)) {
            flags = lines
                .find_map(|line| line.strip_prefix("VmFlags:"))
                .map(str::to_string);
            break;
        }
    }
    let flags = flags.expect("the pool's mapping");
    for flag in ["lo", "dd", "wf"] {
        assert!(
            flags.split_whitespace().any(|found| found == flag),
            "{flag} in {flags}"
        );
    }
    let maps = fs::read_to_string("/proc/self/maps").expect("maps");
    let guard_at = |boundary: fn(usize, usize) -> usize, address: usize| {
        maps.lines().any(|line| {
            parse_range(line).is_some_and(|(start, end)| boundary(start, end) == address)
                && line.split_whitespace().nth(1) == Some("---p")
        })
    };
    assert!(
        guard_at(|_, end| end, base),
        "a guard page ends where the pool starts"
    );
    assert!(
        guard_at(|start, _| start, base + pool.len),
        "a guard page starts where it ends"
    );
}

#[test]
fn a_second_pool_is_refused() {
    key_memory();
    assert_eq!(lock_key_memory(), Err(KeyMemoryError::AlreadyLocked));
}

#[test]
fn a_refused_lock_names_limit_memlock() {
    let refused = KeyMemoryError::Lock {
        bytes: 8192,
        errno: libc::ENOMEM,
    };
    assert!(refused.to_string().contains("LimitMEMLOCK"), "{refused}");
    assert!(
        CryptoError::from(refused)
            .to_string()
            .contains("LimitMEMLOCK")
    );
}

#[test]
fn sigterm_is_not_blocked_while_other_threads_run() {
    let (stop, stopped) = std::sync::mpsc::channel::<()>();
    let other = std::thread::spawn(move || stopped.recv());
    assert!(matches!(
        take_sigterm(|| {}),
        Err(KeyMemoryError::ThreadsRunning { threads }) if threads > 1
    ));
    drop(stop);
    let _ = other.join();
}

/// Whether a guarded call `depth` bytes deep is covered by the scrub with its margin (AC8).
fn within_the_scrub(depth: usize) -> bool {
    depth + STACK_SCRUB_MARGIN <= STACK_SCRUB_LEN
}

/// Bytes of the frame of [`deep_call`].
const DEEP: usize = 60 * 1024;

#[inline(never)]
fn deep_call() {
    let mut frame = [0_u8; DEEP];
    std::hint::black_box(&mut frame).fill(1);
}

#[inline(never)]
fn shallow_call() {
    let mut frame = [0_u8; 1024];
    std::hint::black_box(&mut frame).fill(1);
}

/// AC8: the canary measures how deep a guarded call reaches, and the check fails a call whose
/// depth plus the margin is beyond the scrub.
#[test]
fn the_canary_measures_each_guarded_call() {
    key_memory();
    let slot = KeySlot::new().expect("slot");
    canary::take_deepest();
    slot.with_key(|_| deep_call()).expect("not wiped");
    let deep = canary::take_deepest().expect("a measure");
    assert!(deep >= DEEP, "{deep}");
    assert!(
        !within_the_scrub(deep),
        "a 60 KiB operation is beyond the scrub's margin"
    );

    slot.with_key(|_| shallow_call()).expect("not wiped");
    let shallow = canary::take_deepest().expect("a measure");
    assert!(shallow < deep, "{shallow} against {deep}");
}

/// AC8: every key operation of the crate is within the scrub with its margin, in this build.
/// The regression harness repeats the measure on the release build.
#[test]
fn every_key_operation_is_within_the_scrub() {
    key_memory();
    let params = || {
        WrapParams::new(
            Kdf::None,
            KekDerivation::Direct,
            Vec::new(),
            vilicus_types::UtcMillis::UNIX_EPOCH,
            vilicus_types::Id::new_v7(vilicus_types::UtcMillis::UNIX_EPOCH, [1; 10]).expect("id"),
        )
        .expect("params")
    };
    canary::take_deepest();
    let kek = SymmetricKey::generate().expect("generate");
    let generate = canary::take_deepest();
    let derived = derive_key(&kek, LABEL, &[b"context"]).expect("derive");
    let derive = canary::take_deepest();
    let wrapper = Wrapper::wrap_key(&kek, &derived, PURPOSE, params(), b"context").expect("wrap");
    let wrap = canary::take_deepest();
    let unwrapped = wrapper
        .unwrap_key(&kek, PURPOSE, b"context")
        .expect("unwrap");
    let unwrap = canary::take_deepest();
    for (operation, depth) in [
        ("generate", generate),
        ("derive_key", derive),
        ("wrap_key", wrap),
        ("unwrap_key", unwrap),
    ] {
        let depth = depth.unwrap_or_else(|| panic!("{operation} ran no guarded call"));
        assert!(within_the_scrub(depth), "{operation}: {depth} bytes");
    }
    drop((kek, derived, unwrapped));
}

/// A guarded call inside another is not scrubbed or measured on its own: the outermost one covers
/// both, so the inner scrub cannot be mistaken for the operation's depth.
#[test]
fn nested_guarded_calls_are_measured_once() {
    key_memory();
    let outer = KeySlot::new().expect("slot");
    let inner = KeySlot::new().expect("slot");
    canary::take_deepest();
    outer
        .with_key(|_| inner.with_key(|_| shallow_call()))
        .expect("not wiped")
        .expect("not wiped");
    let depth = canary::take_deepest().expect("a measure");
    assert!(within_the_scrub(depth), "{depth}");
}
