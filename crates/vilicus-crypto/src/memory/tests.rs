//! The key pool, its refusals and the stack canary of the guarded calls (Story 4.2, AC1, AC6 and
//! AC8). The memory inspection of the process, its crash paths and its signals are the
//! regression harness's, `examples/key_memory`, which runs each case in a process of its own.

use std::fs;

use super::*;
use crate::test_support::key_memory;
use crate::{Kdf, KekDerivation, Label, SymmetricKey, WrapParams, Wrapper, derive_key};

const LABEL: Label = crate::label!("vilicus/v1/test/");
const PURPOSE: Label = crate::label!("vilicus/v1/wrap/test");

/// A pool of the process's planned size that is not the process's pool, so that a test can fill
/// it while other tests take slots from the registered one.
fn private_pool() -> &'static Pool {
    key_memory();
    Box::leak(Box::new(
        Pool::map(PLANNED_SLOTS).expect("a pool of the planned size"),
    ))
}

fn parse_range(line: &str) -> Option<(usize, usize)> {
    let (start, end) = line.split_whitespace().next()?.split_once('-')?;
    Some((
        usize::from_str_radix(start, 16).ok()?,
        usize::from_str_radix(end, 16).ok()?,
    ))
}

#[test]
fn the_pool_holds_the_planned_slots_and_refuses_one_more() {
    let pool = private_pool();
    let slots: Vec<Slot> = (0..PLANNED_SLOTS)
        .map(|index| {
            pool.alloc()
                .unwrap_or_else(|error| panic!("slot {index}: {error}"))
        })
        .collect();
    assert!(matches!(pool.alloc(), Err(KeyMemoryError::Exhausted)));
    let mut slots = slots.into_iter();
    drop(slots.next());
    let again = pool.alloc().expect("a released slot is handed out again");
    assert!(again.bytes().iter().all(|byte| *byte == 0));
}

#[test]
fn a_wiped_pool_is_zeroes_and_hands_out_no_slot() {
    let pool = private_pool();
    let mut slot = pool.alloc().expect("slot");
    slot.with_key_mut(|bytes| bytes.fill(0x5a));
    pool.wipe_all();
    assert_eq!(slot.bytes(), &[0; KEY_LEN]);
    assert!(matches!(pool.alloc(), Err(KeyMemoryError::Wiped)));
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
    let slot = Slot::new().expect("slot");
    canary::take_deepest();
    slot.with_key(|_| deep_call());
    let deep = canary::take_deepest().expect("a measure");
    assert!(deep >= DEEP, "{deep}");
    assert!(
        !within_the_scrub(deep),
        "a 60 KiB operation is beyond the scrub's margin"
    );

    slot.with_key(|_| shallow_call());
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
    let outer = Slot::new().expect("slot");
    let inner = Slot::new().expect("slot");
    canary::take_deepest();
    outer.with_key(|_| inner.with_key(|_| shallow_call()));
    let depth = canary::take_deepest().expect("a measure");
    assert!(within_the_scrub(depth), "{depth}");
}
