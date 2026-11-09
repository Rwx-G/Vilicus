//! The limiter of D128 (Story 4.4, AC2, AC6): more simultaneous requests than the limit, admitted
//! in arrival order, never more at once than the limit and the memory budget allow, and refused
//! as retryable once the wait bound passes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use vilicus_types::{
    ARGON2ID_CONCURRENCY_LIMIT, ARGON2ID_MEMORY_BUDGET_KIB, ARGON2ID_QUEUE_WAIT,
    PASSPHRASE_ARGON2ID_MEMORY_KIB,
};

use super::super::test_runtime::{block_on, sleep};
use super::*;
use crate::wrapper::Argon2idParams;

fn cost(memory_kib: u32) -> CheckedCost {
    CheckedCost::below_the_floor(Argon2idParams {
        memory_kib,
        passes: 1,
        lanes: 1,
    })
    .expect("cost")
}

/// Requests made one after another and awaited from as many threads, each holding its permit for
/// `hold` once admitted; returns how many were admitted and how many refused.
fn burst(
    limiter: &'static DerivationLimiter,
    requests: usize,
    cost: CheckedCost,
    hold: Duration,
) -> (usize, usize) {
    let admitted = Arc::new(AtomicUsize::new(0));
    let refused = Arc::new(AtomicUsize::new(0));
    let running = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for _ in 0..requests {
        // Queued here, in order, before the thread that awaits it starts.
        let admission = limiter.admit(&cost, sleep);
        let (admitted, refused, running) = (
            Arc::clone(&admitted),
            Arc::clone(&refused),
            Arc::clone(&running),
        );
        threads.push(thread::spawn(move || match block_on(admission) {
            Ok(permit) => {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                assert!(now <= limiter.limit, "{now} derivations at once");
                admitted.fetch_add(1, Ordering::SeqCst);
                thread::sleep(hold);
                running.fetch_sub(1, Ordering::SeqCst);
                drop(permit);
            }
            Err(error) => {
                assert_eq!(error, CryptoError::Argon2idBusy);
                refused.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for thread in threads {
        thread.join().expect("request thread");
    }
    (
        admitted.load(Ordering::SeqCst),
        refused.load(Ordering::SeqCst),
    )
}

fn leaked(limit: usize, budget_kib: u64, wait: Duration) -> &'static DerivationLimiter {
    Box::leak(Box::new(DerivationLimiter::new(limit, budget_kib, wait)))
}

/// AC2, AC6: with the constants of D128 and the version 1 cost, a burst of more simultaneous
/// requests than the limit is admitted in arrival order, never more at once than the limit, with
/// the working memory of what runs at once within the budget; every request is served when the
/// queue drains within the wait bound.
#[test]
fn a_burst_beyond_the_limit_waits_in_arrival_order() {
    let limiter = leaked(
        ARGON2ID_CONCURRENCY_LIMIT,
        ARGON2ID_MEMORY_BUDGET_KIB,
        ARGON2ID_QUEUE_WAIT,
    );
    let current = CheckedCost::new(Argon2idParams::PASSPHRASE_V1).expect("the version 1 cost");
    let requests = 4 * ARGON2ID_CONCURRENCY_LIMIT;
    let (admitted, refused) = burst(limiter, requests, current, Duration::from_millis(150));
    assert_eq!((admitted, refused), (requests, 0));
    let tickets = (0..u64::try_from(requests).expect("u64")).collect::<Vec<_>>();
    assert_eq!(limiter.admitted(), tickets, "arrival order");
    let (peak_running, peak_memory) = limiter.peaks();
    assert_eq!(
        peak_running, ARGON2ID_CONCURRENCY_LIMIT,
        "the limit, and no more, ran at once"
    );
    assert_eq!(
        peak_memory,
        ARGON2ID_CONCURRENCY_LIMIT as u64 * u64::from(PASSPHRASE_ARGON2ID_MEMORY_KIB)
    );
    assert!(peak_memory <= ARGON2ID_MEMORY_BUDGET_KIB);
}

/// AC2, AC6: a request that cannot start within the wait bound is refused as retryable once the
/// bound has passed, not before; it leaves the queue, so the next request is not blocked behind
/// it.
#[test]
fn a_request_that_cannot_start_in_time_is_refused_as_retryable() {
    let wait = Duration::from_millis(300);
    let limiter = leaked(1, 1 << 20, wait);
    let held = block_on(limiter.admit(&cost(64), sleep)).expect("the first is admitted");
    let started = Instant::now();
    let refused = block_on(limiter.admit(&cost(64), sleep));
    let waited = started.elapsed();
    assert!(matches!(refused, Err(CryptoError::Argon2idBusy)));
    assert!(
        waited >= wait,
        "refused after the bound, not before ({waited:?})"
    );
    assert!(waited < wait * 4, "refused near the bound ({waited:?})");
    drop(held);
    let started = Instant::now();
    let next = block_on(limiter.admit(&cost(64), sleep));
    assert!(next.is_ok(), "the refused request left the queue");
    assert!(started.elapsed() < wait, "admitted at once");
}

/// AC6 with the constants of D128: past the limit, a burst is refused after four seconds.
#[test]
fn past_the_limit_a_burst_is_refused_after_the_wait_bound() {
    let limiter = leaked(
        ARGON2ID_CONCURRENCY_LIMIT,
        ARGON2ID_MEMORY_BUDGET_KIB,
        ARGON2ID_QUEUE_WAIT,
    );
    let current = CheckedCost::new(Argon2idParams::PASSPHRASE_V1).expect("cost");
    let held: Vec<_> = (0..ARGON2ID_CONCURRENCY_LIMIT)
        .map(|_| block_on(limiter.admit(&current, sleep)).expect("within the limit"))
        .collect();
    let started = Instant::now();
    let (admitted, refused) = burst(limiter, 3, current, Duration::ZERO);
    let waited = started.elapsed();
    assert_eq!((admitted, refused), (0, 3));
    assert!(waited >= ARGON2ID_QUEUE_WAIT, "{waited:?}");
    drop(held);
}

/// D128: the working memory of what runs at once stays within the budget, below the
/// concurrency limit too; the oldest request is never overtaken by a smaller one that would fit.
#[test]
fn the_memory_budget_bounds_what_runs_and_the_queue_is_strict() {
    let limiter = leaked(4, 100, Duration::from_secs(4));
    let first = block_on(limiter.admit(&cost(64), sleep)).expect("fits the budget");
    let large = limiter.admit(&cost(64), sleep);
    let small = limiter.admit(&cost(32), sleep);
    let gate = Arc::new(Barrier::new(3));
    let threads: Vec<_> = [large, small]
        .into_iter()
        .map(|admission| {
            let gate = Arc::clone(&gate);
            thread::spawn(move || {
                gate.wait();
                let permit = block_on(admission).expect("admitted once room is made");
                thread::sleep(Duration::from_millis(50));
                drop(permit);
            })
        })
        .collect();
    gate.wait();
    thread::sleep(Duration::from_millis(200));
    assert_eq!(
        limiter.admitted(),
        [0],
        "the small one does not overtake the large one"
    );
    drop(first);
    for thread in threads {
        thread.join().expect("request");
    }
    assert_eq!(limiter.admitted(), [0, 1, 2]);
    let (_, peak_memory) = limiter.peaks();
    assert!(peak_memory <= 100, "{peak_memory} KiB at once");
}

/// A request dropped before it is admitted leaves the queue, and the one behind it moves up.
#[test]
fn a_dropped_request_leaves_the_queue() {
    let limiter = leaked(1, 1 << 20, Duration::from_secs(4));
    let held = block_on(limiter.admit(&cost(64), sleep)).expect("admitted");
    let abandoned = limiter.admit(&cost(64), sleep);
    let behind = limiter.admit(&cost(64), sleep);
    drop(abandoned);
    drop(held);
    let started = Instant::now();
    assert!(block_on(behind).is_ok());
    assert!(started.elapsed() < Duration::from_secs(1));
}
