use std::sync::{Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, AssociatedData, Block, ParamsBuilder, Version};
use argon2id_params::derive::Pool;
use argon2id_params::guidance::{self, PUBLISHED};
use argon2id_params::limiter::Limiter;
use argon2id_params::stats::summarise;
use argon2id_params::{Cost, MIB, UnlockError, unlock};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 9106 section 5.3: the Argon2id test vector (with secret and associated data), computed
/// with the `parallel` feature on a multi-threaded pool, the configuration the spike measures.
#[test]
fn rfc9106_argon2id_vector_on_a_parallel_pool() {
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&[0x04; 12]).unwrap())
        .build()
        .unwrap();
    let argon2 =
        Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap();
    let mut tag = [0u8; 32];
    pool.install(|| argon2.hash_password_into(&[0x01; 32], &[0x02; 16], &mut tag))
        .unwrap();
    assert_eq!(
        tag.to_vec(),
        hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    );
}

/// The reference implementation's (phc-winner-argon2) Argon2id v0x13 vector without secret or
/// associated data, the shape of a Vilicus KEK: "password", "somesalt", m = 64 MiB, t = 2, p = 1,
/// through the spike's own derivation path (caller-owned memory, dedicated pool).
#[test]
fn reference_argon2id_vector_without_secret_or_data() {
    let kek = Pool::new(2)
        .unwrap()
        .derive(Cost::new(64, 2, 1), b"password", b"somesalt")
        .unwrap();
    assert_eq!(
        kek.to_vec(),
        hex("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")
    );
}

/// argon2 0.6.0 frees its own blocks without wiping them; the spike's buffer must be all zeros
/// once a derivation returns.
#[test]
fn derivation_memory_is_wiped() {
    let cost = Cost::new(8, 1, 4);
    let mut memory = vec![Block::new(); cost.m_kib as usize];
    Pool::new(2)
        .unwrap()
        .derive_with_memory(cost, b"pw", &[7; 16], &mut memory)
        .unwrap();
    assert!(memory.iter().all(|b| b.as_ref().iter().all(|&w| w == 0)));
}

/// The pool really caps the threads lane work runs on.
#[test]
fn pool_caps_threads() {
    for threads in [1, 2, 4] {
        assert_eq!(Pool::new(threads).unwrap().threads_inside(), threads);
    }
}

/// The pool size is an implementation choice; the lane count is part of the hash. A KEK must not
/// depend on how many threads computed it, or a wrapper would not open on another host.
#[test]
fn kek_depends_on_lanes_not_on_pool_threads() {
    let cost = Cost::new(8, 1, 4);
    let keks: Vec<_> = [1, 2, 4]
        .into_iter()
        .map(|threads| {
            *Pool::new(threads)
                .unwrap()
                .derive(cost, b"pw", &[7; 16])
                .unwrap()
        })
        .collect();
    assert!(keks.windows(2).all(|pair| pair[0] == pair[1]));
    let two_lanes = Pool::new(4)
        .unwrap()
        .derive(Cost::new(8, 1, 2), b"pw", &[7; 16])
        .unwrap();
    assert_ne!(*two_lanes, keks[0]);
}

#[test]
fn floor_is_each_rfc9106_option_in_memory_and_passes() {
    for set in PUBLISHED.iter().filter(|set| set.floor) {
        let option = set.cost;
        assert!(
            guidance::floor_violation(option).is_none(),
            "{}",
            set.source
        );
        let fewer_passes = Cost {
            t: option.t - 1,
            ..option
        };
        if fewer_passes.t > 0 {
            assert!(
                guidance::floor_violation(Cost {
                    m_kib: option.m_kib.min(1024 * MIB),
                    ..fewer_passes
                })
                .is_some()
            );
        }
    }
    // Memory alone: more passes do not buy back memory below the smallest option.
    assert!(guidance::floor_violation(Cost::new(63, 4, 4)).is_some());
    // Passes alone: below 2 GiB, fewer than three passes are below the floor.
    assert!(guidance::floor_violation(Cost::new(1024, 2, 4)).is_some());
    assert!(guidance::floor_violation(Cost::new(64, 3, 1)).is_none());
}

#[test]
fn only_floor_sets_meet_the_floor() {
    for set in &PUBLISHED {
        assert_eq!(
            guidance::floor_violation(set.cost).is_none(),
            set.floor,
            "{}",
            set.source
        );
    }
}

#[test]
fn ceiling_refuses_oversized_headers() {
    let at_ceiling = Cost {
        m_kib: guidance::CEILING_M_KIB,
        t: 3,
        p: guidance::CEILING_P,
    };
    assert!(guidance::header_violation(at_ceiling).is_none());
    for oversized in [
        Cost {
            m_kib: guidance::CEILING_M_KIB + MIB,
            ..at_ceiling
        },
        Cost { t: 5, ..at_ceiling },
        Cost {
            p: guidance::CEILING_P + 1,
            ..at_ceiling
        },
    ] {
        assert!(
            guidance::ceiling_violation(oversized).is_some(),
            "{oversized}"
        );
    }
}

/// A header outside [floor, ceiling] is refused before it takes a slot of the limiter.
#[test]
fn unlock_refuses_a_bad_header_before_queuing() {
    let limiter = Limiter::new(1, Duration::from_millis(10));
    let held = limiter.acquire().unwrap();
    let pool = Pool::new(1).unwrap();
    for cost in [Cost::new(32, 3, 4), Cost::new(4096, 1, 4)] {
        let result = unlock(&limiter, &pool, cost, b"pw", &[7; 16]);
        assert!(matches!(result, Err(UnlockError::Header(_))), "{cost}");
    }
    drop(held);
}

#[test]
fn limiter_never_exceeds_its_limit_and_wakes_waiters() {
    let limiter = Limiter::new(2, Duration::from_secs(10));
    let barrier = Barrier::new(6);
    let started = Instant::now();
    thread::scope(|scope| {
        for _ in 0..6 {
            scope.spawn(|| {
                barrier.wait();
                let _permit = limiter.acquire().unwrap();
                thread::sleep(Duration::from_millis(20));
            });
        }
    });
    assert_eq!(limiter.peak(), 2);
    // Three rounds of 20 ms; a waiter left asleep until its 10 s bound would show here.
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn limiter_admits_in_arrival_order() {
    let limiter = Limiter::new(1, Duration::from_secs(10));
    let held = limiter.acquire().unwrap();
    let order = Mutex::new(Vec::new());
    thread::scope(|scope| {
        for _ in 0..5 {
            scope.spawn(|| {
                let permit = limiter.acquire().unwrap();
                order.lock().unwrap().push(permit.ticket);
            });
            // Let this request take its ticket before the next one arrives.
            thread::sleep(Duration::from_millis(20));
        }
        drop(held);
    });
    let order = order.into_inner().unwrap();
    assert_eq!(order, vec![1, 2, 3, 4, 5]);
}

#[test]
fn limiter_refuses_after_the_wait_bound_and_skips_the_abandoned_ticket() {
    let limiter = Limiter::new(1, Duration::from_millis(50));
    let held = limiter.acquire().unwrap();
    let refused = thread::scope(|scope| scope.spawn(|| limiter.acquire().err()).join().unwrap());
    let refused = refused.expect("a second request must be refused while the slot is held");
    assert!(refused.waited >= Duration::from_millis(50));
    drop(held);
    let started = Instant::now();
    let next = limiter
        .acquire()
        .expect("the abandoned ticket must not block the queue");
    assert_eq!(next.ticket, 2);
    assert!(started.elapsed() < Duration::from_millis(50));
}

#[test]
fn nearest_rank_percentiles() {
    let durations: Vec<Duration> = (1..=20).map(Duration::from_millis).collect();
    let s = summarise(&durations).unwrap();
    assert_eq!(s.samples, 20);
    assert_eq!(s.median_ms, 10.0);
    assert_eq!(s.p95_ms, 19.0);
    assert_eq!(s.max_ms, 20.0);
    assert!(summarise(&[]).is_none());
}
