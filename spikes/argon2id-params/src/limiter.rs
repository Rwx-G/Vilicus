//! The global concurrency limit on passphrase derivations (FR-11, architecture.md S9).
//!
//! A FIFO ticket queue with a bounded wait: requests start in arrival order, at most `limit` at
//! once, and a request that cannot start within `max_wait` is refused and leaves the queue, so an
//! authenticated caller cannot pile up unbounded work or unbounded waiters. It also records the
//! highest number of derivations it ever let run at once.
//!
//! `waited` is for measurement only; the Core never returns it to a client.

use std::collections::BTreeSet;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

pub struct Limiter {
    limit: usize,
    max_wait: Duration,
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Default)]
struct State {
    running: usize,
    peak: usize,
    next_ticket: u64,
    /// The oldest ticket not yet admitted or abandoned.
    head: u64,
    /// Tickets whose request gave up waiting, skipped when they reach the head.
    abandoned: BTreeSet<u64>,
}

impl State {
    fn skip_abandoned(&mut self) {
        while self.abandoned.remove(&self.head) {
            self.head += 1;
        }
    }
}

/// Held while a derivation runs; releases its slot on drop.
pub struct Permit<'a> {
    limiter: &'a Limiter,
    /// How long the request queued before it got the slot.
    pub waited: Duration,
    /// Arrival order of the request.
    pub ticket: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Refused {
    pub waited: Duration,
}

impl Limiter {
    pub fn new(limit: usize, max_wait: Duration) -> Self {
        assert!(
            limit > 0,
            "a concurrency limit of zero refuses every unlock"
        );
        Self {
            limit,
            max_wait,
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
        }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn acquire(&self) -> Result<Permit<'_>, Refused> {
        let started = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let ticket = state.next_ticket;
        state.next_ticket += 1;
        while ticket != state.head || state.running >= self.limit {
            let waited = started.elapsed();
            let Some(left) = self.max_wait.checked_sub(waited) else {
                state.abandoned.insert(ticket);
                state.skip_abandoned();
                self.changed.notify_all();
                return Err(Refused { waited });
            };
            state = self
                .changed
                .wait_timeout(state, left)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
        state.head += 1;
        state.skip_abandoned();
        state.running += 1;
        state.peak = state.peak.max(state.running);
        self.changed.notify_all();
        Ok(Permit {
            limiter: self,
            waited: started.elapsed(),
            ticket,
        })
    }

    /// The most derivations that ever ran at once under this limiter.
    pub fn peak(&self) -> usize {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).peak
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut state = self.limiter.state.lock().unwrap_or_else(|p| p.into_inner());
        state.running -= 1;
        self.limiter.changed.notify_all();
    }
}
