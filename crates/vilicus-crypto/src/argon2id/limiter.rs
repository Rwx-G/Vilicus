//! The one limiter every Argon2id derivation of the Core goes through (D128, AD-9, DC-80): at most
//! [`ARGON2ID_CONCURRENCY_LIMIT`] derivations at once, whose working memory together stays within
//! [`ARGON2ID_MEMORY_BUDGET_KIB`], admitted strictly in arrival order, and a request that cannot
//! start within [`ARGON2ID_QUEUE_WAIT`] refused as retryable.
//!
//! Admission is a future, so a request waits without holding a thread: the Core awaits it on an
//! async worker before it takes a thread of the blocking pool for the derivation, and no worker
//! thread blocks (D128). The future needs no particular runtime: the runtime gives it a timer, the
//! function [`admit_derivation`] calls with the wait bound, and a request whose timer fires first leaves the
//! queue refused, its waited time in no error. A dropped request leaves the queue too.
//!
//! The queue is strict: only the oldest request may start, even when a smaller one behind it
//! would fit the budget, so a request at the ceiling's memory is never overtaken indefinitely.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use vilicus_types::{ARGON2ID_CONCURRENCY_LIMIT, ARGON2ID_MEMORY_BUDGET_KIB, ARGON2ID_QUEUE_WAIT};

use super::CheckedCost;
use crate::error::CryptoError;

#[cfg(test)]
mod tests;

/// The limiter of the process: the only one the Core's derivations are admitted by.
static LIMITER: DerivationLimiter = DerivationLimiter::new(
    ARGON2ID_CONCURRENCY_LIMIT,
    ARGON2ID_MEMORY_BUDGET_KIB,
    ARGON2ID_QUEUE_WAIT,
);

/// A request for one derivation of `cost` from the process's limiter, queued behind every request
/// made before it: a future that resolves to a [`DerivationPermit`] once the request is the oldest
/// and both the concurrency limit and the memory budget have room, or to
/// [`CryptoError::Argon2idBusy`] once the timer `sleep` makes for [`ARGON2ID_QUEUE_WAIT`] fires
/// first. `cost` passed the floor and the ceiling before the request was made, so a header outside
/// them is never queued.
///
/// The Core gives the timer of its runtime, `tokio::time::sleep` (story 5.1).
pub fn admit_derivation<T: Future<Output = ()>>(
    cost: &CheckedCost,
    sleep: impl FnOnce(Duration) -> T,
) -> Admission<'static, T> {
    LIMITER.admit(cost, sleep)
}

/// The limiter's state, behind its lock.
struct State {
    /// The ticket the next request gets.
    next_ticket: u64,
    /// The requests not yet admitted, oldest first.
    waiting: VecDeque<Waiting>,
    /// Derivations admitted and not yet ended.
    running: usize,
    /// KiB of working memory the running derivations hold.
    memory_kib: u64,
    /// The most derivations ever running at once, for the tests.
    peak_running: usize,
    /// The most working memory ever held at once, in KiB, for the tests.
    peak_memory_kib: u64,
    /// The tickets admitted, in the order they were, for the tests.
    #[cfg(test)]
    admitted: Vec<u64>,
}

/// A request in the queue.
struct Waiting {
    ticket: u64,
    /// Woken when the request may have become admissible: when it reached the head of the queue,
    /// or when a derivation ended.
    waker: Option<Waker>,
}

/// A limiter of derivations: the process has one (`LIMITER`); the tests make their own.
pub(crate) struct DerivationLimiter {
    limit: usize,
    budget_kib: u64,
    wait: Duration,
    state: Mutex<State>,
}

impl DerivationLimiter {
    pub(crate) const fn new(limit: usize, budget_kib: u64, wait: Duration) -> Self {
        Self {
            limit,
            budget_kib,
            wait,
            state: Mutex::new(State {
                next_ticket: 0,
                waiting: VecDeque::new(),
                running: 0,
                memory_kib: 0,
                peak_running: 0,
                peak_memory_kib: 0,
                #[cfg(test)]
                admitted: Vec::new(),
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues a request for a derivation of `cost`, as [`admit_derivation`] does on the process's limiter.
    pub(crate) fn admit<T: Future<Output = ()>>(
        &self,
        cost: &CheckedCost,
        sleep: impl FnOnce(Duration) -> T,
    ) -> Admission<'_, T> {
        let ticket = {
            let mut state = self.state();
            let ticket = state.next_ticket;
            state.next_ticket += 1;
            state.waiting.push_back(Waiting {
                ticket,
                waker: None,
            });
            ticket
        };
        Admission {
            limiter: self,
            ticket,
            cost: *cost,
            timer: Some(Box::pin(sleep(self.wait))),
        }
    }

    /// Wakes the oldest request, which may now be admissible.
    fn wake_head(state: &mut State) {
        if let Some(waker) = state.waiting.front_mut().and_then(|head| head.waker.take()) {
            waker.wake();
        }
    }

    /// Removes `ticket` from the queue, waking the next request when it was the oldest.
    fn leave(&self, ticket: u64) {
        let mut state = self.state();
        if let Some(position) = state.waiting.iter().position(|w| w.ticket == ticket) {
            state.waiting.remove(position);
            if position == 0 {
                Self::wake_head(&mut state);
            }
        }
    }

    /// The most derivations and the most working memory, in KiB, ever admitted at once.
    #[cfg(test)]
    pub(crate) fn peaks(&self) -> (usize, u64) {
        let state = self.state();
        (state.peak_running, state.peak_memory_kib)
    }

    /// The tickets admitted so far, in admission order; tickets count requests from 0.
    #[cfg(test)]
    pub(crate) fn admitted(&self) -> Vec<u64> {
        self.state().admitted.clone()
    }
}

/// A request queued by [`admit_derivation`], resolved once: to a permit, or to a refusal when its timer fires
/// first. Dropping it before it resolves takes it out of the queue.
pub struct Admission<'l, T> {
    limiter: &'l DerivationLimiter,
    ticket: u64,
    cost: CheckedCost,
    /// The wait bound's timer; `None` once the request resolved.
    timer: Option<Pin<Box<T>>>,
}

impl<'l, T: Future<Output = ()>> Future for Admission<'l, T> {
    type Output = Result<DerivationPermit<'l>, CryptoError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        // Every field is Unpin (the timer is boxed), so the admission is too.
        let this = self.get_mut();
        if this.timer.is_none() {
            return Poll::Ready(Err(CryptoError::Argon2idBusy));
        }
        {
            let limiter = this.limiter;
            let mut state = limiter.state();
            let fits = state.running < limiter.limit
                && state.memory_kib + this.cost.working_memory_kib() <= limiter.budget_kib;
            match state.waiting.front_mut() {
                Some(head) if head.ticket == this.ticket && fits => {
                    state.waiting.pop_front();
                    state.running += 1;
                    state.memory_kib += this.cost.working_memory_kib();
                    state.peak_running = state.peak_running.max(state.running);
                    state.peak_memory_kib = state.peak_memory_kib.max(state.memory_kib);
                    #[cfg(test)]
                    state.admitted.push(this.ticket);
                    // The next request may fit beside this one.
                    DerivationLimiter::wake_head(&mut state);
                    this.timer = None;
                    return Poll::Ready(Ok(DerivationPermit {
                        limiter,
                        cost: this.cost,
                    }));
                }
                _ => {
                    // Stored under the lock that checked admissibility, so a derivation that ends
                    // after the check finds the waker and none is lost.
                    if let Some(waiting) =
                        state.waiting.iter_mut().find(|w| w.ticket == this.ticket)
                    {
                        waiting.waker = Some(context.waker().clone());
                    }
                }
            }
        }
        let fired = this
            .timer
            .as_mut()
            .is_some_and(|timer| timer.as_mut().poll(context).is_ready());
        if fired {
            this.timer = None;
            this.limiter.leave(this.ticket);
            return Poll::Ready(Err(CryptoError::Argon2idBusy));
        }
        Poll::Pending
    }
}

impl<T> Drop for Admission<'_, T> {
    fn drop(&mut self) {
        if self.timer.is_some() {
            self.limiter.leave(self.ticket);
        }
    }
}

/// The admission of one derivation of one cost: held while that derivation runs, on the thread of
/// the blocking pool it runs on, and released when dropped, which may admit the next request.
pub struct DerivationPermit<'l> {
    limiter: &'l DerivationLimiter,
    cost: CheckedCost,
}

impl DerivationPermit<'_> {
    /// Refuses a derivation of another cost than the one admitted, whose memory the budget did not
    /// count.
    pub(crate) fn check(&self, cost: &CheckedCost) -> Result<(), CryptoError> {
        if self.cost == *cost {
            Ok(())
        } else {
            Err(CryptoError::PermitMismatch)
        }
    }
}

impl Drop for DerivationPermit<'_> {
    fn drop(&mut self) {
        let mut state = self.limiter.state();
        state.running -= 1;
        state.memory_kib -= self.cost.working_memory_kib();
        DerivationLimiter::wake_head(&mut state);
    }
}
