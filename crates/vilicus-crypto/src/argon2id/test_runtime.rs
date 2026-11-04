//! What a test needs to await an admission of the limiter without an async runtime, which the
//! workspace does not have before story 5.1: a thread that polls one future until it resolves,
//! and a timer whose thread wakes it. Test builds and the `testing` feature only.

use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::Duration;

/// Wakes the thread that polls the future.
struct Unpark(Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Polls `future` on this thread, parked between wakes, until it resolves.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        thread::park();
    }
}

/// Whether the timer fired, and the waker of its last poll.
type TimerState = Arc<Mutex<(bool, Option<Waker>)>>;

/// A timer that fires `duration` after it is made, from a thread of its own.
pub struct Sleep {
    state: TimerState,
}

/// A timer that fires `duration` after this call: the timer an admission is given in tests.
pub fn sleep(duration: Duration) -> Sleep {
    let state: TimerState = Arc::new(Mutex::new((false, None)));
    let fired = Arc::clone(&state);
    thread::spawn(move || {
        thread::sleep(duration);
        let mut state = fired.lock().unwrap_or_else(PoisonError::into_inner);
        state.0 = true;
        if let Some(waker) = state.1.take() {
            waker.wake();
        }
    });
    Sleep { state }
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: std::pin::Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.0 {
            return Poll::Ready(());
        }
        state.1 = Some(context.waker().clone());
        Poll::Pending
    }
}
