//! Key memory: the locked pool every key buffer of the crate lives in, and the process rules that
//! keep its bytes there (spine AD-4, D131, Story 1.10).
//!
//! - [`harden_process`] makes the process non-dumpable and sets its core size limit to 0, so no
//!   core dump is written and no process of the same user without `CAP_SYS_PTRACE` opens its
//!   memory from then on. The kernel resets the dumpable flag on `execve` and on a change of
//!   credentials, so the Core does neither afterwards.
//! - [`lock_key_memory`] maps the process's one pool, before any key exists: an anonymous mapping
//!   framed by a `PROT_NONE` guard page on each side, advised `MADV_DONTDUMP` and
//!   `MADV_WIPEONFORK`, locked with `mlock` and cut into [`PLANNED_SLOTS`] slots of
//!   [`KEY_LEN`] bytes. It refuses a process that is not hardened or that holds `CAP_IPC_LOCK`,
//!   refuses a second pool, and refuses, never replaces by unlocked memory, a pool `mlock` turns
//!   down. Without a pool no key can be created.
//! - A [`Slot`] is one key buffer of the pool, wiped with volatile writes when it is dropped. Its
//!   bytes are lent only through [`Slot::with_key`] and [`Slot::with_key_mut`], which run the
//!   closure under the guard of [`guarded`]: once the outermost guarded call returns or unwinds,
//!   [`STACK_SCRUB_LEN`] bytes of stack below it are overwritten and the AVX registers zeroed.
//! - [`take_sigterm`] blocks SIGTERM and takes it on a thread of its own, which wipes the pool
//!   before the orderly shutdown; [`install_panic_hook`] wipes the pool and aborts on a panic
//!   outside a module handler. Once wiped, the pool hands out no slot.
//!
//! This is the crate's only module with unsafe code (D140; `ci/crate_graph.toml` lists it): each
//! block is a system call or a raw access to the mapping, with its `// SAFETY:` comment.

use std::cell::Cell;
use std::fs;
use std::io;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use zeroize::Zeroize;

use crate::error::{CryptoError, KeyMemoryError};
use crate::key::KEY_LEN;

#[cfg(feature = "testing")]
pub mod testing;

#[cfg(test)]
mod tests;

/// Adults the pool is sized for: the most members unlocked at once that the instance plans for.
const PLANNED_ADULTS: usize = 8;

/// The keys each unlocked adult holds for as long as they are unlocked: the DEK, the household
/// key and the member private key.
const KEYS_PER_ADULT: usize = 3;

/// File keys each unlocked adult holds open at once.
const FILE_KEYS_PER_ADULT: usize = 16;

/// The working buffers of each adult's operations in progress: the transient slot of a wrap's
/// seal, the new key of an unwrap or a derivation.
const TRANSIENT_SLOTS_PER_ADULT: usize = 4;

/// The keys of the instance itself: the instance key, the home partition root and the audit key.
const INSTANCE_KEYS: usize = 3;

/// The working buffers of the instance's own operations.
const INSTANCE_TRANSIENT_SLOTS: usize = 5;

/// Slots of the key pool: for each planned adult, the keys they hold, their open file keys and
/// their transient slots, then the instance's keys and transient slots (D131's sizing rule). The
/// pool holds exactly this many; one more is refused.
pub const PLANNED_SLOTS: usize = PLANNED_ADULTS
    * (KEYS_PER_ADULT + FILE_KEYS_PER_ADULT + TRANSIENT_SLOTS_PER_ADULT)
    + INSTANCE_KEYS
    + INSTANCE_TRANSIENT_SLOTS;

/// Bytes of stack the guard of a key operation overwrites below the guarded call once it returns.
pub const STACK_SCRUB_LEN: usize = 64 * 1024;

/// Bytes the scrub must reach beyond the deepest stack use measured for a key operation: a key
/// operation whose depth plus this margin exceeds [`STACK_SCRUB_LEN`] fails its stack canary
/// check (Story 4.2, AC8).
pub const STACK_SCRUB_MARGIN: usize = 8 * 1024;

/// `CAP_IPC_LOCK`'s bit in the capability sets of `/proc/self/status`.
const CAP_IPC_LOCK: u32 = 14;

/// The process's key pool, once [`lock_key_memory`] mapped it.
static POOL: OnceLock<Pool> = OnceLock::new();

/// Held while a pool is being mapped, so that two callers cannot map one each.
static LOCKING: Mutex<()> = Mutex::new(());

/// The last `errno` of this thread.
fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Turns core dumps and same-user memory access off for this process: `PR_SET_DUMPABLE` 0, then
/// `RLIMIT_CORE` 0, soft and hard. The Core calls it first, before it reads the instance key,
/// and [`lock_key_memory`] refuses a process that has not. Non-dumpable is the barrier:
/// `RLIMIT_CORE` 0 alone does not stop a pipe `core_pattern`, which the kernel feeds whatever
/// the limit (Story 1.10, Debian 13 VM run). A descriptor on the process's memory or a ptrace
/// attach taken before this call keeps working, so the Core runs under a user that runs nothing
/// else (D131).
#[allow(unsafe_code)] // prctl and setrlimit, which std does not wrap (D131).
pub fn harden_process() -> Result<(), KeyMemoryError> {
    // SAFETY: prctl with integer arguments only; PR_SET_DUMPABLE reads its second argument as an
    // unsigned long, so every argument is passed at that width.
    let set = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) };
    if set != 0 {
        return Err(KeyMemoryError::Harden { errno: errno() });
    }
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `no_core` is an initialised rlimit that outlives the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0 {
        return Err(KeyMemoryError::Harden { errno: errno() });
    }
    Ok(())
}

/// Whether the process is non-dumpable and may write no core file, as [`harden_process`] left it.
#[allow(unsafe_code)] // prctl and getrlimit, which std does not wrap.
fn is_hardened() -> Result<bool, KeyMemoryError> {
    // SAFETY: prctl with integer arguments only.
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) };
    let mut core = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    // SAFETY: `core` is a valid out-pointer for the duration of the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core) } != 0 {
        return Err(KeyMemoryError::Harden { errno: errno() });
    }
    Ok(dumpable == 0 && core.rlim_cur == 0 && core.rlim_max == 0)
}

/// The value of `field` (for example `CapEff:`) in `/proc/self/status`.
fn status_field(field: &str) -> Result<String, KeyMemoryError> {
    let status =
        fs::read_to_string("/proc/self/status").map_err(|error| KeyMemoryError::ProcessStatus {
            errno: error.raw_os_error().unwrap_or(0),
        })?;
    status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .map(|value| value.trim().to_string())
        .ok_or(KeyMemoryError::ProcessStatus { errno: 0 })
}

/// Whether `CAP_IPC_LOCK` is in the process's effective capabilities.
fn holds_cap_ipc_lock() -> Result<bool, KeyMemoryError> {
    let effective = status_field("CapEff:")?;
    let set = u64::from_str_radix(&effective, 16)
        .map_err(|_| KeyMemoryError::ProcessStatus { errno: 0 })?;
    Ok(set & (1 << CAP_IPC_LOCK) != 0)
}

/// Maps, advises and locks the process's key pool, before any key exists: the one pool every
/// key of the crate is created in, sized [`PLANNED_SLOTS`] slots. The Core calls it at start,
/// after [`harden_process`], and does not start when it fails:
/// - [`KeyMemoryError::NotHardened`] if the process is still dumpable or may write a core file;
/// - [`KeyMemoryError::CapIpcLock`] if it holds `CAP_IPC_LOCK`, which the Core's unit never
///   grants and which would make its `LimitMEMLOCK` bound nothing;
/// - [`KeyMemoryError::Lock`] if `mlock` refuses the pool: there is no fallback to unlocked
///   memory, and until a pool is locked every key creation fails with
///   [`KeyMemoryError::NotLocked`];
/// - [`KeyMemoryError::AlreadyLocked`] for a second pool.
///
/// ```
/// vilicus_crypto::harden_process()?;
/// vilicus_crypto::lock_key_memory()?;
/// assert_eq!(
///     vilicus_crypto::lock_key_memory(),
///     Err(vilicus_crypto::KeyMemoryError::AlreadyLocked)
/// );
/// let key = vilicus_crypto::SymmetricKey::generate()?;
/// # drop(key);
/// # Ok::<(), vilicus_crypto::CryptoError>(())
/// ```
pub fn lock_key_memory() -> Result<(), KeyMemoryError> {
    let _locking = LOCKING.lock().unwrap_or_else(PoisonError::into_inner);
    if POOL.get().is_some() {
        return Err(KeyMemoryError::AlreadyLocked);
    }
    if !is_hardened()? {
        return Err(KeyMemoryError::NotHardened);
    }
    if holds_cap_ipc_lock()? {
        return Err(KeyMemoryError::CapIpcLock);
    }
    let pool = Pool::map(PLANNED_SLOTS)?;
    POOL.set(pool).map_err(|_| KeyMemoryError::AlreadyLocked)
}

/// Overwrites the whole pool with zeroes and refuses every slot from then on: for the panic hook
/// and the SIGTERM thread only, as the process ends. A thread still using a slot races with the
/// wipe, which is acceptable only because no key operation is meant to start afterwards.
fn wipe_key_memory() {
    if let Some(pool) = POOL.get() {
        pool.wipe_all();
    }
}

/// Blocks SIGTERM and takes it on a thread of its own: when it arrives, the thread wipes the pool
/// and then runs `on_term`, the Core's orderly shutdown. It must be called while the process has
/// one thread, since a thread spawned before it would still receive SIGTERM: it is refused with
/// [`KeyMemoryError::ThreadsRunning`] otherwise. Every thread spawned afterwards inherits the
/// blocked signal, so only that thread takes it.
#[allow(unsafe_code)] // pthread_sigmask, signalfd and read, which std does not wrap (D131).
pub fn take_sigterm(on_term: impl FnOnce() + Send + 'static) -> Result<(), KeyMemoryError> {
    let threads: usize = status_field("Threads:")?
        .parse()
        .map_err(|_| KeyMemoryError::ProcessStatus { errno: 0 })?;
    if threads != 1 {
        return Err(KeyMemoryError::ThreadsRunning { threads });
    }
    // SAFETY: an all-zero sigset_t is a valid value to initialise with sigemptyset.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is a valid sigset_t for both calls, which only write into it.
    let built = unsafe {
        libc::sigemptyset(&mut set) == 0 && libc::sigaddset(&mut set, libc::SIGTERM) == 0
    };
    if !built {
        return Err(KeyMemoryError::Sigterm { errno: errno() });
    }
    // SAFETY: `set` is initialised; the previous mask is not asked for.
    let blocked = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
    if blocked != 0 {
        return Err(KeyMemoryError::Sigterm { errno: blocked });
    }
    // SAFETY: `set` is initialised; -1 asks for a new descriptor.
    let descriptor = unsafe { libc::signalfd(-1, &set, libc::SFD_CLOEXEC) };
    if descriptor < 0 {
        return Err(KeyMemoryError::Sigterm { errno: errno() });
    }
    std::thread::Builder::new()
        .name("vilicus-sigterm".to_string())
        .spawn(move || {
            let mut info = [0_u8; size_of::<libc::signalfd_siginfo>()];
            loop {
                // SAFETY: reads at most `info.len()` bytes into `info`, from the descriptor this
                // thread owns.
                let read = unsafe { libc::read(descriptor, info.as_mut_ptr().cast(), info.len()) };
                if read < 0 && errno() == libc::EINTR {
                    continue;
                }
                break;
            }
            wipe_key_memory();
            on_term();
        })
        .map_err(|error| KeyMemoryError::Sigterm {
            errno: error.raw_os_error().unwrap_or(0),
        })?;
    Ok(())
}

/// What a panic hook observes between the wipe and the abort, in the regression harness only.
#[cfg(feature = "testing")]
static PANIC_OBSERVER: OnceLock<fn()> = OnceLock::new();

/// Installs the Core's panic hook (AD-9, D131). A panic while `in_handler_boundary` is true, on a
/// thread running a module's code inside its boundary, is left to unwind to the boundary, so the
/// keys stay; any other panic wipes the pool and aborts, with no I/O.
pub fn install_panic_hook(in_handler_boundary: fn() -> bool) {
    std::panic::set_hook(Box::new(move |_| {
        if in_handler_boundary() {
            return;
        }
        wipe_key_memory();
        #[cfg(feature = "testing")]
        if let Some(observe) = PANIC_OBSERVER.get() {
            observe();
        }
        std::process::abort();
    }));
}

/// The pool: a locked mapping of whole pages between two guard pages, and which of its slots are
/// in use.
struct Pool {
    /// The first byte after the low guard page.
    base: NonNull<u8>,
    /// Bytes between the guard pages: what is advised, locked and wiped.
    len: usize,
    /// One flag per slot, set while a [`Slot`] owns it.
    in_use: Mutex<Vec<bool>>,
    /// Set by [`Pool::wipe_all`]; no slot is handed out afterwards.
    wiped: AtomicBool,
}

#[allow(unsafe_code)] // the pool shares its raw mapping between threads.
// SAFETY: `base` and `len` never change after `map`, and the mapping is never unmapped. A slot's
// bytes are reached only through the one `Slot` that owns its index, handed out under the
// `in_use` lock; `wipe_all` writes with volatile stores and runs only as the process ends.
unsafe impl Send for Pool {}
#[allow(unsafe_code)] // the pool shares its raw mapping between threads.
// SAFETY: as for `Send`; shared access goes through `in_use`, `wiped` or a `Slot`.
unsafe impl Sync for Pool {}

impl Pool {
    /// Maps a pool of `slots` slots: whole pages between two `PROT_NONE` guard pages, advised
    /// `MADV_DONTDUMP` and `MADV_WIPEONFORK`, then locked. On any failure the mapping is undone.
    #[allow(unsafe_code)] // mmap, mprotect, madvise and mlock of the pool (D131).
    fn map(slots: usize) -> Result<Self, KeyMemoryError> {
        // SAFETY: sysconf with a valid name.
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok()
            .filter(|page| *page > 0)
            .ok_or(KeyMemoryError::Map { errno: errno() })?;
        let len = (slots * KEY_LEN).div_ceil(page) * page;
        let total = len + 2 * page;
        // SAFETY: a new private anonymous mapping with no address hint; the result is compared
        // with MAP_FAILED before any use.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(KeyMemoryError::Map { errno: errno() });
        }
        let undo = |error: KeyMemoryError| {
            // SAFETY: `mapping` and `total` are the mapping made above, which holds no key yet.
            unsafe { libc::munmap(mapping, total) };
            error
        };
        let low_guard = mapping.cast::<u8>();
        // SAFETY: both offsets stay inside the mapping of `total` bytes made above.
        let (base, high_guard) = unsafe { (low_guard.add(page), low_guard.add(page + len)) };
        for guard in [low_guard, high_guard] {
            // SAFETY: one whole page inside the mapping made above.
            if unsafe { libc::mprotect(guard.cast(), page, libc::PROT_NONE) } != 0 {
                return Err(undo(KeyMemoryError::Map { errno: errno() }));
            }
        }
        for (advice, name) in [
            (libc::MADV_DONTDUMP, "MADV_DONTDUMP"),
            (libc::MADV_WIPEONFORK, "MADV_WIPEONFORK"),
        ] {
            // SAFETY: the pages between the guard pages, inside the mapping made above.
            if unsafe { libc::madvise(base.cast(), len, advice) } != 0 {
                return Err(undo(KeyMemoryError::Advise {
                    advice: name,
                    errno: errno(),
                }));
            }
        }
        // SAFETY: the pages between the guard pages, inside the mapping made above.
        if unsafe { libc::mlock(base.cast(), len) } != 0 {
            return Err(undo(KeyMemoryError::Lock {
                bytes: len,
                errno: errno(),
            }));
        }
        Ok(Self {
            base: NonNull::new(base).ok_or(KeyMemoryError::Map { errno: 0 })?,
            len,
            in_use: Mutex::new(vec![false; slots]),
            wiped: AtomicBool::new(false),
        })
    }

    /// A free slot, all zeroes.
    fn alloc(&'static self) -> Result<Slot, KeyMemoryError> {
        let mut in_use = self.in_use.lock().unwrap_or_else(PoisonError::into_inner);
        if self.wiped.load(Ordering::SeqCst) {
            return Err(KeyMemoryError::Wiped);
        }
        let index = in_use
            .iter()
            .position(|used| !used)
            .ok_or(KeyMemoryError::Exhausted)?;
        in_use[index] = true;
        Ok(Slot { pool: self, index })
    }

    fn release(&self, index: usize) {
        let mut in_use = self.in_use.lock().unwrap_or_else(PoisonError::into_inner);
        in_use[index] = false;
    }

    /// Refuses every later slot, then overwrites the whole pool with zeroes. It takes no lock, so
    /// a panic hook that runs while a thread holds `in_use` still wipes.
    #[allow(unsafe_code)] // volatile writes to the raw mapping.
    fn wipe_all(&self) {
        self.wiped.store(true, Ordering::SeqCst);
        for offset in 0..self.len {
            // SAFETY: `offset` is below `len`, inside the locked mapping, which stays mapped for
            // the life of the process.
            unsafe { self.base.as_ptr().add(offset).write_volatile(0) };
        }
    }
}

/// One key buffer: a slot of the pool, all zeroes when taken, wiped with volatile writes when
/// dropped. Not `Clone`, `Copy` or `Debug`. Its bytes are lent only through
/// [`with_key`](Self::with_key) and [`with_key_mut`](Self::with_key_mut), under the guard of
/// [`guarded`].
pub(crate) struct Slot {
    pool: &'static Pool,
    index: usize,
}

impl Slot {
    /// A slot of the process's pool, or the reason there is none: no pool locked yet, every slot
    /// in use, or the pool wiped.
    pub(crate) fn new() -> Result<Self, CryptoError> {
        // The unit tests run in a process the Core's start never ran in: the first slot of a test
        // hardens the process and locks its pool, as that start would.
        #[cfg(test)]
        crate::test_support::key_memory();
        let pool = POOL.get().ok_or(KeyMemoryError::NotLocked)?;
        Ok(pool.alloc()?)
    }

    /// Lends the bytes to `operation`, under the guard of [`guarded`].
    pub(crate) fn with_key<R>(&self, operation: impl FnOnce(&[u8; KEY_LEN]) -> R) -> R {
        guarded(|| operation(self.bytes()))
    }

    /// Lends the bytes to `operation`, to be written, under the guard of [`guarded`].
    pub(crate) fn with_key_mut<R>(&mut self, operation: impl FnOnce(&mut [u8; KEY_LEN]) -> R) -> R {
        guarded(|| operation(self.bytes_mut()))
    }

    #[allow(unsafe_code)] // pointer arithmetic inside the mapping.
    fn start(&self) -> *mut u8 {
        // SAFETY: `index` is below the pool's slot count, so the slot lies inside the mapping.
        unsafe { self.pool.base.as_ptr().add(self.index * KEY_LEN) }
    }

    #[allow(unsafe_code)] // the slot is a range of the raw mapping.
    fn bytes(&self) -> &[u8; KEY_LEN] {
        // SAFETY: the slot's KEY_LEN bytes lie inside the locked mapping, which is never
        // unmapped, and only this `Slot` owns its index; `&self` keeps them unwritten meanwhile.
        unsafe { &*self.start().cast::<[u8; KEY_LEN]>() }
    }

    #[allow(unsafe_code)] // the slot is a range of the raw mapping.
    fn bytes_mut(&mut self) -> &mut [u8; KEY_LEN] {
        // SAFETY: as in `bytes`, and `&mut self` makes the access exclusive.
        unsafe { &mut *self.start().cast::<[u8; KEY_LEN]>() }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.bytes_mut().zeroize();
        #[cfg(test)]
        wiped::record(self.bytes());
        self.pool.release(self.index);
    }
}

thread_local! {
    /// How many guarded calls are running on this thread, one inside another.
    static GUARDED_CALLS: Cell<usize> = const { Cell::new(0) };
}

/// The guard of one guarded call: the outermost one scrubs the stack when it is dropped, on
/// return and while a panic unwinds alike.
struct Guard {
    outermost: bool,
}

impl Guard {
    fn enter() -> Self {
        let outermost = GUARDED_CALLS.with(|calls| calls.replace(calls.get() + 1)) == 0;
        #[cfg(any(test, feature = "testing"))]
        if outermost {
            canary::paint();
        }
        Self { outermost }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if self.outermost {
            #[cfg(any(test, feature = "testing"))]
            canary::measure();
            scrub_stack();
        }
        GUARDED_CALLS.with(|calls| calls.set(calls.get() - 1));
    }
}

/// Runs `operation`, a key operation, under the guard of D131: when the outermost guarded call of
/// the thread returns or unwinds, [`STACK_SCRUB_LEN`] bytes of stack below it are overwritten
/// with zeroes and the AVX registers zeroed, so the frames of the operation and of the primitives
/// it called leave nothing behind. Never inlined, and the operation runs in a frame of its own
/// below it, so what the operation keeps in its locals lies inside the scrubbed range.
#[inline(never)]
fn guarded<R>(operation: impl FnOnce() -> R) -> R {
    let _guard = Guard::enter();
    run_below(operation)
}

#[inline(never)]
fn run_below<R>(operation: impl FnOnce() -> R) -> R {
    operation()
}

/// Overwrites [`STACK_SCRUB_LEN`] bytes of stack below the caller with zeroes, the dead frames
/// of the key operation the caller just ran, then zeroes the AVX registers, so that a signal
/// frame written later cannot spill key bytes they still hold.
#[inline(never)]
fn scrub_stack() {
    let mut area = [0_u8; STACK_SCRUB_LEN];
    area.zeroize();
    std::hint::black_box(&area);
    zero_vector_registers();
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)] // vzeroall, inline assembly (D131).
fn zero_vector_registers() {
    if std::arch::is_x86_feature_detected!("avx") {
        // SAFETY: the CPU has AVX, checked above. vzeroall writes ymm0 to ymm15 only, which
        // clobber_abi("C") declares clobbered, and touches no memory, stack or flags.
        unsafe {
            std::arch::asm!(
                "vzeroall",
                clobber_abi("C"),
                options(nostack, nomem, preserves_flags)
            );
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn zero_vector_registers() {}

/// The stack canary of the guarded calls (Story 4.2, AC8), in test builds only: before the
/// outermost guarded call runs its operation, twice [`STACK_SCRUB_LEN`] bytes below it are
/// painted with a canary byte; once the operation returned, and before the scrub, the deepest
/// byte the operation overwrote gives its stack depth.
#[cfg(any(test, feature = "testing"))]
mod canary {
    use std::cell::Cell;

    use super::STACK_SCRUB_LEN;

    const CANARY: u8 = 0xa5;
    const PAINT_LEN: usize = 2 * STACK_SCRUB_LEN;

    thread_local! {
        /// The lowest painted address, its provenance exposed.
        static PAINTED: Cell<usize> = const { Cell::new(0) };
        /// The deepest stack use measured on this thread since it was last taken.
        static DEEPEST: Cell<Option<usize>> = const { Cell::new(None) };
    }

    #[inline(never)]
    pub(super) fn paint() {
        let mut area = [CANARY; PAINT_LEN];
        std::hint::black_box(&mut area);
        PAINTED.set(area.as_mut_ptr().expose_provenance());
    }

    /// Records how far below the painted top a byte changed since [`paint`]; the whole painted
    /// length when the operation reached past it.
    #[inline(never)]
    #[allow(unsafe_code)] // reads the dead stack the canary painted (test builds only).
    pub(super) fn measure() {
        let low = PAINTED.get();
        let mut depth = 0;
        for offset in 0..PAINT_LEN {
            // SAFETY: dead stack of this thread, below the current frame, painted by `paint` and
            // still mapped; it is read only, and no other thread uses this stack.
            let byte =
                unsafe { std::ptr::with_exposed_provenance::<u8>(low + offset).read_volatile() };
            if byte != CANARY {
                depth = PAINT_LEN - offset;
                break;
            }
        }
        DEEPEST.set(Some(
            DEEPEST.get().map_or(depth, |deepest| deepest.max(depth)),
        ));
    }

    /// The deepest stack use of the guarded calls of this thread since the last call, if any ran.
    pub(crate) fn take_deepest() -> Option<usize> {
        DEEPEST.take()
    }
}

/// What every dropped [`Slot`] held once wiped, read by the tests through this hook (AC3 of
/// Story 4.1): the slot's address and a copy of its bytes, taken after the wipe and before the
/// slot is released. Recorded per thread, so concurrent tests do not see each other's.
#[cfg(test)]
pub(crate) mod wiped {
    use std::cell::RefCell;

    use super::KEY_LEN;

    thread_local! {
        static SEEN: RefCell<Vec<(usize, [u8; KEY_LEN])>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn record(bytes: &[u8; KEY_LEN]) {
        SEEN.with(|seen| seen.borrow_mut().push((bytes.as_ptr().addr(), *bytes)));
    }

    /// Every slot dropped on this thread since the last call, oldest first.
    pub(crate) fn take() -> Vec<(usize, [u8; KEY_LEN])> {
        SEEN.with(|seen| std::mem::take(&mut *seen.borrow_mut()))
    }
}
