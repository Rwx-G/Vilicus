//! Key memory: the locked pool every key buffer of the crate lives in, and the process rules that
//! keep its bytes there (spine AD-4, D131, Story 1.10).
//!
//! - [`harden_process`] makes the process non-dumpable and sets its core size limit to 0, so no
//!   core dump is written and no process of the same user without `CAP_SYS_PTRACE` opens its
//!   memory from then on. The kernel resets the dumpable flag on `execve` and on a change of
//!   credentials, so the Core does neither afterwards.
//! - [`lock_key_memory`] maps the process's one pool, before any key exists: an anonymous mapping
//!   framed by a `PROT_NONE` guard page on each side, advised `MADV_DONTDUMP` and
//!   `MADV_WIPEONFORK`, locked with `mlock`, and cut into two classes of slots: [`PLANNED_SLOTS`]
//!   slots of [`KEY_LEN`] bytes for keys, and [`PLANNED_TEXT_SLOTS`] slots that hold a key's
//!   SQLCipher key text ([`SQLCIPHER_KEY_TEXT_LEN`] bytes). It refuses a process that is not
//!   hardened or that holds `CAP_IPC_LOCK`, refuses a second pool, and refuses, never replaces by
//!   unlocked memory, a pool `mlock` turns down. Without a pool no key can be created.
//! - A [`Slot`] is one buffer of the pool, wiped with volatile writes when it is dropped. Its
//!   bytes are lent only through [`Slot::with_key`] and [`Slot::with_key_mut`], which run the
//!   closure under the guard of [`guarded`] and fail once the pool is wiped: once the outermost
//!   guarded call returns or unwinds, [`STACK_SCRUB_LEN`] bytes of stack below it are
//!   overwritten and the AVX registers zeroed.
//! - [`take_sigterm`] blocks SIGTERM and takes it on a thread of its own, which wipes the pool
//!   before the orderly shutdown; [`install_panic_hook`] wipes the pool and aborts on a panic
//!   outside a module handler. [`start_key_memory`] runs the four steps in the Core's order.
//! - A [`WorkingMemory`] is the locked mapping of one Argon2id derivation, too large for a slot:
//!   its blocks and its passphrase, framed, advised and locked as the pool is, refused rather than
//!   left unlocked, and wiped then unmapped when dropped (Story 4.4).
//!
//! A wipe first marks the pool wiped, so that no slot is handed out and no guarded call starts,
//! then waits up to [`WIPE_WAIT`] for the guarded calls and slot wipes in progress to end, then
//! overwrites the pool. A guarded call that was running when the pool was marked returns
//! [`KeyMemoryError::Wiped`] instead of its result, whether it ended before the overwrite or not:
//! no key operation returns a result computed from keys that were being wiped.
//!
//! Not covered (outside D131's claim): the AVX-512 registers zmm16 to zmm31 and the mask registers,
//! which `vzeroall` leaves; a CPU without AVX, on which no vector register is zeroed; the stack
//! depth of a key operation, which the canary of the tests measures but nothing bounds at run
//! time, so an operation deeper than the scrub leaves the frames below it unscrubbed.
//!
//! This is the crate's only module with unsafe code (D140; `ci/crate_graph.toml` lists it): each
//! block is a system call or a raw access to the mapping, allowed on its own statement and with
//! its `// SAFETY:` comment.

use std::cell::{Cell, RefCell};
use std::fs;
use std::io;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use argon2::Block;
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
/// seal, the new key of an unwrap or a derivation, the key text of a file being keyed.
const TRANSIENT_SLOTS_PER_ADULT: usize = 4;

/// The keys of the instance itself: the instance key, the home partition root and the audit key.
const INSTANCE_KEYS: usize = 3;

/// The working buffers of the instance's own operations.
const INSTANCE_TRANSIENT_SLOTS: usize = 5;

/// Slots of the key class: for each planned adult, the keys they hold, their open file keys and
/// their transient slots, then the instance's keys and transient slots (D131's sizing rule). The
/// pool holds exactly this many; one more is refused.
pub const PLANNED_SLOTS: usize = PLANNED_ADULTS
    * (KEYS_PER_ADULT + FILE_KEYS_PER_ADULT + TRANSIENT_SLOTS_PER_ADULT)
    + INSTANCE_KEYS
    + INSTANCE_TRANSIENT_SLOTS;

/// Bytes of SQLCipher's raw key text of a key: `x'`, the key's lowercase hex digits, then `'`.
pub const SQLCIPHER_KEY_TEXT_LEN: usize = 2 + 2 * KEY_LEN + 1;

/// Bytes of a slot of the text class: the key text, rounded up to 16.
pub(crate) const TEXT_SLOT_LEN: usize = SQLCIPHER_KEY_TEXT_LEN.next_multiple_of(16);

/// Slots of the text class. A key text exists only while a file is being keyed, a transient
/// buffer, so the class holds the planned transient slots of the adults and of the instance.
pub const PLANNED_TEXT_SLOTS: usize =
    PLANNED_ADULTS * TRANSIENT_SLOTS_PER_ADULT + INSTANCE_TRANSIENT_SLOTS;

/// The slot classes, by class index: the bytes of one slot and how many the pool holds.
const CLASSES: [(usize, usize); 2] = [
    (KEY_LEN, PLANNED_SLOTS),
    (TEXT_SLOT_LEN, PLANNED_TEXT_SLOTS),
];

/// Bytes of stack the guard of a key operation overwrites below the guarded call once it returns.
pub const STACK_SCRUB_LEN: usize = 64 * 1024;

/// Bytes the scrub must reach beyond the deepest stack use measured for a key operation: a key
/// operation whose depth plus this margin exceeds [`STACK_SCRUB_LEN`] fails its stack canary
/// check (Story 4.2, AC8).
pub const STACK_SCRUB_MARGIN: usize = 8 * 1024;

/// How long a wipe waits for the guarded calls and slot wipes in progress before it overwrites
/// the pool anyway. Today's key operations take microseconds; a longer one past this bound races
/// with the overwrite, and its result is discarded (the module documentation).
pub const WIPE_WAIT: Duration = Duration::from_secs(1);

/// `CAP_IPC_LOCK`'s bit in the capability sets of `/proc/self/status`.
const CAP_IPC_LOCK: u32 = 14;

/// The capability sets of `/proc/self/status` that must not hold `CAP_IPC_LOCK`: effective, and
/// those from which it could become effective again.
const CAPABILITY_SETS: [&str; 3] = ["CapEff:", "CapPrm:", "CapAmb:"];

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
pub fn harden_process() -> Result<(), KeyMemoryError> {
    #[allow(unsafe_code)] // prctl, which std does not wrap (D131).
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
    #[allow(unsafe_code)] // setrlimit, which std does not wrap (D131).
    // SAFETY: `no_core` is an initialised rlimit that outlives the call.
    let limited = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) };
    if limited != 0 {
        return Err(KeyMemoryError::Harden { errno: errno() });
    }
    Ok(())
}

/// Whether the process is non-dumpable and may write no core file, as [`harden_process`] left it.
fn is_hardened() -> Result<bool, KeyMemoryError> {
    #[allow(unsafe_code)] // prctl, which std does not wrap.
    // SAFETY: prctl with integer arguments only.
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) };
    let mut core = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    #[allow(unsafe_code)] // getrlimit, which std does not wrap.
    // SAFETY: `core` is a valid out-pointer for the duration of the call.
    let read = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core) };
    if read != 0 {
        return Err(KeyMemoryError::Harden { errno: errno() });
    }
    Ok(dumpable == 0 && core.rlim_cur == 0 && core.rlim_max == 0)
}

/// Fills `out` from the operating system's generator, `getrandom(2)` with no flag, so that it
/// blocks until the generator is seeded, retrying an interrupted call and a short read: the salt
/// of each passphrase wrapper (`doc/qa/argon2-review.md`, U6).
pub(crate) fn os_random(out: &mut [u8]) -> Result<(), CryptoError> {
    let mut filled = 0;
    while filled < out.len() {
        let rest = &mut out[filled..];
        #[allow(unsafe_code)] // getrandom(2), which std does not expose.
        // SAFETY: writes at most `rest.len()` bytes into `rest`, which outlives the call.
        let read = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        match usize::try_from(read) {
            Ok(read) => filled += read,
            Err(_) if errno() == libc::EINTR => {}
            Err(_) => return Err(CryptoError::Random),
        }
    }
    Ok(())
}

/// `/proc/self/status`.
fn process_status() -> Result<String, KeyMemoryError> {
    fs::read_to_string("/proc/self/status").map_err(|error| KeyMemoryError::ProcessStatus {
        errno: error.raw_os_error().unwrap_or(0),
    })
}

/// The value of `field` (for example `CapEff:`) in `status`, a `/proc/<pid>/status` text.
fn status_field(status: &str, field: &str) -> Result<String, KeyMemoryError> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .map(|value| value.trim().to_string())
        .ok_or(KeyMemoryError::ProcessStatus { errno: 0 })
}

/// Whether `status`, a `/proc/<pid>/status` text, shows `CAP_IPC_LOCK` in any of
/// [`CAPABILITY_SETS`].
fn holds_cap_ipc_lock(status: &str) -> Result<bool, KeyMemoryError> {
    for set in CAPABILITY_SETS {
        let bits = u64::from_str_radix(&status_field(status, set)?, 16)
            .map_err(|_| KeyMemoryError::ProcessStatus { errno: 0 })?;
        if bits & (1 << CAP_IPC_LOCK) != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Maps, advises and locks the process's key pool, before any key exists: the one pool every
/// key of the crate is created in. The Core calls it at start, after [`harden_process`], and does
/// not start when it fails:
/// - [`KeyMemoryError::NotHardened`] if the process is still dumpable or may write a core file;
/// - [`KeyMemoryError::CapIpcLock`] if `CAP_IPC_LOCK` is in its effective, permitted or ambient
///   capabilities: the Core's unit never grants it, and with it `LimitMEMLOCK` bounds nothing;
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
    if holds_cap_ipc_lock(&process_status()?)? {
        return Err(KeyMemoryError::CapIpcLock);
    }
    let pool = Pool::map(CLASSES)?;
    POOL.set(pool).map_err(|_| KeyMemoryError::AlreadyLocked)
}

/// Sets the process up as the Core's start does, in its order, before any key exists:
/// [`harden_process`], [`take_sigterm`] with `on_term`, [`lock_key_memory`], then
/// [`install_panic_hook`] with `in_handler_boundary`. The first step that fails stops it with
/// its error, and the Core does not start. That nothing replaces the panic hook afterwards is
/// the Core's to hold.
pub fn start_key_memory(
    on_term: impl FnOnce() + Send + 'static,
    in_handler_boundary: fn() -> bool,
) -> Result<(), KeyMemoryError> {
    harden_process()?;
    take_sigterm(on_term)?;
    lock_key_memory()?;
    install_panic_hook(in_handler_boundary);
    Ok(())
}

/// Wipes the process's pool, if it has one (the module documentation): for the panic hook and
/// the SIGTERM thread, as the process ends.
fn wipe_key_memory() {
    if let Some(pool) = POOL.get() {
        pool.wipe_all(WIPE_WAIT);
    }
}

/// Blocks SIGTERM and takes it on a thread of its own: when it arrives, the thread wipes the pool
/// and then runs `on_term`, the Core's orderly shutdown. It must be called while the process has
/// one thread, since a thread spawned before it would still receive SIGTERM: it is refused with
/// [`KeyMemoryError::ThreadsRunning`] otherwise. Every thread spawned afterwards inherits the
/// blocked signal, so only that thread takes it.
pub fn take_sigterm(on_term: impl FnOnce() + Send + 'static) -> Result<(), KeyMemoryError> {
    let threads: usize = status_field(&process_status()?, "Threads:")?
        .parse()
        .map_err(|_| KeyMemoryError::ProcessStatus { errno: 0 })?;
    if threads != 1 {
        return Err(KeyMemoryError::ThreadsRunning { threads });
    }
    #[allow(unsafe_code)] // a sigset_t for sigemptyset to initialise.
    // SAFETY: an all-zero sigset_t is a valid value to initialise with sigemptyset.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    #[allow(unsafe_code)] // sigemptyset and sigaddset, which std does not wrap.
    // SAFETY: `set` is a valid sigset_t for both calls, which only write into it.
    let built = unsafe {
        libc::sigemptyset(&mut set) == 0 && libc::sigaddset(&mut set, libc::SIGTERM) == 0
    };
    if !built {
        return Err(KeyMemoryError::Sigterm { errno: errno() });
    }
    #[allow(unsafe_code)] // pthread_sigmask, which std does not wrap (D131).
    // SAFETY: `set` is initialised; the previous mask is not asked for.
    let blocked = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
    if blocked != 0 {
        return Err(KeyMemoryError::Sigterm { errno: blocked });
    }
    #[allow(unsafe_code)] // signalfd, which std does not wrap (D131).
    // SAFETY: `set` is initialised; -1 asks for a new descriptor.
    let descriptor = unsafe { libc::signalfd(-1, &set, libc::SFD_CLOEXEC) };
    if descriptor < 0 {
        return Err(KeyMemoryError::Sigterm { errno: errno() });
    }
    std::thread::Builder::new()
        .name("vilicus-sigterm".to_string())
        .spawn(move || {
            await_signal(descriptor);
            wipe_key_memory();
            on_term();
        })
        .map_err(|error| KeyMemoryError::Sigterm {
            errno: error.raw_os_error().unwrap_or(0),
        })?;
    Ok(())
}

/// Reads one signal from `descriptor`, a signalfd, retrying when interrupted; any other end of
/// the read is taken as the signal, so the shutdown is never lost.
fn await_signal(descriptor: libc::c_int) {
    let mut info = [0_u8; size_of::<libc::signalfd_siginfo>()];
    loop {
        #[allow(unsafe_code)] // read(2) on a signalfd, which std does not wrap.
        // SAFETY: reads at most `info.len()` bytes into `info`, from the descriptor this thread
        // owns.
        let read = unsafe { libc::read(descriptor, info.as_mut_ptr().cast(), info.len()) };
        if read < 0 && errno() == libc::EINTR {
            continue;
        }
        return;
    }
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

/// One slot class of a pool: where its slots start, their size, and which of them are in use.
struct Class {
    /// Bytes from the pool's base to the first slot.
    offset: usize,
    /// Bytes of one slot.
    slot_len: usize,
    /// One flag per slot, set while a [`Slot`] owns it.
    in_use: Mutex<Vec<bool>>,
}

/// The pool: a locked mapping of whole pages between two guard pages, cut into slot classes, and
/// the state of its wipe.
struct Pool {
    /// The first byte after the low guard page.
    base: NonNull<u8>,
    /// Bytes between the guard pages: what is advised, locked and wiped.
    len: usize,
    /// The slot classes, by class index.
    classes: [Class; CLASSES.len()],
    /// Set by [`Pool::wipe_all`]: no slot is handed out and no guarded call starts afterwards.
    wiped: AtomicBool,
    /// Guarded calls and slot wipes in progress on the pool, which a wipe waits for.
    in_flight: AtomicUsize,
}

#[allow(unsafe_code)] // the pool shares its raw mapping between threads.
// SAFETY: `base` and `len` never change after `map`, and the mapping is never unmapped. A slot's
// bytes are reached only through the one `Slot` that owns its index, handed out under its class's
// lock, and only inside a guarded call or the slot's drop, each counted in `in_flight`.
// `wipe_all` marks the pool wiped, which stops new calls, then writes only once `in_flight` shows
// none in progress, or once `WIPE_WAIT` has passed: past that bound it races with a call still
// running, which the process accepts as it ends, and that call's result is discarded.
unsafe impl Send for Pool {}
#[allow(unsafe_code)] // the pool shares its raw mapping between threads.
// SAFETY: as for `Send`; shared access goes through the class locks, the atomics or a `Slot`.
unsafe impl Sync for Pool {}

thread_local! {
    /// The pools this thread has a guarded call or a slot wipe in progress on, by address, one
    /// entry per call: what a wipe from this thread does not wait for.
    static ENTERED: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// A guarded call or a slot wipe in progress on a pool, counted until it is dropped.
struct InFlight<'a> {
    pool: &'a Pool,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let address = self.pool.address();
        let _ = ENTERED.try_with(|entered| {
            let mut entered = entered.borrow_mut();
            if let Some(position) = entered.iter().rposition(|pool| *pool == address) {
                entered.remove(position);
            }
        });
        self.pool.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The size of a page.
fn page_size() -> Result<usize, KeyMemoryError> {
    #[allow(unsafe_code)] // sysconf, which std does not wrap.
    // SAFETY: sysconf with a valid name.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(page)
        .ok()
        .filter(|page| *page > 0)
        .ok_or(KeyMemoryError::Map { errno: errno() })
}

/// A mapping of `len` bytes, whole pages, between two `PROT_NONE` guard pages, advised
/// `MADV_DONTDUMP` and `MADV_WIPEONFORK`, then locked, all zeroes: what the pool and the Argon2id
/// working memory are made of (D131). On any failure the mapping is undone; a refused `mlock`
/// gives the error `refused` makes from the bytes asked for and the `errno`.
struct LockedMapping {
    /// The first byte after the low guard page.
    base: NonNull<u8>,
    /// Bytes between the guard pages.
    len: usize,
    /// The size of a page, the size of each guard.
    page: usize,
}

impl LockedMapping {
    fn new(len: usize, refused: fn(usize, i32) -> KeyMemoryError) -> Result<Self, KeyMemoryError> {
        let page = page_size()?;
        let len = len
            .checked_next_multiple_of(page)
            .filter(|len| *len > 0)
            .ok_or(KeyMemoryError::Map { errno: 0 })?;
        let total = len
            .checked_add(2 * page)
            .ok_or(KeyMemoryError::Map { errno: 0 })?;
        #[allow(unsafe_code)] // mmap of locked memory (D131).
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
            #[allow(unsafe_code)] // munmap of the mapping that failed to set up.
            // SAFETY: `mapping` and `total` are the mapping made above, which holds no secret yet.
            let _ = unsafe { libc::munmap(mapping, total) };
            error
        };
        let low_guard = mapping.cast::<u8>();
        #[allow(unsafe_code)] // pointer arithmetic inside the mapping.
        // SAFETY: both offsets stay inside the mapping of `total` bytes made above.
        let (base, high_guard) = unsafe { (low_guard.add(page), low_guard.add(page + len)) };
        for guard in [low_guard, high_guard] {
            #[allow(unsafe_code)] // mprotect of a guard page (D131).
            // SAFETY: one whole page inside the mapping made above.
            let protected = unsafe { libc::mprotect(guard.cast(), page, libc::PROT_NONE) };
            if protected != 0 {
                return Err(undo(KeyMemoryError::Map { errno: errno() }));
            }
        }
        for (advice, name) in [
            (libc::MADV_DONTDUMP, "MADV_DONTDUMP"),
            (libc::MADV_WIPEONFORK, "MADV_WIPEONFORK"),
        ] {
            #[allow(unsafe_code)] // madvise of locked memory (D131).
            // SAFETY: the pages between the guard pages, inside the mapping made above.
            let advised = unsafe { libc::madvise(base.cast(), len, advice) };
            if advised != 0 {
                return Err(undo(KeyMemoryError::Advise {
                    advice: name,
                    errno: errno(),
                }));
            }
        }
        #[allow(unsafe_code)] // mlock (D131).
        // SAFETY: the pages between the guard pages, inside the mapping made above.
        let locked = unsafe { libc::mlock(base.cast(), len) };
        if locked != 0 {
            return Err(undo(refused(len, errno())));
        }
        Ok(Self {
            base: NonNull::new(base).ok_or(KeyMemoryError::Map { errno: 0 })?,
            len,
            page,
        })
    }
}

impl Pool {
    /// Maps a pool of `classes`, each a slot size and a slot count, in a [`LockedMapping`]. The
    /// pool's mapping is never unmapped.
    fn map(classes: [(usize, usize); CLASSES.len()]) -> Result<Self, KeyMemoryError> {
        let mut offset = 0;
        let classes = classes.map(|(slot_len, slots)| {
            let class = Class {
                offset,
                slot_len,
                in_use: Mutex::new(vec![false; slots]),
            };
            offset = (offset + slot_len * slots).next_multiple_of(16);
            class
        });
        let mapping =
            LockedMapping::new(offset, |bytes, errno| KeyMemoryError::Lock { bytes, errno })?;
        Ok(Self {
            base: mapping.base,
            len: mapping.len,
            classes,
            wiped: AtomicBool::new(false),
            in_flight: AtomicUsize::new(0),
        })
    }

    fn address(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }

    /// Counts a guarded call or a slot wipe in: refused once the pool is wiped when `refusable`.
    /// The count is raised before the flag is read, and a wipe sets the flag before it reads the
    /// count, so a call either sees the flag or is waited for.
    fn enter(&self, refusable: bool) -> Result<InFlight<'_>, KeyMemoryError> {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        let in_flight = InFlight { pool: self };
        let _ = ENTERED.try_with(|entered| entered.borrow_mut().push(self.address()));
        if refusable && self.wiped.load(Ordering::SeqCst) {
            return Err(KeyMemoryError::Wiped);
        }
        Ok(in_flight)
    }

    /// A free slot of class `class`, all zeroes.
    fn alloc<const N: usize>(&'static self, class: usize) -> Result<Slot<N>, KeyMemoryError> {
        let mut in_use = self.classes[class]
            .in_use
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
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

    fn release(&self, class: usize, index: usize) {
        let mut in_use = self.classes[class]
            .in_use
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        in_use[index] = false;
    }

    /// Marks the pool wiped, waits up to `wait` for the guarded calls and slot wipes in progress
    /// on other threads to end, then overwrites the whole pool with zeroes. It takes no lock, so a
    /// panic hook that runs while a thread holds a class lock still wipes.
    fn wipe_all(&self, wait: Duration) {
        self.wiped.store(true, Ordering::SeqCst);
        let address = self.address();
        let own = ENTERED
            .try_with(|entered| {
                entered
                    .borrow()
                    .iter()
                    .filter(|pool| **pool == address)
                    .count()
            })
            .unwrap_or(0);
        let deadline = Instant::now() + wait;
        while self.in_flight.load(Ordering::SeqCst) > own && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        for offset in 0..self.len {
            #[allow(unsafe_code)] // volatile writes to the raw mapping.
            // SAFETY: `offset` is below `len`, inside the locked mapping, which stays mapped for
            // the life of the process; the calls that may still read it are those past the wait,
            // whose results are discarded (the `Sync` comment of `Pool`).
            unsafe {
                self.base.as_ptr().add(offset).write_volatile(0)
            };
        }
    }

    fn is_wiped(&self) -> bool {
        self.wiped.load(Ordering::SeqCst)
    }
}

/// One buffer of `N` bytes, a slot of the pool's class for that length: all zeroes when taken,
/// wiped with volatile writes when dropped. Not `Clone`, `Copy` or `Debug`. Its bytes are lent
/// only through [`with_key`](Self::with_key) and [`with_key_mut`](Self::with_key_mut), under the
/// guard of [`guarded`].
pub(crate) struct Slot<const N: usize> {
    pool: &'static Pool,
    index: usize,
}

/// The buffer of a key.
pub(crate) type KeySlot = Slot<KEY_LEN>;

/// The buffer of a key's SQLCipher key text.
pub(crate) type TextSlot = Slot<TEXT_SLOT_LEN>;

impl<const N: usize> Slot<N> {
    /// The class of the slots of `N` bytes; any other length fails the build.
    const CLASS: usize = if N == CLASSES[0].0 {
        0
    } else if N == CLASSES[1].0 {
        1
    } else {
        panic!("no slot class of this length")
    };

    /// A slot of the process's pool, or the reason there is none: no pool locked yet, every slot
    /// of the class in use, or the pool wiped.
    pub(crate) fn new() -> Result<Self, CryptoError> {
        // The unit tests run in a process the Core's start never ran in: the first slot of a test
        // hardens the process and locks its pool, as that start would.
        #[cfg(test)]
        crate::test_support::key_memory();
        let pool = POOL.get().ok_or(KeyMemoryError::NotLocked)?;
        Ok(pool.alloc(Self::CLASS)?)
    }

    /// Lends the bytes to `operation`, under the guard of [`guarded`]: refused, and the result of
    /// an operation that ran discarded, when the pool is wiped.
    pub(crate) fn with_key<R>(
        &self,
        operation: impl FnOnce(&[u8; N]) -> R,
    ) -> Result<R, KeyMemoryError> {
        guarded(self.pool, || operation(self.bytes()))
    }

    /// Lends the bytes to `operation`, to be written, as [`with_key`](Self::with_key) does.
    pub(crate) fn with_key_mut<R>(
        &mut self,
        operation: impl FnOnce(&mut [u8; N]) -> R,
    ) -> Result<R, KeyMemoryError> {
        let pool = self.pool;
        guarded(pool, || operation(self.bytes_mut()))
    }

    // The three accessors below are one unsafe expression each, in tail position, where Rust
    // takes no attribute on an expression: their allow is on the function, the smallest item.
    #[allow(unsafe_code)] // pointer arithmetic inside the mapping.
    fn start(&self) -> *mut u8 {
        let class = &self.pool.classes[Self::CLASS];
        // SAFETY: `index` is below the class's slot count, so the slot lies inside the mapping.
        unsafe {
            self.pool
                .base
                .as_ptr()
                .add(class.offset + self.index * class.slot_len)
        }
    }

    #[allow(unsafe_code)] // the slot is a range of the raw mapping.
    fn bytes(&self) -> &[u8; N] {
        // SAFETY: the slot's N bytes lie inside the locked mapping, which is never unmapped, and
        // only this `Slot` owns its index; `&self` keeps them unwritten by it meanwhile, and the
        // callers hold the pool's in-flight count, which a wipe waits for.
        unsafe { &*self.start().cast::<[u8; N]>() }
    }

    #[allow(unsafe_code)] // the slot is a range of the raw mapping.
    fn bytes_mut(&mut self) -> &mut [u8; N] {
        // SAFETY: as in `bytes`, and `&mut self` makes the access exclusive.
        unsafe { &mut *self.start().cast::<[u8; N]>() }
    }
}

impl<const N: usize> Drop for Slot<N> {
    fn drop(&mut self) {
        // Counted, never refused: a slot whose call returned past a wipe's bound may hold key
        // bytes written after the overwrite, and its drop wipes them.
        let in_flight = self.pool.enter(false);
        self.bytes_mut().zeroize();
        #[cfg(test)]
        wiped::record(self.bytes());
        drop(in_flight);
        self.pool.release(Self::CLASS, self.index);
    }
}

// A block of Argon2id lies in the mapping as the crate lays it out: 1 KiB, aligned below a page.
const _: () = assert!(size_of::<Block>() == Block::SIZE && align_of::<Block>() <= 4096);

/// The working memory of one Argon2id derivation, outside the pool: exactly the blocks the
/// derivation asks for, then a buffer for the passphrase it derives from, in a locked mapping of
/// its own (Story 4.4; `doc/qa/argon2-review.md`, finding F1: the blocks are worth the KEK, so
/// a swapped page of them would skip the derivation's cost). The Core holds at most
/// `vilicus_types::ARGON2ID_MEMORY_BUDGET_KIB` of it at once, which its `LimitMEMLOCK` covers
/// beside the pool.
///
/// It is wiped with volatile writes, then unmapped, when it is dropped: on success, on error and
/// while a panic unwinds alike. A refused `mlock` is [`KeyMemoryError::WorkingMemoryLock`], never
/// answered with unlocked memory.
pub(crate) struct WorkingMemory {
    mapping: LockedMapping,
    blocks: usize,
    passphrase_len: usize,
}

impl WorkingMemory {
    /// A locked mapping of `blocks` blocks followed by `passphrase_len` bytes, all zeroes, in
    /// whole pages.
    pub(crate) fn new(blocks: usize, passphrase_len: usize) -> Result<Self, KeyMemoryError> {
        let bytes = blocks
            .checked_mul(Block::SIZE)
            .and_then(|bytes| bytes.checked_add(passphrase_len))
            .ok_or(KeyMemoryError::Map { errno: 0 })?;
        let mapping = LockedMapping::new(bytes, |bytes, errno| {
            KeyMemoryError::WorkingMemoryLock { bytes, errno }
        })?;
        Ok(Self {
            mapping,
            blocks,
            passphrase_len,
        })
    }

    /// The blocks and the passphrase buffer after them, exactly as long as [`new`](Self::new) was
    /// given.
    pub(crate) fn split(&mut self) -> (&mut [Block], &mut [u8]) {
        let blocks_len = self.blocks * Block::SIZE;
        let base = self.mapping.base.as_ptr();
        #[allow(unsafe_code)] // the blocks are the start of the raw mapping.
        // SAFETY: the mapping is page-aligned, which `Block`'s alignment divides (the assertion
        // above), holds `blocks_len` bytes at its start (`new`), and is zeroes or what the
        // derivation wrote, either a valid `Block`, whose only field is an array of integers.
        // `&mut self` makes the borrow exclusive, and the passphrase buffer below is disjoint.
        let blocks = unsafe { std::slice::from_raw_parts_mut(base.cast::<Block>(), self.blocks) };
        #[allow(unsafe_code)] // the passphrase buffer is the rest of the raw mapping.
        // SAFETY: `blocks_len + passphrase_len` is at most `len` (`new`), so the range lies inside
        // the mapping, after the blocks and disjoint from them.
        let passphrase =
            unsafe { std::slice::from_raw_parts_mut(base.add(blocks_len), self.passphrase_len) };
        (blocks, passphrase)
    }
}

impl Drop for WorkingMemory {
    fn drop(&mut self) {
        let base = self.mapping.base.as_ptr();
        #[allow(unsafe_code)] // the raw mapping, as 64-bit words.
        // SAFETY: the mapping is page-aligned and a whole number of pages, so it is exactly
        // `len / 8` aligned words; no borrow of it outlives `&mut self`.
        let words = unsafe {
            std::slice::from_raw_parts_mut(base.cast::<u64>(), self.mapping.len / size_of::<u64>())
        };
        // Volatile writes of whole words: one per eight bytes of a buffer of hundreds of MiB.
        words.zeroize();
        #[cfg(test)]
        working_memory_wiped::record(words);
        #[allow(unsafe_code)] // munmap, which also unlocks.
        // SAFETY: the guard page before `base`, the `len` bytes and the guard page after them are
        // the mapping `LockedMapping::new` made, and nothing refers to it any more.
        let _ = unsafe {
            libc::munmap(
                base.sub(self.mapping.page).cast(),
                self.mapping.len + 2 * self.mapping.page,
            )
        };
    }
}

/// What every dropped [`WorkingMemory`] held once wiped, read by the tests: its address, its
/// length and whether every byte was zero after the wipe. Recorded per thread.
#[cfg(test)]
pub(crate) mod working_memory_wiped {
    use std::cell::RefCell;

    thread_local! {
        static SEEN: RefCell<Vec<(usize, usize, bool)>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn record(words: &[u64]) {
        let all_zero = words.iter().all(|word| *word == 0);
        SEEN.with(|seen| {
            seen.borrow_mut()
                .push((words.as_ptr().addr(), size_of_val(words), all_zero));
        });
    }

    /// Every working memory dropped on this thread since the last call, oldest first.
    pub(crate) fn take() -> Vec<(usize, usize, bool)> {
        SEEN.with(|seen| std::mem::take(&mut *seen.borrow_mut()))
    }
}

thread_local! {
    /// How many guarded calls are running on this thread, one inside another.
    static GUARDED_CALLS: Cell<usize> = const { Cell::new(0) };
}

/// The scrub of one guarded call: the outermost one of the thread scrubs the stack when it is
/// dropped, on return, on refusal and while a panic unwinds alike.
struct Scrub {
    outermost: bool,
}

impl Scrub {
    fn enter() -> Self {
        let outermost = GUARDED_CALLS.with(|calls| calls.replace(calls.get() + 1)) == 0;
        #[cfg(any(test, feature = "testing"))]
        if outermost {
            canary::paint();
        }
        Self { outermost }
    }
}

impl Drop for Scrub {
    fn drop(&mut self) {
        if self.outermost {
            #[cfg(any(test, feature = "testing"))]
            canary::measure();
            scrub_stack();
        }
        GUARDED_CALLS.with(|calls| calls.set(calls.get() - 1));
    }
}

/// Runs `operation`, a key operation on a slot of `pool`, under the guard of D131:
/// - refused with [`KeyMemoryError::Wiped`] if the pool is wiped when it starts, and the
///   operation's result discarded for the same error if the pool was wiped while it ran, so no
///   result computed from keys being wiped is returned;
/// - counted in the pool's in-flight calls meanwhile, which a wipe waits for;
/// - when the outermost guarded call of the thread returns or unwinds, [`STACK_SCRUB_LEN`] bytes
///   of stack below it are overwritten with zeroes and the AVX registers zeroed, so the frames of
///   the operation and of the primitives it called leave nothing behind.
///
/// Never inlined, and the operation runs in a frame of its own below it, so what the operation
/// keeps in its locals lies inside the scrubbed range.
#[inline(never)]
fn guarded<R>(pool: &Pool, operation: impl FnOnce() -> R) -> Result<R, KeyMemoryError> {
    let _scrub = Scrub::enter();
    let in_flight = pool.enter(true)?;
    #[cfg(test)]
    test_hooks::before_operation(pool);
    let result = run_below(operation);
    let wiped_meanwhile = pool.is_wiped();
    drop(in_flight);
    if wiped_meanwhile {
        drop(result);
        return Err(KeyMemoryError::Wiped);
    }
    Ok(result)
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
fn zero_vector_registers() {
    if std::arch::is_x86_feature_detected!("avx") {
        #[allow(unsafe_code)] // vzeroall, inline assembly (D131).
        // SAFETY: the CPU has AVX, checked above. vzeroall writes ymm0 to ymm15 only, which
        // clobber_abi("C") declares clobbered, and touches no memory, stack or flags.
        unsafe {
            std::arch::asm!(
                "vzeroall",
                clobber_abi("C"),
                options(nostack, nomem, preserves_flags)
            );
        };
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn zero_vector_registers() {}

/// The stack canary of the guarded calls (Story 4.2, AC8), in test builds only: before the
/// outermost guarded call runs its operation, twice [`STACK_SCRUB_LEN`] bytes below it are
/// painted with a canary byte; once the operation returned, and before the scrub, the deepest
/// byte the operation overwrote gives its stack depth. The paint and the measure are in the
/// tested build only, so the release build does not carry them.
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
    pub(super) fn measure() {
        let low = PAINTED.get();
        let mut depth = 0;
        for offset in 0..PAINT_LEN {
            #[allow(unsafe_code)] // reads the dead stack the canary painted (test builds only).
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

/// A test hook run inside every guarded call, after it is admitted and before its operation, so
/// that a test can wipe a pool while a key operation is in progress.
#[cfg(test)]
mod test_hooks {
    use std::cell::RefCell;

    use super::Pool;

    type Hook = Box<dyn FnMut(&Pool)>;

    thread_local! {
        static BEFORE_OPERATION: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    /// Runs `hook` before each guarded operation of this thread until [`clear`].
    pub(super) fn set(hook: impl FnMut(&Pool) + 'static) {
        BEFORE_OPERATION.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn clear() {
        BEFORE_OPERATION.with(|slot| *slot.borrow_mut() = None);
    }

    pub(super) fn before_operation(pool: &Pool) {
        let hook = BEFORE_OPERATION.with(|slot| slot.borrow_mut().take());
        if let Some(mut hook) = hook {
            hook(pool);
            BEFORE_OPERATION.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot.is_none() {
                    *slot = Some(hook);
                }
            });
        }
    }
}

/// What every dropped [`Slot`] held once wiped, read by the tests through this hook (AC3 of
/// Story 4.1): the slot's address and a copy of its first bytes, taken after the wipe and before
/// the slot is released. Recorded per thread, so concurrent tests do not see each other's.
#[cfg(test)]
pub(crate) mod wiped {
    use std::cell::RefCell;

    use super::KEY_LEN;

    thread_local! {
        static SEEN: RefCell<Vec<(usize, [u8; KEY_LEN])>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn record<const N: usize>(bytes: &[u8; N]) {
        let mut first = [0; KEY_LEN];
        let len = N.min(KEY_LEN);
        first[..len].copy_from_slice(&bytes[..len]);
        SEEN.with(|seen| seen.borrow_mut().push((bytes.as_ptr().addr(), first)));
    }

    /// Every slot dropped on this thread since the last call, oldest first.
    pub(crate) fn take() -> Vec<(usize, [u8; KEY_LEN])> {
        SEEN.with(|seen| std::mem::take(&mut *seen.borrow_mut()))
    }
}
