//! Locked key memory and process hygiene.
//!
//! A `LockedPool` is one anonymous mapping, locked with `mlock`, excluded from core dumps with
//! `MADV_DONTDUMP`, zero-filled in fork children with `MADV_WIPEONFORK`, framed by two
//! `PROT_NONE` guard pages and cut into fixed slots. A `Slot` is one key buffer; dropping it
//! wipes it with volatile writes. The pool is allocated once, before any key exists, so a
//! refused lock fails at start, never at unlock.

use std::cell::Cell;
use std::fmt;
use std::fs;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use zeroize::Zeroize;

/// Bytes per slot: a 32-byte key with a 16-byte tag fits, so AEAD opens can run in place.
pub const SLOT_LEN: usize = 64;

/// Slots the Core needs at its planned maximum (the sizing rule): for each of 8 unlocked
/// adults, the DEK, the household key and the member private key, 16 open file keys and 4
/// transient slots for an operation in progress; plus the instance key, the home partition
/// root, the audit key and 5 transient slots for instance-level work.
pub const PLANNED_SLOTS: usize = 8 * (3 + 16 + 4) + 3 + 5;

/// Bytes the stack scrub overwrites below the caller's frame.
pub const STACK_SCRUB_LEN: usize = 64 * 1024;

/// Bytes painted below the caller's frame to measure how deep a key operation reaches.
pub const STACK_PAINT_LEN: usize = 2 * STACK_SCRUB_LEN;

const CANARY: u8 = 0xa5;

static REGISTERED: OnceLock<&'static LockedPool> = OnceLock::new();
static PAINTED_LOW: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static IN_HANDLER_BOUNDARY: Cell<bool> = const { Cell::new(false) };
}

/// Why a pool could not be created or a slot allocated.
#[derive(Debug)]
pub enum PoolError {
    /// `mmap` or `mprotect` of a guard page failed.
    Map(io::Error),
    /// `mlock` was refused: no `CAP_IPC_LOCK` and `RLIMIT_MEMLOCK` too low.
    Lock(io::Error),
    /// An `madvise` call failed; the name says which advice.
    Advise(&'static str, io::Error),
    /// The process already has its pool.
    AlreadyRegistered,
    /// Every slot is in use.
    Exhausted,
    /// A slot was asked for more than `SLOT_LEN` bytes.
    TooLong(usize),
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Map(e) => write!(f, "mmap failed: {e}"),
            Self::Lock(e) => write!(f, "mlock refused: {e}"),
            Self::Advise(advice, e) => write!(f, "madvise {advice} failed: {e}"),
            Self::AlreadyRegistered => write!(f, "the process already has a locked pool"),
            Self::Exhausted => write!(f, "locked pool exhausted"),
            Self::TooLong(len) => write!(f, "slot of {len} bytes exceeds {SLOT_LEN}"),
        }
    }
}

impl std::error::Error for PoolError {}

/// A locked, dump-excluded mapping cut into `SLOT_LEN`-byte slots.
pub struct LockedPool {
    base: *mut u8,
    len: usize,
    in_use: Mutex<Vec<bool>>,
}

// SAFETY: `base` and `len` never change after construction and the mapping is never unmapped
// (the pool is leaked). Each slot's bytes are reached only through the one `Slot` that owns
// the index, handed out under the `in_use` mutex; `wipe_all` writes with volatile stores.
unsafe impl Send for LockedPool {}
// SAFETY: as above.
unsafe impl Sync for LockedPool {}

impl LockedPool {
    /// Maps `pages` usable pages between two guard pages, advises and locks them, and registers
    /// the pool as the process's only one, which the panic hook and the SIGTERM handler wipe.
    /// The pool lives until the process ends.
    pub fn new(pages: usize) -> Result<&'static LockedPool, PoolError> {
        if REGISTERED.get().is_some() {
            return Err(PoolError::AlreadyRegistered);
        }
        let page = page_size();
        let len = pages * page;
        let total = len + 2 * page;
        // SAFETY: anonymous private mapping with no address hint; the result is checked
        // against MAP_FAILED before use.
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
            return Err(PoolError::Map(io::Error::last_os_error()));
        }
        let unmap_on_error = |error: PoolError| {
            // SAFETY: `mapping` and `total` describe the mapping created above, holding no key.
            unsafe { libc::munmap(mapping, total) };
            error
        };
        // SAFETY: both offsets stay inside the mapping of `total` bytes.
        let (low_guard, base, high_guard) = unsafe {
            let low = mapping.cast::<u8>();
            (low, low.add(page), low.add(page + len))
        };
        for guard in [low_guard, high_guard] {
            // SAFETY: one page inside the mapping created above.
            if unsafe { libc::mprotect(guard.cast(), page, libc::PROT_NONE) } != 0 {
                return Err(unmap_on_error(PoolError::Map(io::Error::last_os_error())));
            }
        }
        for (advice, name) in [
            (libc::MADV_DONTDUMP, "MADV_DONTDUMP"),
            (libc::MADV_WIPEONFORK, "MADV_WIPEONFORK"),
        ] {
            // SAFETY: the usable range of the mapping created above.
            if unsafe { libc::madvise(base.cast(), len, advice) } != 0 {
                return Err(unmap_on_error(PoolError::Advise(
                    name,
                    io::Error::last_os_error(),
                )));
            }
        }
        // SAFETY: the usable range of the mapping created above.
        if unsafe { libc::mlock(base.cast(), len) } != 0 {
            return Err(unmap_on_error(PoolError::Lock(io::Error::last_os_error())));
        }
        let pool: &'static LockedPool = Box::leak(Box::new(LockedPool {
            base,
            len,
            in_use: Mutex::new(vec![false; len / SLOT_LEN]),
        }));
        REGISTERED
            .set(pool)
            .map_err(|_| PoolError::AlreadyRegistered)?;
        Ok(pool)
    }

    /// The process's pool, once created.
    pub fn registered() -> Option<&'static LockedPool> {
        REGISTERED.get().copied()
    }

    /// Start address and length of the usable part of the mapping (guard pages excluded).
    pub fn range(&self) -> (usize, usize) {
        (self.base as usize, self.len)
    }

    /// Takes a free slot for a buffer of `len` bytes.
    pub fn alloc(&'static self, len: usize) -> Result<Slot, PoolError> {
        if len > SLOT_LEN {
            return Err(PoolError::TooLong(len));
        }
        let mut in_use = self.in_use.lock().unwrap_or_else(|e| e.into_inner());
        let index = in_use
            .iter()
            .position(|used| !used)
            .ok_or(PoolError::Exhausted)?;
        in_use[index] = true;
        Ok(Slot {
            pool: self,
            index,
            len,
        })
    }

    /// Overwrites the whole pool with zeroes. Meant for the panic hook and the SIGTERM handler,
    /// right before the process ends: it races with any thread still using a slot, which is
    /// acceptable only because nothing runs after it.
    pub fn wipe_all(&self) {
        for offset in 0..self.len {
            // SAFETY: `offset` is inside the mapping, which stays mapped for the process life.
            unsafe { std::ptr::write_volatile(self.base.add(offset), 0) };
        }
    }

    fn release(&self, index: usize) {
        let mut in_use = self.in_use.lock().unwrap_or_else(|e| e.into_inner());
        in_use[index] = false;
    }
}

/// One key buffer inside a `LockedPool`. Not `Clone`, not `Debug`; wiped on drop.
pub struct Slot {
    pool: &'static LockedPool,
    index: usize,
    len: usize,
}

impl Slot {
    /// The buffer's bytes.
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the slot range is inside the mapping and owned by this `Slot` alone.
        unsafe { std::slice::from_raw_parts(self.start(), self.len) }
    }

    /// The buffer's bytes, writable.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as in `bytes`, and `&mut self` makes the access exclusive.
        unsafe { std::slice::from_raw_parts_mut(self.start(), self.len) }
    }

    /// Address of the first byte, for tests that look at the slot after it is dropped.
    pub fn address(&self) -> usize {
        self.start() as usize
    }

    fn start(&self) -> *mut u8 {
        // SAFETY: `index` is below `len / SLOT_LEN`, so the offset stays inside the mapping.
        unsafe { self.pool.base.add(self.index * SLOT_LEN) }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        // SAFETY: the whole slot, not only `len` bytes, so a shorter reuse leaves nothing.
        unsafe { std::slice::from_raw_parts_mut(self.start(), SLOT_LEN) }.zeroize();
        self.pool.release(self.index);
    }
}

/// Runs `f` as an AD-9 module handler: a panic inside it unwinds to here and is returned as
/// `Err`, and the panic hook leaves the key pool alone while the flag is set.
pub fn handler_boundary<R>(
    f: impl FnOnce() -> R + std::panic::UnwindSafe,
) -> std::thread::Result<R> {
    let previous = IN_HANDLER_BOUNDARY.with(|flag| flag.replace(true));
    let result = std::panic::catch_unwind(f);
    IN_HANDLER_BOUNDARY.with(|flag| flag.set(previous));
    result
}

/// Installs the Core's panic hook. Inside a handler boundary it does nothing, so the panic
/// unwinds to `handler_boundary`; anywhere else it wipes the pool and aborts. `observe` is spike
/// instrumentation that lets the harness scan between the wipe and the abort; the Core passes
/// `None`, so its hook does no I/O.
pub fn install_panic_hook(observe: Option<fn()>) {
    std::panic::set_hook(Box::new(move |_| {
        if IN_HANDLER_BOUNDARY.with(Cell::get) {
            return;
        }
        if let Some(pool) = LockedPool::registered() {
            pool.wipe_all();
        }
        if let Some(observe) = observe {
            observe();
        }
        std::process::abort();
    }));
}

/// Blocks SIGTERM in the calling thread (and so in every thread it spawns afterwards) and
/// starts a thread that waits for it on a signalfd, wipes the pool, runs `observe` (spike
/// instrumentation, `None` in the Core) and exits.
pub fn install_sigterm_wiper(observe: Option<fn()>) -> io::Result<()> {
    // SAFETY: `set` is initialised by sigemptyset before use; the calls only take pointers to it.
    let fd = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        if libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
        libc::signalfd(-1, &set, libc::SFD_CLOEXEC)
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    std::thread::spawn(move || {
        let mut info = [0u8; std::mem::size_of::<libc::signalfd_siginfo>()];
        // SAFETY: reads one signalfd_siginfo into a buffer of exactly that size.
        let read = unsafe { libc::read(fd, info.as_mut_ptr().cast(), info.len()) };
        if read > 0 {
            if let Some(pool) = LockedPool::registered() {
                pool.wipe_all();
            }
            if let Some(observe) = observe {
                observe();
            }
            std::process::exit(0);
        }
    });
    Ok(())
}

/// Turns core dumps off for this process: `PR_SET_DUMPABLE` 0 and `RLIMIT_CORE` 0. The first
/// also stops a same-user process without `CAP_SYS_PTRACE` from opening this process's memory
/// from now on; a descriptor or ptrace attach taken before this call keeps working. The kernel
/// resets the flag on `execve` and on credential changes, so the Core does neither afterwards.
pub fn harden_process() -> io::Result<()> {
    // SAFETY: plain prctl with integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    set_core_limit(0)
}

/// Sets both the soft and hard `RLIMIT_CORE`, or the soft one to the hard one when `bytes` is
/// `u64::MAX`.
pub fn set_core_limit(bytes: u64) -> io::Result<()> {
    let hard = get_limit(libc::RLIMIT_CORE)?.1;
    let limit = if bytes == u64::MAX {
        (hard, hard)
    } else {
        (bytes, bytes)
    };
    set_limit(libc::RLIMIT_CORE, limit)
}

/// Lowers `RLIMIT_MEMLOCK` (soft and hard) to `bytes`.
pub fn set_memlock_limit(bytes: u64) -> io::Result<()> {
    set_limit(libc::RLIMIT_MEMLOCK, (bytes, bytes))
}

/// The `PR_GET_DUMPABLE` value of this process.
pub fn dumpable() -> i32 {
    // SAFETY: plain prctl with integer arguments.
    unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }
}

/// Soft and hard limit of `resource`.
pub fn get_limit(resource: libc::__rlimit_resource_t) -> io::Result<(u64, u64)> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid out-pointer.
    if unsafe { libc::getrlimit(resource, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((limit.rlim_cur, limit.rlim_max))
}

fn set_limit(resource: libc::__rlimit_resource_t, (soft, hard): (u64, u64)) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    // SAFETY: `limit` is a valid pointer to an initialized rlimit.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Overwrites `STACK_SCRUB_LEN` bytes of stack below the caller with zeroes, which covers the
/// dead frames that the key operations the caller just returned from left behind, then zeroes
/// the AVX registers so a later signal frame cannot spill key bytes held in them.
#[inline(never)]
pub fn scrub_stack() {
    let mut area = [0u8; STACK_SCRUB_LEN];
    area.zeroize();
    std::hint::black_box(&area);
    zero_vector_registers();
}

fn zero_vector_registers() {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("avx") {
        // SAFETY: AVX is present (checked above), which is all `vzeroall` needs.
        unsafe { vzeroall() };
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx")]
unsafe fn vzeroall() {
    // SAFETY: vzeroall only zeroes ymm0-ymm15, all of which `clobber_abi("C")` declares
    // clobbered; it touches no memory and no flags.
    unsafe {
        std::arch::asm!(
            "vzeroall",
            clobber_abi("C"),
            options(nostack, nomem, preserves_flags)
        )
    };
}

/// Drops into a stack scrub: hold one in a function that calls key operations, so the scrub
/// also runs when the function leaves early with an error.
pub struct ScrubOnDrop;

impl Drop for ScrubOnDrop {
    fn drop(&mut self) {
        scrub_stack();
    }
}

/// Paints `STACK_PAINT_LEN` bytes below the caller's frame with a canary byte, so that
/// `deepest_stack_use` can measure how far a following call reaches.
#[inline(never)]
pub fn paint_stack() {
    let mut area = [CANARY; STACK_PAINT_LEN];
    std::hint::black_box(&mut area);
    PAINTED_LOW.store(area.as_ptr() as usize, Ordering::SeqCst);
}

/// Bytes below the painted area's top that some call overwrote since `paint_stack`: the depth
/// of the deepest stack use. Equal to `STACK_PAINT_LEN` when the call reached past the paint.
#[inline(never)]
pub fn deepest_stack_use() -> usize {
    let low = PAINTED_LOW.load(Ordering::SeqCst);
    for offset in 0..STACK_PAINT_LEN {
        // SAFETY: dead stack of this thread below the current frame, painted by
        // `paint_stack` and still mapped; read only.
        let byte = unsafe { std::ptr::read_volatile((low + offset) as *const u8) };
        if byte != CANARY {
            return STACK_PAINT_LEN - offset;
        }
    }
    0
}

fn page_size() -> usize {
    // SAFETY: sysconf with a valid name.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size).unwrap_or(4096)
}

/// What `/proc/<pid>/smaps` says about the mapping that contains an address.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MappingInfo {
    /// The `VmFlags` line, for example `rd wr mr mw me lo ac dd wf`.
    pub vm_flags: String,
    /// The `Swap` line, in kB.
    pub swap_kb: u64,
    /// The `Locked` line, in kB.
    pub locked_kb: u64,
}

/// Reads the smaps entry of the mapping of `pid` (or `self`) that contains `address`.
pub fn mapping_info(pid: &str, address: usize) -> io::Result<Option<MappingInfo>> {
    let smaps = fs::read_to_string(format!("/proc/{pid}/smaps"))?;
    let mut current: Option<MappingInfo> = None;
    for line in smaps.lines() {
        if let Some((start, end)) = parse_range(line) {
            if current.is_some() {
                break;
            }
            if (start..end).contains(&address) {
                current = Some(MappingInfo::default());
            }
            continue;
        }
        let Some(info) = current.as_mut() else {
            continue;
        };
        if let Some(flags) = line.strip_prefix("VmFlags:") {
            info.vm_flags = flags.trim().to_string();
        } else if let Some(value) = line.strip_prefix("Swap:") {
            info.swap_kb = parse_kb(value);
        } else if let Some(value) = line.strip_prefix("Locked:") {
            info.locked_kb = parse_kb(value);
        }
    }
    Ok(current)
}

/// Whether the page of this process that holds `address` is resident and whether it is
/// swapped out, from bits 63 and 62 of its `/proc/self/pagemap` entry (both readable without
/// privilege; only the frame number is restricted).
pub fn page_state(address: usize) -> io::Result<(bool, bool)> {
    use std::os::unix::fs::FileExt;
    let pagemap = fs::File::open("/proc/self/pagemap")?;
    let mut entry = [0u8; 8];
    pagemap.read_exact_at(&mut entry, (address / page_size() * 8) as u64)?;
    let entry = u64::from_ne_bytes(entry);
    Ok((entry >> 63 == 1, (entry >> 62) & 1 == 1))
}

/// The `VmLck` value of `/proc/self/status`, in kB.
pub fn locked_kb() -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("VmLck:").map(parse_kb))
        })
        .unwrap_or(0)
}

/// Parses the `start-end` address range at the start of a maps or smaps header line.
pub fn parse_range(line: &str) -> Option<(usize, usize)> {
    let range = line.split_whitespace().next()?;
    let (start, end) = range.split_once('-')?;
    Some((
        usize::from_str_radix(start, 16).ok()?,
        usize::from_str_radix(end, 16).ok()?,
    ))
}

fn parse_kb(value: &str) -> u64 {
    value
        .split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}
