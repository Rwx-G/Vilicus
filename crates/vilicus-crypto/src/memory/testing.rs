//! What the key memory regression harness (`examples/key_memory`, Story 4.2 AC10) needs of the
//! crate and of the system, compiled with the `testing` feature only. The harness plants known
//! keys in the pool, reads the canary of the guarded calls, and makes the process events whose
//! memory it then inspects: a fork, a signal, a memory fault.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

use super::{PANIC_OBSERVER, POOL, Slot, canary};
use crate::key::{KEY_LEN, SymmetricKey};

/// A key read from `file` at `offset` straight into a slot, so that no other copy of it exists in
/// the process: the harness plants the keys whose copies it then looks for.
pub fn key_from_file(file: &File, offset: u64) -> io::Result<SymmetricKey> {
    let mut slot = Slot::new().map_err(io::Error::other)?;
    slot.with_key_mut(|bytes| file.read_exact_at(bytes, offset))?;
    Ok(SymmetricKey::from_slot(slot))
}

/// Lends `key`'s bytes to `operation` under the guard of a key operation, as the crate's own
/// operations are.
pub fn with_key<R>(key: &SymmetricKey, operation: impl FnOnce(&[u8; KEY_LEN]) -> R) -> R {
    key.slot().with_key(operation)
}

/// The address and length of the pool's locked pages, once it is locked.
pub fn key_pool() -> Option<(usize, usize)> {
    POOL.get().map(|pool| (pool.base.as_ptr().addr(), pool.len))
}

/// The deepest stack use of the guarded calls of this thread since the last call, if any ran.
pub fn take_deepest_stack_use() -> Option<usize> {
    canary::take_deepest()
}

/// Has the panic hook run `observe` between its wipe and its abort, so that the harness can read
/// the wiped pool before the process ends. Only the first observer set is kept.
pub fn set_panic_observer(observe: fn()) {
    let _ = PANIC_OBSERVER.set(observe);
}

/// `PR_GET_DUMPABLE` of this process.
#[allow(unsafe_code)] // prctl, which std does not wrap.
pub fn dumpable() -> i32 {
    // SAFETY: prctl with integer arguments only.
    unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) }
}

/// Sends `signal` to the process `pid`.
#[allow(unsafe_code)] // kill(2), which std wraps for SIGKILL only.
pub fn signal(pid: u32, signal: i32) -> io::Result<()> {
    let pid = i32::try_from(pid).map_err(io::Error::other)?;
    // SAFETY: kill(2) with integer arguments only.
    if unsafe { libc::kill(pid, signal) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What a forked child read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkView {
    /// The key's slot read as zeroes in the child.
    pub slot_zero: bool,
    /// `control`, in unadvised heap memory, kept its bytes in the child.
    pub control_kept: bool,
}

/// Forks; the child reads `key`'s slot and `control` and ends at once, and its exit status says
/// what it read.
#[allow(unsafe_code)] // fork, _exit and waitpid, which std does not wrap.
pub fn fork_and_read(key: &SymmetricKey, control: &[u8]) -> io::Result<ForkView> {
    let slot = key.slot().start().cast_const();
    let expected = control.to_vec();
    // SAFETY: the child only reads memory and calls `_exit`, both async-signal-safe, as a forked
    // child of a threaded parent must.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: the slot stays mapped in the child, where MADV_WIPEONFORK makes it zeroes.
        let slot_bytes = unsafe { std::slice::from_raw_parts(slot, KEY_LEN) };
        let slot_zero = slot_bytes.iter().all(|byte| *byte == 0);
        let control_kept = control == expected.as_slice() && control.iter().any(|byte| *byte != 0);
        let code = i32::from(slot_zero) | (i32::from(control_kept) << 1);
        // SAFETY: `_exit` skips the atexit handlers a forked child of a threaded parent must not
        // run.
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    // SAFETY: `pid` is this process's child and `status` a valid out-pointer.
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
        return Err(io::Error::last_os_error());
    }
    let code = libc::WEXITSTATUS(status);
    Ok(ForkView {
        slot_zero: code & 1 == 1,
        control_kept: code & 2 == 2,
    })
}

/// Writes to a `PROT_NONE` page: a real memory fault, which a SIGSEGV sent with kill(2) is not,
/// since the Rust runtime's stack overflow handler returns from that one.
#[allow(unsafe_code)] // mmap and a faulting write, on purpose.
pub fn fault() -> io::Result<()> {
    // SAFETY: a new private anonymous mapping with no access and no address hint, compared with
    // MAP_FAILED before use.
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if page == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: faults on purpose: the page has no access, and the default action of SIGSEGV
    // ends the process.
    unsafe { page.cast::<u8>().write_volatile(1) };
    Err(io::Error::other(
        "the write to a PROT_NONE page did not fault",
    ))
}
