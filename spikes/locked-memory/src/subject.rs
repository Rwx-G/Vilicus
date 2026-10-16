//! The subject process: holds keys, runs one code path, and stops at each phase so the
//! harness can read its memory. It talks over stdin and stdout, one line per message.
//!
//! Variants: `core` is the shape proposed for the Core (hardened process, locked slots,
//! Core-owned and wiped Argon2 memory, AEAD and HKDF objects built and dropped per operation,
//! in-place opens, a stack scrub guard around key operations); `asis` runs the same operations
//! the way the crates offer them by default; `control` skips the process hardening;
//! `limit-only` sets `RLIMIT_CORE` 0 but leaves the process dumpable; `preopen` waits for the
//! harness to open its memory before it hardens itself, then behaves as `core`.

use std::fs::File;
use std::io::{self, BufRead, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Prk, Salt};
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use zeroize::{Zeroize, Zeroizing};

use crate::material::{
    self, DEK, DEK_AAD, DEK_NONCE, EPH_IKM, Field, HK, HKDF_INFO, HKDF_SALT, HPKE_AAD, HPKE_CT,
    HPKE_ENC, HPKE_INFO, HPKE_TAG, KEY, MEMBER_PK, MEMBER_SK, PASSPHRASE, RECORD_NONCE,
    WRAPPED_DEK,
};
use crate::patterns::CodePath;
use crate::pool::{self, LockedPool, ScrubOnDrop, Slot};

/// Pages in the locked pool: 256 slots, above the planned size in the story's sizing rule.
pub const POOL_PAGES: usize = 4;
/// Exit code when the pool cannot be locked.
pub const EXIT_MLOCK_REFUSED: i32 = 3;
/// Exit code of any other failure.
pub const EXIT_ERROR: i32 = 2;

static KEYS_READ: AtomicUsize = AtomicUsize::new(0);

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Runs `scenario` in `variant` with the material file at `material`; returns the exit code.
pub fn run(scenario: &str, variant: &str, material: &Path) -> i32 {
    match run_inner(scenario, variant, material) {
        Ok(()) => 0,
        Err(error) => {
            say(&format!("ERROR {error}"));
            EXIT_ERROR
        }
    }
}

fn run_inner(scenario: &str, variant: &str, material: &Path) -> Result<()> {
    match variant {
        "core" | "asis" => pool::harden_process()?,
        "preopen" => {
            pause("PREHARDEN");
            pool::harden_process()?;
        }
        "control" => pool::set_core_limit(u64::MAX)?,
        "limit-only" => pool::set_core_limit(0)?,
        other => return Err(format!("unknown variant {other}").into()),
    }
    if scenario == "mlock-over-limit" {
        pool::set_memlock_limit(4096)?;
    }
    if scenario == "sigterm" {
        // Before any other thread exists, so every thread inherits the blocked SIGTERM.
        pool::install_sigterm_wiper(Some(observe_sigterm))?;
    }
    let pool = match LockedPool::new(POOL_PAGES) {
        Ok(pool) => pool,
        Err(error) => {
            say(&format!(
                "ERROR {error}; keys_read={}",
                KEYS_READ.load(Ordering::SeqCst)
            ));
            std::process::exit(EXIT_MLOCK_REFUSED);
        }
    };
    let (start, len) = pool.range();
    say(&format!("POOL {start:x} {len}"));
    let flags = pool::mapping_info("self", start)?
        .map(|info| info.vm_flags)
        .unwrap_or_default();
    say(&format!(
        "STATUS dumpable={} core_limit={} vmlck_kb={} vmflags={}",
        pool::dumpable(),
        pool::get_limit(libc::RLIMIT_CORE)?.0,
        pool::locked_kb(),
        flags.replace(' ', ",")
    ));

    let file = File::open(material)?;
    let core = variant != "asis";
    if let Some(path) = CodePath::from_name(scenario) {
        return match path {
            CodePath::Copies => copies(pool, &file, core),
            CodePath::Passphrase => passphrase(pool, &file, core, false),
            CodePath::Hkdf => hkdf(pool, &file, core),
            CodePath::HpkeOpen => hpke_open(pool, &file, core),
            CodePath::HpkeSeal => hpke_seal(pool, &file, core),
        };
    }
    match scenario {
        "passphrase-wrong" => passphrase(pool, &file, core, true),
        "hpke-open-thread" => hpke_open_thread(pool, &file, core),
        "hold" | "mlock-over-limit" => hold(pool, &file),
        "panic-hook" => panic_hook(pool, &file),
        "panic-unwind" => panic_unwind(pool, &file),
        "sigterm" => hold(pool, &file),
        "dump" => dump(pool, &file),
        "fork" => fork(pool, &file),
        "swap" => swap(pool, &file),
        other => Err(format!("unknown scenario {other}").into()),
    }
}

fn say(line: &str) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// Announces `phase`, waits for the harness to answer, and returns the answer.
fn pause(phase: &str) -> String {
    say(phase);
    let mut answer = String::new();
    let _ = io::stdin().lock().read_line(&mut answer);
    answer.trim().to_string()
}

fn observe_panic() {
    pause("PANICKED");
}

fn observe_sigterm() {
    pause("TERMWIPED");
}

fn secret(pool: &'static LockedPool, file: &File, field: Field) -> Result<Slot> {
    let mut slot = pool.alloc(field.len)?;
    file.read_exact_at(slot.bytes_mut(), field.offset as u64)?;
    KEYS_READ.fetch_add(1, Ordering::SeqCst);
    Ok(slot)
}

fn public(file: &File, field: Field) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; field.len];
    file.read_exact_at(&mut bytes, field.offset as u64)?;
    Ok(bytes)
}

/// Runs `operation` the Core way when `core` is set: a canary painted below the caller first,
/// the depth it reached reported as `STACK <bytes>`, and a scrub guard that also runs when the
/// operation fails.
fn guarded<T>(core: bool, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let _scrub = core.then_some(ScrubOnDrop);
    if core {
        pool::paint_stack();
    }
    let result = operation();
    if core {
        say(&format!("STACK {}", pool::deepest_stack_use()));
    }
    result
}

/// Copies the key to the deepest end of a 16 KiB frame, below what `pause` later uses, so the
/// copy is still there when the harness scans at LIVE.
#[inline(never)]
fn copy_to_stack(slot: &Slot) {
    let mut frame = [0u8; 16 * 1024];
    frame[..32].copy_from_slice(slot.bytes());
    std::hint::black_box(&mut frame);
}

fn copies(pool: &'static LockedPool, file: &File, core: bool) -> Result<()> {
    let key = secret(pool, file, KEY)?;
    // The key sits at offset 32 of a 64-byte allocation, so the allocator's free-list pointers
    // written over the first 16 bytes on free do not hide it.
    let mut heap = vec![0u8; 64];
    heap[32..].copy_from_slice(key.bytes());
    // Wiped on drop in the Core shape, freed as is by default.
    let (wiped, plain) = if core {
        (Some(Zeroizing::new(heap)), None)
    } else {
        (None, Some(heap))
    };
    copy_to_stack(&key);
    pause("LIVE");
    drop((wiped, plain, key));
    if core {
        pool::scrub_stack();
    }
    pause("DROPPED");
    Ok(())
}

/// Argon2id memory that is wiped when dropped, on the error path too.
struct WipedBlocks(Vec<argon2::Block>);

impl WipedBlocks {
    fn wipe(&mut self) {
        for block in self.0.iter_mut() {
            block.zeroize();
        }
    }
}

impl Drop for WipedBlocks {
    fn drop(&mut self) {
        self.wipe();
    }
}

// Each code path runs its key operations in an `#[inline(never)]` function and stops at LIVE
// after it returns. In the Core shape the AEAD and HKDF objects are built from the slot and
// dropped inside that function, and the scrub guard runs as it returns; by default the caller
// keeps them, as code that caches a key object would.

fn passphrase(pool: &'static LockedPool, file: &File, core: bool, wrong: bool) -> Result<()> {
    let passphrase = secret(pool, file, PASSPHRASE)?;
    let mut kek = pool.alloc(32)?;
    let mut dek = pool.alloc(WRAPPED_DEK.len)?;
    file.read_exact_at(dek.bytes_mut(), WRAPPED_DEK.offset as u64)?;
    if wrong {
        let last = WRAPPED_DEK.len - 1;
        dek.bytes_mut()[last] ^= 1;
    }
    let mut rewrapped = pool.alloc(DEK.len)?;
    let outcome = guarded(core, || {
        unwrap_and_rewrap(&passphrase, &mut kek, &mut dek, &mut rewrapped, core)
    });
    let (key, mut blocks) = match outcome {
        Ok(kept) => kept,
        Err(error) if wrong => {
            say(&format!("FAILED {error}"));
            (None, None)
        }
        Err(error) => return Err(error),
    };
    pause("LIVE");

    drop(key);
    if let Some(blocks) = blocks.as_mut() {
        blocks.wipe();
    }
    pause("WIPED");
    drop(blocks);
    drop((passphrase, kek, dek, rewrapped));
    if core {
        pool::scrub_stack();
    }
    pause("DROPPED");
    Ok(())
}

/// Passphrase to KEK, DEK opened in place, then sealed again under a new nonce. The Core shape
/// gives Argon2id memory it owns and wipes, and drops the AEAD key before returning; the
/// default lets the crate allocate and free the memory, and hands the AEAD key back.
#[inline(never)]
fn unwrap_and_rewrap(
    passphrase: &Slot,
    kek: &mut Slot,
    dek: &mut Slot,
    rewrapped: &mut Slot,
    core: bool,
) -> Result<(Option<LessSafeKey>, Option<WipedBlocks>)> {
    let argon2 = material::argon2();
    let blocks = if core {
        let mut blocks = WipedBlocks(vec![
            argon2::Block::default();
            material::ARGON2_M_KIB as usize
        ]);
        argon2
            .hash_password_into_with_memory(
                passphrase.bytes(),
                material::ARGON2_SALT,
                kek.bytes_mut(),
                &mut blocks.0,
            )
            .map_err(material::other)?;
        Some(blocks)
    } else {
        argon2
            .hash_password_into(passphrase.bytes(), material::ARGON2_SALT, kek.bytes_mut())
            .map_err(material::other)?;
        None
    };

    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, kek.bytes())?);
    key.open_in_place(
        Nonce::assume_unique_for_key(DEK_NONCE),
        Aad::from(DEK_AAD),
        dek.bytes_mut(),
    )?;
    rewrapped
        .bytes_mut()
        .copy_from_slice(&dek.bytes()[..DEK.len]);
    let _tag = key.seal_in_place_separate_tag(
        Nonce::assume_unique_for_key(*b"e16-rewrap-n"),
        Aad::from(DEK_AAD),
        rewrapped.bytes_mut(),
    )?;
    Ok((if core { None } else { Some(key) }, blocks))
}

struct Len32;

impl KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

fn hkdf(pool: &'static LockedPool, file: &File, core: bool) -> Result<()> {
    let dek = secret(pool, file, DEK)?;
    let mut file_key = pool.alloc(32)?;
    let kept = guarded(core, || derive_and_use(&dek, &mut file_key, core))?;
    pause("LIVE");

    drop((kept, dek, file_key));
    if core {
        pool::scrub_stack();
    }
    pause("DROPPED");
    Ok(())
}

/// File key derivation, then one record sealed and opened with it. The Core shape drops the
/// HKDF and AEAD objects before returning; the default hands them back.
#[inline(never)]
fn derive_and_use(
    dek: &Slot,
    file_key: &mut Slot,
    core: bool,
) -> Result<Option<(Prk, LessSafeKey, Vec<u8>)>> {
    let prk = Salt::new(HKDF_SHA256, HKDF_SALT).extract(dek.bytes());
    prk.expand(&[HKDF_INFO], Len32)?
        .fill(file_key.bytes_mut())?;

    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, file_key.bytes())?);
    let mut record = vec![0x5a_u8; 256];
    let tag = key.seal_in_place_separate_tag(
        Nonce::assume_unique_for_key(RECORD_NONCE),
        Aad::empty(),
        &mut record,
    )?;
    record.extend_from_slice(tag.as_ref());
    key.open_in_place(
        Nonce::assume_unique_for_key(RECORD_NONCE),
        Aad::empty(),
        &mut record,
    )?;
    Ok(if core { None } else { Some((prk, key, record)) })
}

type Kem = X25519HkdfSha256;

fn hpke_open(pool: &'static LockedPool, file: &File, core: bool) -> Result<()> {
    let sk = secret(pool, file, MEMBER_SK)?;
    let mut hk = pool.alloc(HK.len)?;
    guarded(core, || open_household_key(&sk, &mut hk, file, core))?;
    pause("LIVE");

    drop((sk, hk));
    if core {
        pool::scrub_stack();
    }
    pause("DROPPED");
    Ok(())
}

/// The household key unwrap on a spawned thread, as the Core's blocking pool would run it.
/// The thread reports an address inside its own stack, then ends; the harness looks for
/// residue in that stack's mapping, which glibc keeps cached after the thread is joined.
fn hpke_open_thread(pool: &'static LockedPool, file: &File, core: bool) -> Result<()> {
    let file = file.try_clone()?;
    let worker = std::thread::spawn(move || -> std::result::Result<(), String> {
        let marker = 0u8;
        say(&format!(
            "THREADSTACK {:x}",
            std::hint::black_box(&marker) as *const u8 as usize
        ));
        let sk = secret(pool, &file, MEMBER_SK).map_err(|e| e.to_string())?;
        let mut hk = pool.alloc(HK.len).map_err(|e| e.to_string())?;
        guarded(core, || open_household_key(&sk, &mut hk, &file, core))
            .map_err(|e| e.to_string())?;
        drop((sk, hk));
        Ok(())
    });
    worker
        .join()
        .map_err(|_| "the worker panicked")?
        .map_err(|e| format!("worker: {e}"))?;
    pause("DROPPED");
    Ok(())
}

/// Opens the household key wrap. The Core shape opens in place into the locked slot (usage
/// rule U5); the default uses the `Vec`-returning `single_shot_open`.
#[inline(never)]
fn open_household_key(sk_slot: &Slot, hk: &mut Slot, file: &File, core: bool) -> Result<()> {
    let sk =
        <Kem as hpke::Kem>::PrivateKey::from_bytes(sk_slot.bytes()).map_err(material::other)?;
    let (enc, tag) = material::hpke_public(&public(file, HPKE_ENC)?, &public(file, HPKE_TAG)?)
        .map_err(material::other)?;
    if core {
        file.read_exact_at(hk.bytes_mut(), HPKE_CT.offset as u64)?;
        hpke::single_shot_open_in_place_detached::<AesGcm256, HkdfSha256, Kem>(
            &OpModeR::Base,
            &sk,
            &enc,
            HPKE_INFO,
            hk.bytes_mut(),
            HPKE_AAD,
            &tag,
        )
        .map_err(material::other)?;
    } else {
        let mut sealed = public(file, HPKE_CT)?;
        sealed.extend_from_slice(&tag.to_bytes());
        let plaintext = hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(
            &OpModeR::Base,
            &sk,
            &enc,
            HPKE_INFO,
            &sealed,
            HPKE_AAD,
        )
        .map_err(material::other)?;
        hk.bytes_mut().copy_from_slice(&plaintext);
    }
    Ok(())
}

fn hpke_seal(pool: &'static LockedPool, file: &File, core: bool) -> Result<()> {
    let hk = secret(pool, file, HK)?;
    let ikm = secret(pool, file, EPH_IKM)?;
    let mut sealed = pool.alloc(HK.len)?;
    sealed.bytes_mut().copy_from_slice(hk.bytes());
    let enc = guarded(core, || seal_household_key(&ikm, &mut sealed, file))?;
    say(&format!("ENC {}", hex(&enc)));
    pause("LIVE");

    drop((hk, ikm, sealed));
    if core {
        pool::scrub_stack();
    }
    pause("DROPPED");
    Ok(())
}

/// Seals the household key copy in `sealed` to the member public key, with the ephemeral key
/// seeded from `ikm`; returns the encapsulated key.
#[inline(never)]
fn seal_household_key(ikm: &Slot, sealed: &mut Slot, file: &File) -> Result<Vec<u8>> {
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(&public(file, MEMBER_PK)?)
        .map_err(material::other)?;
    let (enc, _tag) = hpke::single_shot_seal_in_place_detached::<AesGcm256, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        &pk,
        HPKE_INFO,
        sealed.bytes_mut(),
        HPKE_AAD,
        &mut material::SliceRng::new(ikm.bytes()),
    )
    .map_err(material::other)?;
    Ok(enc.to_bytes().to_vec())
}

/// Holds a key in a slot until the harness signals or kills the process.
fn hold(pool: &'static LockedPool, file: &File) -> Result<()> {
    let key = secret(pool, file, KEY)?;
    pause("LIVE");
    drop(key);
    pause("DROPPED");
    Ok(())
}

/// Holds a key in a slot and a DEK copy in ordinary heap memory (the core file control), then
/// faults on request or waits to be signalled.
fn dump(pool: &'static LockedPool, file: &File) -> Result<()> {
    let key = secret(pool, file, KEY)?;
    let heap_dek = public(file, DEK)?;
    if pause("LIVE") == "fault" {
        fault();
    }
    std::hint::black_box((&key, &heap_dek));
    pause("DROPPED");
    Ok(())
}

/// Writes to a `PROT_NONE` page: a real fault, unlike a SIGSEGV sent with kill(2), which the
/// Rust runtime's stack-overflow handler resets and returns from without ending the process.
fn fault() {
    // SAFETY: anonymous mapping with no access, used only for the faulting write below.
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
    if page != libc::MAP_FAILED {
        // SAFETY: deliberately faults; the default SIGSEGV action then ends the process.
        unsafe { std::ptr::write_volatile(page.cast::<u8>(), 1) };
    }
}

/// The Core's panic shape, both cases in one process: a panic inside an AD-9 handler boundary
/// is caught and leaves the keys in place; a panic outside it wipes the pool and aborts.
fn panic_hook(pool: &'static LockedPool, file: &File) -> Result<()> {
    pool::install_panic_hook(Some(observe_panic));
    let key = secret(pool, file, KEY)?;
    let dek = secret(pool, file, DEK)?;
    pause("LIVE");
    let caught = pool::handler_boundary(|| panic!("E16 test panic inside a handler boundary"));
    if caught.is_ok() {
        return Err("the handler did not panic".into());
    }
    pause("CAUGHT");
    std::hint::black_box((&key, &dek));
    panic!("E16 test panic outside a handler boundary");
}

/// A worker thread panics while it owns slots; unwinding drops them.
fn panic_unwind(pool: &'static LockedPool, file: &File) -> Result<()> {
    std::panic::set_hook(Box::new(|_| {}));
    let file = file.try_clone()?;
    let worker = std::thread::spawn(move || {
        let key = secret(pool, &file, KEY).expect("key slot");
        let dek = secret(pool, &file, DEK).expect("dek slot");
        pause("LIVE");
        std::hint::black_box((&key, &dek));
        panic!("E16 test panic in a worker thread");
    });
    if worker.join().is_ok() {
        return Err("the worker did not panic".into());
    }
    pause("DROPPED");
    Ok(())
}

/// Forks while a key is in a slot and a copy is on the heap; the child reports what it sees.
fn fork(pool: &'static LockedPool, file: &File) -> Result<()> {
    let key = secret(pool, file, KEY)?;
    let heap_copy = key.bytes().to_vec();
    let slot_address = key.address();
    // SAFETY: the child only reads memory and calls `_exit`, both async-signal-safe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if pid == 0 {
        // SAFETY: the slot range stays mapped in the child (zero-filled by MADV_WIPEONFORK).
        let slot = unsafe { std::slice::from_raw_parts(slot_address as *const u8, 32) };
        let slot_zero = slot.iter().all(|b| *b == 0);
        let heap_kept = heap_copy.iter().any(|b| *b != 0);
        let code = i32::from(slot_zero) | (i32::from(heap_kept) << 1);
        // SAFETY: `_exit` skips atexit handlers, as a forked child of a threaded parent must.
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    // SAFETY: `pid` is our child; `status` is a valid out-pointer.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = libc::WEXITSTATUS(status);
    say(&format!(
        "FORK slot_zero={} heap_copy_kept={}",
        code & 1 == 1,
        code & 2 == 2
    ));
    drop((key, heap_copy));
    Ok(())
}

/// Holds a key in a slot and in an unlocked page, then fills memory until the cgroup limit
/// pushes pages to swap, and reports, for the page of each copy, whether it is resident or
/// swapped out (from `/proc/self/pagemap`), and the swapped size of the pool mapping.
fn swap(pool: &'static LockedPool, file: &File) -> Result<()> {
    const PRESSURE_MIB: usize = 384;
    let key = secret(pool, file, KEY)?;
    let mut plain = vec![0u8; 1 << 20];
    plain[..32].copy_from_slice(key.bytes());
    let plain_address = plain.as_ptr() as usize;

    let mut pressure: Vec<Vec<u8>> = Vec::new();
    for i in 0..PRESSURE_MIB {
        pressure.push(vec![u8::try_from(i % 251).unwrap_or(1) | 1; 1 << 20]);
    }
    std::hint::black_box(&pressure);

    let (pool_start, _) = pool.range();
    let pool_info = pool::mapping_info("self", pool_start)?.unwrap_or_default();
    let (pool_present, pool_swapped) = pool::page_state(key.address())?;
    let (plain_present, plain_swapped) = pool::page_state(plain_address)?;
    say(&format!(
        "SWAP pool_page_present={pool_present} pool_page_swapped={pool_swapped} \
         plain_page_present={plain_present} plain_page_swapped={plain_swapped} \
         pool_swap_kb={} pool_locked_kb={} pressure_mib={PRESSURE_MIB}",
        pool_info.swap_kb, pool_info.locked_kb
    ));
    drop((key, plain, pressure));
    Ok(())
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
