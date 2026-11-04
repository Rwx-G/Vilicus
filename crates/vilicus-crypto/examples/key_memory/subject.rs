//! The subject process: sets the process up, plants keys, runs one path, and stops at each phase
//! so that the harness can read its memory. It talks over stdin and stdout, one line a message.
//!
//! Variants: `core` sets the process up as the Core does (`harden_process`, `take_sigterm` for
//! the SIGTERM scenario, `lock_key_memory`) and runs the path through `vilicus_crypto`; `asis` runs
//! the same operation the default way, on aws-lc-rs directly, with the keys in ordinary heap
//! memory and the aws-lc-rs objects kept until the drop; `unhardened` asks for the pool without
//! hardening first; `control` neither hardens nor locks, the dumpable process of the dump checks.

use std::fs::File;
use std::io::{self, BufRead, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use vilicus_crypto::{
    CryptoError, Kdf, KekDerivation, Label, SymmetricKey, WrapParams, Wrapper, derive_key, label,
    testing,
};
use vilicus_types::{Id, UtcMillis};

use crate::material::{self, DEK, DERIVE_CONTEXT, DERIVE_LABEL, Field, KEK, KEY, MARKER, PARENT};

/// Exit status of a subject whose key memory was refused.
pub const EXIT_REFUSED: i32 = 3;
/// Exit status of any other failure.
pub const EXIT_ERROR: i32 = 2;

const PURPOSE: Label = label!("vilicus/v1/wrap/key-memory");
const CONTEXT: &[u8] = b"key-memory";
const OTHER_CONTEXT: &[u8] = b"another record";
const NONCE: [u8; 12] = *b"key-memory-n";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn run(scenario: &str, variant: &str, material: &Path) -> i32 {
    match run_inner(scenario, variant, material) {
        Ok(()) => 0,
        Err(error) => {
            say(&format!("ERROR {error}"));
            EXIT_ERROR
        }
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

/// Sets the process up for `variant`; `false` when the key memory was refused, which the subject
/// reports and ends on.
fn set_up(scenario: &str, variant: &str) -> Result<bool> {
    match variant {
        "core" => {
            vilicus_crypto::harden_process()?;
            if scenario == "sigterm" {
                vilicus_crypto::take_sigterm(|| {
                    pause("TERMWIPED");
                    std::process::exit(0);
                })?;
            }
        }
        "unhardened" => {}
        "asis" | "control" => {
            say("POOL 0 0");
            say(&format!("STATUS dumpable={}", testing::dumpable()));
            return Ok(true);
        }
        other => return Err(format!("unknown variant {other}").into()),
    }
    if let Err(error) = vilicus_crypto::lock_key_memory() {
        let generate = match SymmetricKey::generate() {
            Ok(_) => "created".to_string(),
            Err(error) => format!("refused ({error})"),
        };
        say(&format!("REFUSED {error:?}: {error}; a key: {generate}"));
        return Ok(false);
    }
    let (start, len) = testing::key_pool().ok_or("no pool after lock_key_memory")?;
    say(&format!("POOL {start:x} {len}"));
    say(&format!("STATUS dumpable={}", testing::dumpable()));
    Ok(true)
}

fn run_inner(scenario: &str, variant: &str, material: &Path) -> Result<()> {
    if !set_up(scenario, variant)? {
        std::process::exit(EXIT_REFUSED);
    }
    let file = File::open(material)?;
    let core = variant == "core";
    match scenario {
        "hold" => hold(&file),
        "capacity" => capacity(),
        "copies" => copies(&file, core),
        "derive" => derive(&file, core),
        "wrap" => wrap(&file, core),
        "unwrap" => unwrap(&file, core, CONTEXT),
        "unwrap-wrong" => unwrap(&file, core, OTHER_CONTEXT),
        "thread" => thread(&file, core),
        "panic-hook" => panic_hook(&file),
        "sigterm" => hold(&file),
        "fork" => fork(&file),
        "dump" => dump(&file, core),
        "swap" => swap(&file),
        other => Err(format!("unknown scenario {other}").into()),
    }
}

fn secret(file: &File, field: Field) -> Result<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    file.read_exact_at(&mut bytes, field.0)?;
    Ok(bytes)
}

/// Runs `operation`, a key operation of the crate, and reports how deep its guarded calls
/// reached, as `STACK <name> <bytes>`.
fn measured<T>(name: &str, operation: impl FnOnce() -> T) -> T {
    testing::take_deepest_stack_use();
    let result = operation();
    let depth =
        testing::take_deepest_stack_use().map_or_else(|| "none".to_string(), |d| d.to_string());
    say(&format!("STACK {name} {depth}"));
    result
}

fn params() -> Result<WrapParams> {
    let created_at = UtcMillis::from_millis(1_793_577_600_000)?;
    Ok(WrapParams::new(
        Kdf::None,
        KekDerivation::Direct,
        Vec::new(),
        created_at,
        Id::new_v7(created_at, [7; 10])?,
    )?)
}

fn hold(file: &File) -> Result<()> {
    let key = material::planted(file, KEY)?;
    pause("LIVE");
    drop(key);
    pause("DROPPED");
    Ok(())
}

/// Takes keys until the pool refuses one, and reports how many it gave and why it stopped.
fn capacity() -> Result<()> {
    let mut keys = Vec::new();
    let refusal = loop {
        match SymmetricKey::generate() {
            Ok(key) => keys.push(key),
            Err(error) => break error,
        }
    };
    say(&format!(
        "CAPACITY {} {}",
        keys.len(),
        matches!(
            refusal,
            CryptoError::KeyMemory(vilicus_crypto::KeyMemoryError::Exhausted)
        )
    ));
    drop(keys);
    pause("DROPPED");
    Ok(())
}

/// Copies `bytes` to the deep end of a 16 KiB frame, below what `pause` later uses, so the copy
/// is still there when the harness reads the stack.
#[inline(never)]
fn copy_to_deep_stack(bytes: &[u8]) {
    let mut frame = [0_u8; 16 * 1024];
    frame[..32].copy_from_slice(&bytes[..32]);
    std::hint::black_box(&mut frame);
}

/// A key copied to the stack inside the closure the crate lends its bytes to: scrubbed when the
/// closure's guarded call returns. The default shape makes the same copy with no guard.
fn copies(file: &File, core: bool) -> Result<()> {
    if core {
        let key = material::planted(file, KEY)?;
        measured("copies", || {
            testing::with_key(&key, |bytes| copy_to_deep_stack(bytes))
        })?;
        pause("LIVE");
        drop(key);
    } else {
        let key = material::plain_copy(&secret(file, KEY)?);
        copy_to_deep_stack(&key[32..]);
        pause("LIVE");
        drop(key);
    }
    pause("DROPPED");
    Ok(())
}

fn derive(file: &File, core: bool) -> Result<()> {
    if core {
        let parent = material::planted(file, PARENT)?;
        let child = measured("derive", || {
            derive_key(&parent, DERIVE_LABEL, &[DERIVE_CONTEXT])
        })?;
        pause("LIVE");
        drop((parent, child));
    } else {
        let parent = material::plain_copy(&secret(file, PARENT)?);
        let prk = Salt::new(HKDF_SHA256, &[]).extract(&parent[32..]);
        let mut child = vec![0_u8; 32];
        prk.expand(&[DERIVE_LABEL.as_str().as_bytes()], HKDF_SHA256)
            .map_err(material::other)?
            .fill(&mut child)
            .map_err(material::other)?;
        pause("LIVE");
        drop((parent, prk, child));
    }
    pause("DROPPED");
    Ok(())
}

fn wrap(file: &File, core: bool) -> Result<()> {
    if core {
        let kek = material::planted(file, KEK)?;
        let dek = material::planted(file, DEK)?;
        let params = params()?;
        let wrapper = measured("wrap", || {
            Wrapper::wrap_key(&kek, &dek, PURPOSE, params, CONTEXT)
        })?;
        pause("LIVE");
        drop((kek, dek, wrapper));
    } else {
        let (key, sealed) = asis_seal(file)?;
        pause("LIVE");
        drop((key, sealed));
    }
    pause("DROPPED");
    Ok(())
}

/// The default shape's KEK: a heap copy, and the AES-256-GCM key object built from it.
type AsisKek = (Vec<u8>, LessSafeKey);

/// The default shape of a wrap: the KEK and the key in heap copies, an AES-256-GCM key object
/// kept, the key sealed in a heap buffer.
fn asis_seal(file: &File) -> Result<(AsisKek, Vec<u8>)> {
    let kek = material::plain_copy(&secret(file, KEK)?);
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &kek[32..]).map_err(material::other)?);
    let mut sealed = material::plain_copy(&secret(file, DEK)?);
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(NONCE),
            Aad::from(CONTEXT),
            &mut sealed[32..],
        )
        .map_err(material::other)?;
    sealed.extend_from_slice(tag.as_ref());
    Ok(((kek, key), sealed))
}

/// The key is wrapped, its own slot dropped, then the wrapper opened with `context`: with the
/// context it was made for, the key comes back in a new slot; with another, the open fails and
/// the buffer it wrote into is wiped.
fn unwrap(file: &File, core: bool, context: &[u8]) -> Result<()> {
    if core {
        let kek = material::planted(file, KEK)?;
        let dek = material::planted(file, DEK)?;
        let wrapper = Wrapper::wrap_key(&kek, &dek, PURPOSE, params()?, CONTEXT)?;
        drop(dek);
        let opened = measured("unwrap", || wrapper.unwrap_key(&kek, PURPOSE, context));
        if let Err(error) = &opened {
            say(&format!("FAILED {error}"));
        }
        pause("LIVE");
        drop((kek, opened, wrapper));
    } else {
        let ((kek, key), mut sealed) = asis_seal(file)?;
        let opened = key
            .open_in_place(
                Nonce::assume_unique_for_key(NONCE),
                Aad::from(context),
                &mut sealed[32..],
            )
            .map(|plaintext| plaintext.to_vec());
        if let Err(error) = &opened {
            say(&format!("FAILED {error:?}"));
        }
        pause("LIVE");
        drop((kek, key, sealed, opened));
    }
    pause("DROPPED");
    Ok(())
}

/// A wrap and an unwrap on a spawned thread, as the Core's blocking pool would run them; the
/// thread reports an address inside its stack, then ends, and the harness looks for residue in
/// that stack's mapping, which the C library keeps cached after the join.
fn thread(file: &File, core: bool) -> Result<()> {
    let file = file.try_clone()?;
    let worker = std::thread::spawn(move || -> std::result::Result<(), String> {
        let marker = 0_u8;
        say(&format!(
            "THREADSTACK {:x}",
            std::ptr::addr_of!(marker).addr()
        ));
        std::hint::black_box(&marker);
        if core {
            let kek = material::planted(&file, KEK).map_err(|e| e.to_string())?;
            let dek = material::planted(&file, DEK).map_err(|e| e.to_string())?;
            let params = params().map_err(|e| e.to_string())?;
            let wrapper = measured("thread-wrap", || {
                Wrapper::wrap_key(&kek, &dek, PURPOSE, params, CONTEXT)
            })
            .map_err(|e| e.to_string())?;
            let opened = measured("thread-unwrap", || {
                wrapper.unwrap_key(&kek, PURPOSE, CONTEXT)
            })
            .map_err(|e| e.to_string())?;
            drop((kek, dek, opened));
        } else {
            let kek = secret(&file, KEK).map_err(|e| e.to_string())?;
            copy_to_deep_stack(&kek);
            let (kept, sealed) = asis_seal(&file).map_err(|e| e.to_string())?;
            drop((kept, sealed));
        }
        Ok(())
    });
    worker
        .join()
        .map_err(|_| "the worker panicked")?
        .map_err(|error| format!("worker: {error}"))?;
    pause("DROPPED");
    Ok(())
}

thread_local! {
    /// The harness's stand-in for the Core's mark of a module handler's boundary
    /// (`vilicus_core::boundary::in_module_code`).
    static IN_HANDLER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn in_handler() -> bool {
    IN_HANDLER.with(std::cell::Cell::get)
}

fn observe_panic() {
    pause("PANICKED");
}

/// The Core's panic shape: a panic inside a handler's boundary unwinds to it and the keys stay;
/// a panic outside one wipes the pool and aborts.
fn panic_hook(file: &File) -> Result<()> {
    vilicus_crypto::install_panic_hook(in_handler);
    testing::set_panic_observer(observe_panic);
    let key = material::planted(file, KEY)?;
    let dek = material::planted(file, DEK)?;
    pause("LIVE");
    let caught = std::panic::catch_unwind(|| {
        IN_HANDLER.with(|mark| mark.set(true));
        panic!("a panic inside a handler's boundary");
    });
    IN_HANDLER.with(|mark| mark.set(false));
    if caught.is_ok() {
        return Err("the handler did not panic".into());
    }
    pause("CAUGHT");
    std::hint::black_box((&key, &dek));
    panic!("a panic outside any handler's boundary");
}

fn fork(file: &File) -> Result<()> {
    let key = material::planted(file, KEY)?;
    let control = secret(file, MARKER)?.to_vec();
    let view = testing::fork_and_read(&key, &control)?;
    say(&format!(
        "FORK slot_zero={} control_kept={}",
        view.slot_zero, view.control_kept
    ));
    drop(key);
    Ok(())
}

/// Holds a key (the `core` variant) and the marker in heap memory, then faults on request or
/// waits to be signalled.
fn dump(file: &File, core: bool) -> Result<()> {
    let key = if core {
        Some(material::planted(file, KEY)?)
    } else {
        None
    };
    let marker = material::plain_copy(&secret(file, MARKER)?);
    if pause("LIVE") == "fault" {
        testing::fault()?;
    }
    std::hint::black_box((&key, &marker));
    pause("DROPPED");
    Ok(())
}

/// Holds a key in a slot and a copy in an unlocked page, then fills memory until the cgroup
/// limit pushes pages out, and reports from `/proc/self/pagemap` whether each copy's page is
/// resident or swapped.
fn swap(file: &File) -> Result<()> {
    const PRESSURE_MIB: usize = 384;
    let key = material::planted(file, KEY)?;
    let mut plain = vec![0_u8; 1 << 20];
    plain[..32].copy_from_slice(&secret(file, KEY)?);
    let mut pressure: Vec<Vec<u8>> = Vec::new();
    for index in 0..PRESSURE_MIB {
        pressure.push(vec![u8::try_from(index % 251).unwrap_or(1) | 1; 1 << 20]);
    }
    std::hint::black_box(&pressure);
    let (pool_start, _) = testing::key_pool().ok_or("no pool")?;
    let pool = page_state(pool_start)?;
    let unlocked = page_state(plain.as_ptr().addr())?;
    say(&format!(
        "SWAP pool_present={} pool_swapped={} plain_present={} plain_swapped={} pressure_mib={PRESSURE_MIB}",
        pool.0, pool.1, unlocked.0, unlocked.1
    ));
    drop((key, plain, pressure));
    Ok(())
}

/// Whether the page holding `address` is resident and whether it is swapped out: bits 63 and 62
/// of its `/proc/self/pagemap` entry, readable without privilege.
fn page_state(address: usize) -> io::Result<(bool, bool)> {
    let pagemap = File::open("/proc/self/pagemap")?;
    let mut entry = [0_u8; 8];
    pagemap.read_exact_at(&mut entry, (address / 4096 * 8) as u64)?;
    let entry = u64::from_ne_bytes(entry);
    Ok((entry >> 63 == 1, (entry >> 62) & 1 == 1))
}
