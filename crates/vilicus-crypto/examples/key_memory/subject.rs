//! The subject process: sets the process up, plants keys, runs one path, and stops at each phase
//! so that the harness can read its memory. It talks over stdin and stdout, one line a message.
//!
//! Variants: `core` sets the process up as the Core does (`start_key_memory`: hardening, the
//! SIGTERM thread, the pool, the panic hook) and runs the path through `vilicus_crypto`; `asis`
//! runs the same operation the default way, on aws-lc-rs directly, with the keys in ordinary heap
//! memory and the aws-lc-rs objects kept until the drop; `unhardened` asks for the pool without
//! hardening first; `control` neither hardens nor locks, the dumpable process of the dump checks.
//!
//! The default shape reads each key once, straight into a heap copy it reports as `PLANTED
//! <pattern> <address>`, so that the harness can tell that planted input apart from the copies
//! the operation itself made, which alone count as the control of the product shape's absences.

use std::fs::File;
use std::io::{self, BufRead, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use aws_lc_rs::hmac;
use vilicus_crypto::{
    CryptoError, InstanceKey, Kdf, KekDerivation, Label, PartitionRoot, SymmetricKey, WrapParams,
    Wrapper, label, testing,
};
use vilicus_types::{Id, ModuleName, UtcMillis};

use crate::material::{
    self, DEK, DERIVE_CONTEXT, DERIVE_LABEL, Field, GENERATION, HOUSEHOLD, HOUSEHOLD_VERSION, KEK,
    KEY, MARKER, MODULE, PARENT, ROOT, ROOT_VERSION, SET_COUNTER, SET_RECORDS,
};

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

thread_local! {
    /// The harness's stand-in for the Core's mark of a module handler's boundary
    /// (`vilicus_core::boundary::in_module_code`).
    static IN_HANDLER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn in_handler() -> bool {
    IN_HANDLER.with(std::cell::Cell::get)
}

fn on_term() {
    pause("TERMWIPED");
    std::process::exit(0);
}

/// Sets the process up for `variant`; `false` when the key memory was refused, which the subject
/// reports and ends on.
fn set_up(variant: &str) -> Result<bool> {
    let started = match variant {
        "core" => vilicus_crypto::start_key_memory(on_term, in_handler),
        "unhardened" => vilicus_crypto::lock_key_memory(),
        "asis" | "control" => {
            say("POOL 0 0");
            say(&format!("STATUS dumpable={}", testing::dumpable()));
            return Ok(true);
        }
        other => return Err(format!("unknown variant {other}").into()),
    };
    if let Err(error) = started {
        let generate = match SymmetricKey::generate() {
            Ok(_) => "created".to_string(),
            Err(error) => format!("refused ({error})"),
        };
        say(&format!("REFUSED {error:?}: {error}; a key: {generate}"));
        return Ok(false);
    }
    let (start, len) = testing::key_pool().ok_or("no pool after the start")?;
    say(&format!("POOL {start:x} {len}"));
    say(&format!("STATUS dumpable={}", testing::dumpable()));
    Ok(true)
}

fn run_inner(scenario: &str, variant: &str, material: &Path) -> Result<()> {
    if !set_up(variant)? {
        std::process::exit(EXIT_REFUSED);
    }
    let file = File::open(material)?;
    let core = variant == "core";
    match scenario {
        "hold" | "sigterm" => hold(&file),
        "capacity" => capacity(),
        "copies" => copies(&file, core),
        "derive" => derive(&file, core),
        "wrap" => wrap(&file, core),
        "unwrap" => unwrap(&file, core, CONTEXT),
        "unwrap-wrong" => unwrap(&file, core, OTHER_CONTEXT),
        "key-text" => key_text(&file, core),
        "file-key" => file_key(&file, core),
        "instance-key" => instance_key(material, core),
        "set-mac" => set_mac(&file, core),
        "thread" => thread(&file, core),
        "panic-hook" => panic_hook(&file),
        "fork" => fork(&file),
        "dump" => dump(&file, core),
        "swap" => swap(&file),
        other => Err(format!("unknown scenario {other}").into()),
    }
}

/// The secret of `field`, read straight into a heap copy for the default shape and reported as
/// planted: at offset 32 of a 64-byte allocation, so that the allocator's free-list pointers,
/// written over the first 16 bytes of a freed chunk, do not hide it.
fn planted_plain(file: &File, field: Field, name: &str) -> Result<Vec<u8>> {
    let mut heap = vec![0_u8; 64];
    file.read_exact_at(&mut heap[32..], field.0)?;
    say(&format!("PLANTED {name} {:x}", heap[32..].as_ptr().addr()));
    Ok(heap)
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
        let key = planted_plain(file, KEY, "key")?;
        copy_to_deep_stack(&key[32..]);
        pause("LIVE");
        drop(key);
    }
    pause("DROPPED");
    Ok(())
}

/// The HKDF `info` of the derivation, as `vilicus_crypto::testing::derive_key` builds it: the label, its
/// 0x00 end byte, then the context with its length as a `u16` big-endian (D153).
fn derive_info() -> Result<Vec<u8>> {
    let len = u16::try_from(DERIVE_CONTEXT.len())?;
    Ok([
        DERIVE_LABEL.as_str().as_bytes(),
        &[0x00],
        &len.to_be_bytes(),
        DERIVE_CONTEXT,
    ]
    .concat())
}

fn derive(file: &File, core: bool) -> Result<()> {
    if core {
        let parent = material::planted(file, PARENT)?;
        let child = measured("derive", || {
            testing::derive_key(&parent, DERIVE_LABEL, &[DERIVE_CONTEXT])
        })?;
        pause("LIVE");
        drop((parent, child));
    } else {
        let parent = planted_plain(file, PARENT, "parent")?;
        let info = derive_info()?;
        let prk = Salt::new(HKDF_SHA256, &[]).extract(&parent[32..]);
        let mut child = vec![0_u8; 32];
        prk.expand(&[&info], HKDF_SHA256)
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

/// The default shape's KEK: its planted heap copy, and the AES-256-GCM key object built from it.
type AsisKek = (Vec<u8>, LessSafeKey);

/// The default shape of a wrap: the KEK and the key in planted heap copies, an AES-256-GCM key
/// object kept, the key sealed in place in its copy.
fn asis_seal(file: &File) -> Result<(AsisKek, Vec<u8>)> {
    let kek = planted_plain(file, KEK, "kek")?;
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &kek[32..]).map_err(material::other)?);
    let mut sealed = planted_plain(file, DEK, "dek")?;
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

/// SQLCipher's key text of a key: built in a text slot and lent to a closure in the product
/// shape; in the default shape, built in a heap buffer as `vilicus-storage` builds it today and
/// freed with no wipe.
fn key_text(file: &File, core: bool) -> Result<()> {
    if core {
        let key = material::planted(file, KEY)?;
        let len = measured("key-text", || {
            key.with_sqlcipher_key_text(|text| std::hint::black_box(text).len())
        })?;
        say(&format!("TEXT {len}"));
        pause("LIVE");
        drop(key);
    } else {
        let key = planted_plain(file, KEY, "key")?;
        let mut text = Vec::with_capacity(vilicus_crypto::SQLCIPHER_KEY_TEXT_LEN);
        text.extend_from_slice(b"x'");
        text.extend_from_slice(material::hex(&key[32..]).as_bytes());
        text.push(b'\'');
        std::hint::black_box(&text);
        pause("LIVE");
        drop((key, text));
    }
    pause("DROPPED");
    Ok(())
}

/// The default shape of an HKDF-SHA-256 derivation from `ikm` under `info`: the PRK object and the
/// child kept in heap memory until the drop.
fn asis_derive(ikm: &[u8], info: &[u8]) -> Result<(aws_lc_rs::hkdf::Prk, Vec<u8>)> {
    let prk = Salt::new(HKDF_SHA256, &[]).extract(ikm);
    let mut child = vec![0_u8; 32];
    prk.expand(&[info], HKDF_SHA256)
        .map_err(material::other)?
        .fill(&mut child)
        .map_err(material::other)?;
    Ok((prk, child))
}

/// SQLCipher's key text of `key` as a heap buffer, the default shape.
fn asis_key_text(key: &[u8]) -> Vec<u8> {
    let mut text = Vec::with_capacity(vilicus_crypto::SQLCIPHER_KEY_TEXT_LEN);
    text.extend_from_slice(b"x'");
    text.extend_from_slice(material::hex(key).as_bytes());
    text.push(b'\'');
    text
}

/// Story 4.3: a member DEK planted in a slot derives the key of one of its module files, whose
/// SQLCipher key text is then lent, as the Core keys a file with it. The default shape derives
/// the same key on aws-lc-rs directly and builds the text in a heap buffer.
fn file_key(file: &File, core: bool) -> Result<()> {
    if core {
        let dek = testing::member_dek_from_file(file, ROOT.0, material::member(), ROOT_VERSION)?;
        let key = measured("file-key", || {
            dek.file_key(&ModuleName::from_static(MODULE), GENERATION)
        })?;
        let len = measured("file-key-text", || {
            key.with_sqlcipher_key_text(|text| std::hint::black_box(text).len())
        })?;
        say(&format!("TEXT {len}"));
        pause("LIVE");
        drop((dek, key));
    } else {
        let root = planted_plain(file, ROOT, "root")?;
        let (prk, child) = asis_derive(&root[32..], &material::file_key_info())?;
        let text = asis_key_text(&child);
        std::hint::black_box(&text);
        pause("LIVE");
        drop((root, prk, child, text));
    }
    pause("DROPPED");
    Ok(())
}

/// Story 4.3: the instance key read from its credential straight into a slot, then the home
/// partition root and the `core.db` key derived from it. The default shape reads the credential
/// into a heap buffer, reported as its planted input, and derives on aws-lc-rs directly.
fn instance_key(material_path: &Path, core: bool) -> Result<()> {
    let credential = material::credential_path(material_path);
    if core {
        let instance = measured("instance-key", || {
            InstanceKey::from_credential(&credential, 1)
        })?;
        let home = measured("home-root", || instance.home_partition_root())?;
        let core_db = measured("core-db-key", || instance.core_metadata_key())?;
        pause("LIVE");
        drop((instance, home, core_db));
    } else {
        let read = std::fs::read(&credential)?;
        let mut instance = vec![0_u8; 64];
        instance[32..].copy_from_slice(&read);
        drop(read);
        say(&format!(
            "PLANTED instance {:x}",
            instance[32..].as_ptr().addr()
        ));
        let home = asis_derive(
            &instance[32..],
            &material::hkdf_info("vilicus/v1/partition/home", &[]),
        )?;
        let core_db = asis_derive(
            &instance[32..],
            &material::hkdf_info("vilicus/v1/core/db", &[]),
        )?;
        pause("LIVE");
        drop((instance, home, core_db));
    }
    pause("DROPPED");
    Ok(())
}

/// Story 4.3, gate AD36-1: a household key planted in a slot derives the `wrappers.db` set MAC
/// key, which seals a record set and verifies it. The default shape derives the same key on
/// aws-lc-rs directly and keeps its HMAC key object until the drop.
fn set_mac(file: &File, core: bool) -> Result<()> {
    if core {
        let hk = testing::household_key_from_file(file, HOUSEHOLD.0, HOUSEHOLD_VERSION)?;
        let set_key = measured("set-key", || hk.wrapper_set_key())?;
        let mac = measured("set-mac-seal", || set_key.seal(SET_COUNTER, &SET_RECORDS))?;
        measured("set-mac-verify", || {
            set_key.verify(&mac, SET_COUNTER, &SET_RECORDS)
        })?;
        pause("LIVE");
        drop((hk, set_key, mac));
    } else {
        let hk = planted_plain(file, HOUSEHOLD, "hk")?;
        let (prk, set_key) = asis_derive(&hk[32..], &material::set_key_info())?;
        let mac_key = hmac::Key::new(hmac::HMAC_SHA256, &set_key);
        let mut context = hmac::Context::with_key(&mac_key);
        for record in SET_RECORDS {
            context.update(record);
        }
        let tag = context.sign();
        std::hint::black_box(&tag);
        pause("LIVE");
        drop((hk, prk, set_key, mac_key, tag));
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
            let ((kek, key), mut sealed) = asis_seal(&file).map_err(|e| e.to_string())?;
            let opened = key
                .open_in_place(
                    Nonce::assume_unique_for_key(NONCE),
                    Aad::from(CONTEXT),
                    &mut sealed[32..],
                )
                .map(|plaintext| plaintext.to_vec());
            drop((kek, key, sealed, opened));
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

fn observe_panic() {
    pause("PANICKED");
}

/// The Core's panic shape: a panic inside a handler's boundary unwinds to it and the keys stay;
/// a panic outside one wipes the pool and aborts. `start_key_memory` installed the hook.
fn panic_hook(file: &File) -> Result<()> {
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
    let mut control = vec![0_u8; 32];
    file.read_exact_at(&mut control, MARKER.0)?;
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
    let marker = planted_plain(file, MARKER, "marker")?;
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
    file.read_exact_at(&mut plain[..32], KEY.0)?;
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
