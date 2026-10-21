//! Test code: the file inspection of Story 1.11 (E17), on the product build. It reads a module
//! file, its WAL and its shm as bytes, never through SQL, decrypts every page of the file, free
//! pages included, and every frame physically present in the WAL, stale frames included, and
//! searches them for runs of known values, as `spikes/secure-delete-wal/src/pages.rs` and
//! `src/scan.rs` do. A spike is evidence, not product code, so the procedure is ported here
//! rather than depended on.
//!
//! SQLCipher 4 page layout with its default settings: the first `PAGE_SIZE - RESERVE` bytes of a
//! page are AES-256-CBC ciphertext, followed by a 16-byte IV and a 64-byte HMAC-SHA512; on page 1
//! the first 16 bytes hold the KDF salt in clear instead of the SQLite magic string. A file keyed
//! with a raw 256-bit key is encrypted under that key itself. WAL headers and frame headers are
//! not encrypted; each frame carries one page encrypted like the page in the file. The shm holds
//! the WAL index, never page content, and is scanned as it is. Any layout surprise is a panic,
//! never a silent pass-through.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use aws_lc_rs::cipher::{AES_256, DecryptingKey, DecryptionContext, UnboundCipherKey};
use aws_lc_rs::iv::FixedLength;
use vilicus_storage::ModuleFile;

const PAGE_SIZE: usize = 4096;
/// IV (16) plus HMAC-SHA512 (64), the SQLCipher 4 default reserve.
const RESERVE: usize = 80;
const IV_LEN: usize = 16;
const SALT_LEN: usize = 16;
const WAL_HEADER_LEN: usize = 32;
const WAL_FRAME_HEADER_LEN: usize = 24;

/// A file's decrypted pages, its WAL's decrypted frames and its raw shm.
pub(super) struct Inspected {
    /// Every page of the database file, decrypted, in page order.
    pub(super) file: Vec<u8>,
    /// Every frame of the WAL, decrypted, in file order; empty when there is no WAL content.
    pub(super) wal: Vec<u8>,
    /// The frames the WAL held.
    pub(super) wal_frames: usize,
    /// The shm as it is.
    pub(super) shm: Vec<u8>,
}

impl Inspected {
    /// Each part of the inspection by name, for the assertions.
    pub(super) fn parts(&self) -> [(&'static str, &[u8]); 3] {
        [
            ("file", self.file.as_slice()),
            ("wal", self.wal.as_slice()),
            ("shm", self.shm.as_slice()),
        ]
    }
}

fn read_or_empty(path: &Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("read {}: {error}", path.display()),
    }
}

/// Reads and decrypts `file` under its raw `key`.
pub(super) fn inspect(file: &ModuleFile, key: &[u8; 32]) -> Inspected {
    let raw = read_or_empty(&file.path());
    assert!(
        !raw.is_empty() && raw.len().is_multiple_of(PAGE_SIZE),
        "the file is whole {PAGE_SIZE}-byte pages"
    );
    let decrypting = DecryptingKey::cbc(UnboundCipherKey::new(&AES_256, key).expect("an AES key"))
        .expect("AES-256-CBC");
    let decrypted: Vec<u8> = raw
        .as_chunks::<PAGE_SIZE>()
        .0
        .iter()
        .enumerate()
        .flat_map(|(index, page)| decrypt_page(&decrypting, page, index == 0))
        .collect();
    assert_eq!(
        (
            u16::from_be_bytes([decrypted[16], decrypted[17]]),
            decrypted[20],
            [decrypted[21], decrypted[22], decrypted[23]]
        ),
        (4096, 80, [64, 32, 32]),
        "page 1 decrypts to a SQLite header of the SQLCipher 4 layout"
    );
    let wal_raw = read_or_empty(&file.wal_path());
    let (wal, wal_frames) = if wal_raw.is_empty() {
        (Vec::new(), 0)
    } else {
        assert!(
            wal_raw.len() >= WAL_HEADER_LEN,
            "a WAL starts with its header"
        );
        let page_size = u32::from_be_bytes([wal_raw[8], wal_raw[9], wal_raw[10], wal_raw[11]]);
        assert_eq!(page_size, 4096, "the WAL page size");
        let frames = &wal_raw[WAL_HEADER_LEN..];
        let frame_len = WAL_FRAME_HEADER_LEN + PAGE_SIZE;
        assert_eq!(frames.len() % frame_len, 0, "no partial WAL frame");
        let decrypted: Vec<u8> = frames
            .chunks_exact(frame_len)
            .flat_map(|frame| {
                let page_number = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
                decrypt_page(
                    &decrypting,
                    &frame[WAL_FRAME_HEADER_LEN..],
                    page_number == 1,
                )
            })
            .collect();
        (decrypted, frames.len() / frame_len)
    };
    let mut shm_path = file.path().into_os_string();
    shm_path.push("-shm");
    Inspected {
        file: decrypted,
        wal,
        wal_frames,
        shm: read_or_empty(Path::new(&shm_path)),
    }
}

fn decrypt_page(key: &DecryptingKey, page: &[u8], first_page: bool) -> Vec<u8> {
    assert_eq!(page.len(), PAGE_SIZE);
    let start = if first_page { SALT_LEN } else { 0 };
    let end = PAGE_SIZE - RESERVE;
    let iv: [u8; IV_LEN] = page[end..end + IV_LEN].try_into().expect("an IV");
    let mut decoded = page.to_vec();
    key.decrypt(
        &mut decoded[start..end],
        DecryptionContext::Iv128(FixedLength::from(iv)),
    )
    .expect("AES-256-CBC decryption");
    decoded
}

/// A needle counts as found when a run of this many of its bytes appears.
pub(super) const WINDOW: usize = 16;
/// The finer pass: a run of 8 bytes or more (AC6 and AC7 of Story 3.6).
pub(super) const SHORT_WINDOW: usize = 8;

/// Every 16-byte and every 8-byte window of every needle, mapped to the needle it came from.
#[derive(Default)]
pub(super) struct Needles {
    windows: HashMap<[u8; WINDOW], usize>,
    short_windows: HashMap<[u8; SHORT_WINDOW], usize>,
    count: usize,
}

impl Needles {
    pub(super) fn add(&mut self, needle: &[u8]) {
        assert!(
            needle.len() >= WINDOW,
            "a needle is at least one window long"
        );
        let id = self.count;
        self.count += 1;
        for window in needle.windows(WINDOW) {
            self.windows
                .insert(window.try_into().expect("window length"), id);
        }
        for window in needle.windows(SHORT_WINDOW) {
            self.short_windows
                .insert(window.try_into().expect("window length"), id);
        }
    }

    pub(super) fn len(&self) -> usize {
        self.count
    }

    /// The needles of which a run of 16 bytes or more appears in `haystack`.
    pub(super) fn found_in(&self, haystack: &[u8]) -> usize {
        hits(&self.windows, haystack)
    }

    /// The needles of which a run of 8 bytes or more appears in `haystack`.
    pub(super) fn found_in_short(&self, haystack: &[u8]) -> usize {
        hits(&self.short_windows, haystack)
    }
}

fn hits<const N: usize>(windows: &HashMap<[u8; N], usize>, haystack: &[u8]) -> usize {
    let mut found = BTreeSet::new();
    for window in haystack.windows(N) {
        if let Some(id) = windows.get(window) {
            found.insert(*id);
        }
    }
    found.len()
}

/// A fixed-seed SplitMix64 generator: every run writes the same known values, which a scan then
/// looks for. Test values, not keys.
pub(super) struct Rng(u64);

impl Rng {
    pub(super) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(super) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    pub(super) fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length)
            .map(|_| self.next_u64().to_le_bytes()[0])
            .collect()
    }

    /// Random text of `length` characters from 64 letters, digits and two signs: 6 bits a byte,
    /// so a run of 8 bytes (48 bits) of one value does not appear in another by chance at the
    /// sizes the tests scan.
    pub(super) fn text(&mut self, length: usize) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";
        (0..length)
            .map(|_| char::from(ALPHABET[usize::from(self.next_u64().to_le_bytes()[0] & 0x3f)]))
            .collect()
    }

    pub(super) fn random_10(&mut self) -> [u8; 10] {
        self.bytes(10).try_into().expect("ten bytes")
    }
}

#[test]
fn a_surviving_run_of_one_window_is_found_and_a_shorter_one_is_not() {
    let mut rng = Rng::new(1);
    let needle = rng.bytes(200);
    let mut needles = Needles::default();
    needles.add(&needle);
    let mut haystack = vec![0u8; 4096];
    haystack[1000..1000 + WINDOW].copy_from_slice(&needle[77..77 + WINDOW]);
    assert_eq!(
        (
            needles.found_in(&haystack),
            needles.found_in_short(&haystack)
        ),
        (1, 1)
    );
    let mut haystack = vec![0u8; 4096];
    haystack[1000..1000 + WINDOW - 1].copy_from_slice(&needle[10..10 + WINDOW - 1]);
    assert_eq!(
        (
            needles.found_in(&haystack),
            needles.found_in_short(&haystack)
        ),
        (0, 1)
    );
    let mut haystack = vec![0u8; 4096];
    haystack[1000..1000 + SHORT_WINDOW - 1].copy_from_slice(&needle[10..10 + SHORT_WINDOW - 1]);
    assert_eq!(needles.found_in_short(&haystack), 0);
}
