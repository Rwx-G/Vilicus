//! Reads another process's memory through `/proc/<pid>/mem` and finds copies of patterns.
//!
//! A pattern of 16 bytes or more is cut into 16-byte windows every 8 bytes (the last window
//! ends at the pattern's end); a shorter pattern is one window. A window found anywhere counts
//! as an occurrence of its pattern at the inferred start address, so a copy whose head was
//! overwritten (as `free` does to the first 16 bytes of a chunk) is still reported, and any
//! surviving run of 23 bytes or more of a pattern is found. Runs shorter than that, and
//! patterns transformed beyond the forms in `patterns.rs`, are not detected. A window whose
//! bytes also belong to another pattern (a key and its clamped form share their middle) is
//! ignored for a pattern that has windows of its own, so a hit is attributed to one form.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::FileExt;

use crate::patterns::Pattern;

const WINDOW: usize = 16;
const STEP: usize = 8;
const FILTER_BITS: u32 = 24;

/// What kind of mapping a hit is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegionKind {
    /// The locked key pool.
    Pool,
    /// The `[heap]` mapping (brk heap).
    Heap,
    /// The main thread's `[stack]`.
    Stack,
    /// Any other anonymous mapping: mmap'ed allocations, glibc arenas, thread stacks.
    Anonymous,
    /// A file-backed mapping (the binary's data and bss, libraries).
    File,
}

impl fmt::Display for RegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            RegionKind::Pool => "pool",
            RegionKind::Heap => "heap",
            RegionKind::Stack => "stack",
            RegionKind::Anonymous => "anon",
            RegionKind::File => "file",
        };
        f.write_str(name)
    }
}

/// One readable mapping of the target process.
#[derive(Debug, Clone)]
pub struct Region {
    /// Start address.
    pub start: usize,
    /// End address (exclusive).
    pub end: usize,
    /// Classification.
    pub kind: RegionKind,
}

/// Lists every mapping of `pid`, whatever its protection: `/proc/<pid>/mem` reads through
/// `PROT_NONE` and other non-readable private mappings (the kernel forces the access for a
/// tracer), so guard pages and pages a library made inaccessible are searched too. Only the
/// kernel-provided `[vvar]`, `[vvar_vclock]` and `[vsyscall]` pages are skipped: they hold
/// kernel time data and an emulated syscall page, never process memory.
pub fn regions(pid: u32, pool: (usize, usize)) -> io::Result<Vec<Region>> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mut regions = Vec::new();
    for line in maps.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some((start, end)) = crate::pool::parse_range(line) else {
            continue;
        };
        let name = fields.get(5).copied().unwrap_or("");
        if matches!(name, "[vvar]" | "[vvar_vclock]" | "[vsyscall]") {
            continue;
        }
        let kind = if start <= pool.0 && pool.0 < end {
            RegionKind::Pool
        } else if name == "[heap]" {
            RegionKind::Heap
        } else if name == "[stack]" {
            RegionKind::Stack
        } else if name.is_empty() || name.starts_with('[') {
            RegionKind::Anonymous
        } else {
            RegionKind::File
        };
        regions.push(Region { start, end, kind });
    }
    Ok(regions)
}

/// Where each pattern was found.
#[derive(Debug, Default)]
pub struct Findings {
    /// Pattern name to the distinct start addresses found, with their region kind.
    pub hits: BTreeMap<String, BTreeMap<usize, RegionKind>>,
    /// Bytes read.
    pub bytes_read: usize,
    /// Mappings that could not be read (always 0 in a returned `Findings`).
    pub unreadable: usize,
}

impl Findings {
    /// Number of occurrences of `name`.
    pub fn count(&self, name: &str) -> usize {
        self.hits.get(name).map_or(0, BTreeMap::len)
    }

    /// Number of occurrences of `name` in mappings of `kind`.
    pub fn count_in(&self, name: &str, kind: RegionKind) -> usize {
        self.hits
            .get(name)
            .map_or(0, |hits| hits.values().filter(|k| **k == kind).count())
    }

    /// `name=total[kind:count,...]` for every pattern found, or `none`.
    pub fn summary(&self) -> String {
        if self.hits.is_empty() {
            return "none".to_string();
        }
        self.hits
            .iter()
            .map(|(name, hits)| {
                let mut per_kind: BTreeMap<RegionKind, usize> = BTreeMap::new();
                for kind in hits.values() {
                    *per_kind.entry(*kind).or_default() += 1;
                }
                let kinds: Vec<String> = per_kind.iter().map(|(k, n)| format!("{k}:{n}")).collect();
                format!("{name}={}[{}]", hits.len(), kinds.join(","))
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Addresses of the occurrences of `name`.
    pub fn addresses(&self, name: &str) -> Vec<usize> {
        self.hits
            .get(name)
            .map(|hits| hits.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Names of the patterns found.
    pub fn names(&self) -> BTreeSet<String> {
        self.hits.keys().cloned().collect()
    }
}

/// The windows of a pattern set, indexed by their first 8 bytes, behind a bit filter.
pub struct Index {
    filter: Vec<u64>,
    windows: HashMap<u64, Vec<(usize, usize, usize)>>,
    shared: HashMap<(usize, usize), bool>,
    has_unique: Vec<bool>,
    names: Vec<String>,
    bytes: Vec<Vec<u8>>,
}

impl Index {
    /// Builds the index of `patterns`. Patterns shorter than 8 bytes are refused.
    pub fn new(patterns: &[Pattern]) -> Index {
        let mut index = Index {
            filter: vec![0; 1 << (FILTER_BITS - 6)],
            windows: HashMap::new(),
            shared: HashMap::new(),
            has_unique: vec![false; patterns.len()],
            names: patterns.iter().map(|p| p.name.clone()).collect(),
            bytes: patterns.iter().map(|p| p.bytes.clone()).collect(),
        };
        let mut owners: HashMap<&[u8], BTreeSet<usize>> = HashMap::new();
        for (id, p) in patterns.iter().enumerate() {
            for (offset, len) in windows(p.bytes.len()) {
                owners
                    .entry(&p.bytes[offset..offset + len])
                    .or_default()
                    .insert(id);
            }
        }
        for (id, p) in patterns.iter().enumerate() {
            assert!(
                p.bytes.len() >= 8,
                "pattern {} shorter than 8 bytes",
                p.name
            );
            for (offset, len) in windows(p.bytes.len()) {
                let head = head(&p.bytes[offset..]);
                let bit = filter_bit(head);
                index.filter[bit / 64] |= 1 << (bit % 64);
                index
                    .windows
                    .entry(head)
                    .or_default()
                    .push((id, offset, len));
                let shared = owners[&p.bytes[offset..offset + len]].len() > 1;
                index.shared.insert((id, offset), shared);
                index.has_unique[id] |= !shared;
            }
        }
        index
    }

    /// Records every occurrence in `data`, which was read at `address`.
    pub fn search(&self, data: &[u8], address: usize, kind: RegionKind, findings: &mut Findings) {
        if data.len() < 8 {
            return;
        }
        for i in 0..=data.len() - 8 {
            let head = head(&data[i..]);
            let bit = filter_bit(head);
            if self.filter[bit / 64] & (1 << (bit % 64)) == 0 {
                continue;
            }
            let Some(candidates) = self.windows.get(&head) else {
                continue;
            };
            for &(id, offset, len) in candidates {
                if self.has_unique[id] && self.shared[&(id, offset)] {
                    continue;
                }
                let pattern_window = &self.bytes[id][offset..offset + len];
                if data.get(i..i + len) == Some(pattern_window) {
                    let start = (address + i).wrapping_sub(offset);
                    findings
                        .hits
                        .entry(self.names[id].clone())
                        .or_default()
                        .insert(start, kind);
                }
            }
        }
    }
}

fn windows(len: usize) -> Vec<(usize, usize)> {
    if len < WINDOW {
        return vec![(0, len)];
    }
    let mut offsets: Vec<usize> = (0..=len - WINDOW).step_by(STEP).collect();
    if offsets.last() != Some(&(len - WINDOW)) {
        offsets.push(len - WINDOW);
    }
    offsets.into_iter().map(|o| (o, WINDOW)).collect()
}

fn head(bytes: &[u8]) -> u64 {
    u64::from_ne_bytes(bytes[..8].try_into().expect("8 bytes"))
}

fn filter_bit(head: u64) -> usize {
    (head.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (64 - FILTER_BITS)) as usize
}

/// Opens `/proc/<pid>/mem`. Fails when the caller may not read the target's memory.
pub fn open_memory(pid: u32) -> io::Result<File> {
    File::open(format!("/proc/{pid}/mem"))
}

/// Reads every mapping of `pid` and searches it for `patterns`. Fails if any mapping cannot be
/// read, so that an unread region can never pass as a region with nothing in it.
pub fn scan(pid: u32, pool: (usize, usize), patterns: &[Pattern]) -> io::Result<Findings> {
    let index = Index::new(patterns);
    let memory = open_memory(pid)?;
    let mut findings = Findings::default();
    let mut unreadable = Vec::new();
    for region in regions(pid, pool)? {
        let mut data = vec![0u8; region.end - region.start];
        match memory.read_exact_at(&mut data, region.start as u64) {
            Ok(()) => {
                findings.bytes_read += data.len();
                index.search(&data, region.start, region.kind, &mut findings);
            }
            Err(error) => unreadable.push(format!(
                "{:x}-{:x} {} ({error})",
                region.start, region.end, region.kind
            )),
        }
    }
    findings.unreadable = unreadable.len();
    if !unreadable.is_empty() {
        return Err(io::Error::other(format!(
            "unreadable mapping(s): {}",
            unreadable.join("; ")
        )));
    }
    Ok(findings)
}
