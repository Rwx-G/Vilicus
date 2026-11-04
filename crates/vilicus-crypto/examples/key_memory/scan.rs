//! Reads another process's memory through `/proc/<pid>/mem` and finds copies of patterns, as
//! Story 1.10's inspection method does (its Result, "Inspection method").
//!
//! A pattern of 16 bytes or more is cut into 16-byte windows every 8 bytes, the last window
//! ending at the pattern's end; a window found anywhere counts as an occurrence of its pattern
//! at the start address it implies, so a copy whose head was overwritten is still reported, and
//! any surviving run of 23 bytes or more of a pattern is found. A window that also belongs to
//! another pattern is ignored for a pattern that has windows of its own.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::FileExt;

use crate::material::Pattern;

const WINDOW: usize = 16;
const STEP: usize = 8;

/// What kind of mapping a hit is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegionKind {
    /// The locked key pool.
    Pool,
    /// The `[heap]` mapping.
    Heap,
    /// The main thread's `[stack]`.
    Stack,
    /// Any other anonymous mapping: allocations, arenas, thread stacks.
    Anonymous,
    /// A file-backed mapping.
    File,
}

impl fmt::Display for RegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pool => "pool",
            Self::Heap => "heap",
            Self::Stack => "stack",
            Self::Anonymous => "anon",
            Self::File => "file",
        })
    }
}

/// One mapping of the target process.
#[derive(Debug, Clone)]
pub struct Region {
    pub start: usize,
    pub end: usize,
    pub kind: RegionKind,
}

/// The `start-end` range at the start of a maps or smaps line.
pub fn parse_range(line: &str) -> Option<(usize, usize)> {
    let (start, end) = line.split_whitespace().next()?.split_once('-')?;
    Some((
        usize::from_str_radix(start, 16).ok()?,
        usize::from_str_radix(end, 16).ok()?,
    ))
}

/// Every mapping of `pid`, whatever its protection: `/proc/<pid>/mem` reads `PROT_NONE` and other
/// non-readable private mappings for a tracer, so guard pages are searched too. Only the kernel's
/// `[vvar]`, `[vvar_vclock]` and `[vsyscall]` pages are skipped.
pub fn regions(pid: u32, pool: (usize, usize)) -> io::Result<Vec<Region>> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mut regions = Vec::new();
    for line in maps.lines() {
        let Some((start, end)) = parse_range(line) else {
            continue;
        };
        let name = line.split_whitespace().nth(5).unwrap_or("");
        if matches!(name, "[vvar]" | "[vvar_vclock]" | "[vsyscall]") {
            continue;
        }
        let kind = if pool.1 > 0 && start <= pool.0 && pool.0 < end {
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
}

impl Findings {
    pub fn count(&self, name: &str) -> usize {
        self.hits.get(name).map_or(0, BTreeMap::len)
    }

    pub fn count_in(&self, name: &str, kind: RegionKind) -> usize {
        self.hits
            .get(name)
            .map_or(0, |hits| hits.values().filter(|k| **k == kind).count())
    }

    /// Hits outside the pool, of any pattern.
    pub fn outside_pool(&self) -> usize {
        self.hits
            .values()
            .flat_map(BTreeMap::values)
            .filter(|kind| **kind != RegionKind::Pool)
            .count()
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
}

/// The windows of a pattern set, indexed by their first 8 bytes.
pub struct Index {
    windows: HashMap<u64, Vec<(usize, usize, usize)>>,
    shared: HashMap<(usize, usize), bool>,
    has_unique: Vec<bool>,
    names: Vec<String>,
    bytes: Vec<Vec<u8>>,
}

fn windows(len: usize) -> Vec<(usize, usize)> {
    if len < WINDOW {
        return vec![(0, len)];
    }
    let mut offsets: Vec<usize> = (0..=len - WINDOW).step_by(STEP).collect();
    if offsets.last() != Some(&(len - WINDOW)) {
        offsets.push(len - WINDOW);
    }
    offsets.into_iter().map(|offset| (offset, WINDOW)).collect()
}

fn head(bytes: &[u8]) -> u64 {
    u64::from_ne_bytes(bytes[..8].try_into().expect("8 bytes"))
}

impl Index {
    /// The index of `patterns`, each at least 8 bytes long.
    pub fn new(patterns: &[Pattern]) -> Index {
        let mut owners: HashMap<&[u8], BTreeSet<usize>> = HashMap::new();
        for (id, p) in patterns.iter().enumerate() {
            assert!(
                p.bytes.len() >= 8,
                "pattern {} is shorter than 8 bytes",
                p.name
            );
            for (offset, len) in windows(p.bytes.len()) {
                owners
                    .entry(&p.bytes[offset..offset + len])
                    .or_default()
                    .insert(id);
            }
        }
        let mut index = Index {
            windows: HashMap::new(),
            shared: HashMap::new(),
            has_unique: vec![false; patterns.len()],
            names: patterns.iter().map(|p| p.name.clone()).collect(),
            bytes: patterns.iter().map(|p| p.bytes.clone()).collect(),
        };
        for (id, p) in patterns.iter().enumerate() {
            for (offset, len) in windows(p.bytes.len()) {
                index
                    .windows
                    .entry(head(&p.bytes[offset..]))
                    .or_default()
                    .push((id, offset, len));
                let shared = owners[&p.bytes[offset..offset + len]].len() > 1;
                index.shared.insert((id, offset), shared);
                index.has_unique[id] |= !shared;
            }
        }
        index
    }

    /// Records every occurrence in `data`, read at `address`.
    pub fn search(&self, data: &[u8], address: usize, kind: RegionKind, findings: &mut Findings) {
        if data.len() < 8 {
            return;
        }
        for i in 0..=data.len() - 8 {
            let Some(candidates) = self.windows.get(&head(&data[i..])) else {
                continue;
            };
            for &(id, offset, len) in candidates {
                if self.has_unique[id] && self.shared[&(id, offset)] {
                    continue;
                }
                if data.get(i..i + len) == Some(&self.bytes[id][offset..offset + len]) {
                    findings
                        .hits
                        .entry(self.names[id].clone())
                        .or_default()
                        .insert((address + i).wrapping_sub(offset), kind);
                }
            }
        }
    }
}

pub fn open_memory(pid: u32) -> io::Result<File> {
    File::open(format!("/proc/{pid}/mem"))
}

/// Reads every mapping of `pid` and searches it for `patterns`. Fails if any mapping cannot be
/// read, so that an unread region never passes as one with nothing in it.
pub fn scan(pid: u32, pool: (usize, usize), patterns: &[Pattern]) -> io::Result<Findings> {
    let index = Index::new(patterns);
    let memory = open_memory(pid)?;
    let mut findings = Findings::default();
    let mut unreadable = Vec::new();
    for region in regions(pid, pool)? {
        let mut data = vec![0_u8; region.end - region.start];
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
    if !unreadable.is_empty() {
        return Err(io::Error::other(format!(
            "unreadable mapping(s): {}",
            unreadable.join("; ")
        )));
    }
    Ok(findings)
}
