//! Coverage-guided fuzz targets of `vilicus-proto` (Story 2.7), and the checks they run.
//!
//! Each [`Target`] is a check over raw bytes that panics when an input breaks the decoding
//! invariants of `doc/architecture-spine.md` AD-12 and AD-13: an accepted input encodes back to
//! exactly its bytes, and the decoded value stays within the profile bounds (nesting depth, item
//! bound of the socket kind). A decoder that panics, overflows the stack or allocates past the
//! memory limit fails the run on its own. The same checks run in two ways:
//!
//! - under libFuzzer, with the `libfuzzer` feature, on the nightly toolchain of the `fuzz` job,
//!   driven by `ci/fuzz.py`;
//! - on stable, without any fuzzing dependency, by the regression replay of `tests/` over the
//!   minimized inputs committed under `crates/vilicus-proto/tests/data/fuzz/`, and by each target
//!   built without the feature, which replays the files and directories it is given.
//!
//! No crate depends on this one (`ci/crate_graph.toml`, `[isolated.fuzz]`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use dcbor::{CBOR, CBORCase};
use vilicus_proto::SocketKind;
use vilicus_proto::frame::{self, FrameError, LENGTH_PREFIX_LEN};
use vilicus_proto::message::{
    self, Hello, HelloRefusal, HelloReply, Message, RequestBody, first_frame,
};
use vilicus_proto::profile::{self, LISTED_TAGS, MAX_DEPTH, Rejection};
use vilicus_proto::wire::{self, DecodeError, Wire};
use vilicus_types::{
    ClientError, DataType, ErrorCode, ExceptionClass, Id, MessageKey, ModuleName, OperatorSetting,
    Principal, RetryClass, Source, Taint, Tier, UtcMillis,
};

/// Bytes per data item a decoded message may hold in memory, for the memory limit. Story 2.5
/// measured at most 215 (a map at the data item bound, 53.9 MiB for 262 144 items), rounded up.
const BYTES_PER_ITEM: u64 = 256;

/// Copies of the message bytes a decode holds at once: the frame, `dcbor`'s copy, the profile's
/// round-trip re-encoding (Story 2.5) and the check's own re-encoding.
const MESSAGE_COPIES: u64 = 4;

/// Resident memory of a fuzzing process besides the decode of the input it runs, in MiB: the
/// libFuzzer and AddressSanitizer runtimes, the corpus, and the freed memory a long run keeps
/// mapped, which Story 2.7 measured on 10-minute runs of every target (Result).
const RUNTIME_MIB: u64 = 256;

/// How much more memory a decoded message may take under AddressSanitizer than its decode
/// budget, rounded up from Story 2.7's measure of the worst message of each socket kind (Result):
/// red zones around every allocation and the shadow memory.
const SANITIZER_FACTOR: u64 = 3;

const MIB: u64 = 1 << 20;

/// How a target reads its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// The bytes of one message.
    Message,
    /// A stream of frames, each a length prefix and a message.
    Frames,
    /// One frame whose message is described by a repetition, read by [`expand`], so that the
    /// fuzzer reaches messages of any size up to the frame maximum from a few bytes.
    Repeated,
}

impl Input {
    /// The name `ci/fuzz.py` reads.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Frames => "frames",
            Self::Repeated => "repeated",
        }
    }

    /// A message in the shape a target of this input reads: the message itself, one frame
    /// holding it, or a repetition making an array that holds it once.
    pub fn shape(self, message: &[u8]) -> Vec<u8> {
        let len = u32::try_from(message.len()).expect("a vector input fits a frame");
        match self {
            Self::Message => message.to_vec(),
            Self::Frames => [&len.to_be_bytes()[..], message].concat(),
            Self::Repeated => [&1u32.to_be_bytes()[..], &0u32.to_be_bytes(), message].concat(),
        }
    }
}

/// One fuzz target: the binary of `src/bin/` that bears its name runs [`Target::check`].
pub struct Target {
    /// The target's name, which is also the name of its binary and of its regression directory.
    pub name: &'static str,
    /// The socket kind whose frame maximum and item bound limit the target's inputs and memory.
    pub kind: SocketKind,
    /// How the target reads its input, which tells `ci/fuzz.py` how to shape its seeds.
    pub input: Input,
    /// The public decoding entry points of `vilicus-proto` the target reaches: functions as
    /// `module::function`, types decoded through their `Wire::from_cbor` by their name.
    pub decoders: &'static [&'static str],
    /// The check: returns when the input is refused or round-trips within bounds, panics
    /// otherwise.
    pub check: fn(&[u8]),
}

impl Target {
    /// Longest input libFuzzer generates: a whole frame of the target's socket kind, prefix
    /// included, so that a frame at the maximum can be reached.
    pub const fn max_len(&self) -> u64 {
        self.kind.max_message_len() as u64 + LENGTH_PREFIX_LEN as u64
    }

    /// Memory a decode may hold for one message of the socket kind, in bytes: every copy of the
    /// largest message, and the largest number of items at their measured cost.
    pub const fn decode_budget(&self) -> u64 {
        MESSAGE_COPIES * self.kind.max_message_len() as u64
            + BYTES_PER_ITEM * self.kind.max_items() as u64
    }

    /// The single allocation that fails the run, in MiB: twice the frame maximum, plus one. A
    /// buffer a decode needs holds one message, with the slack of a growing buffer: decoding a
    /// 16 MiB byte string makes one 20 MiB allocation (Story 2.7, Result). A larger one is
    /// reserved from what an input declares, or is a vector of items amplifying past the frame:
    /// the decoded array of Story 2.5's review, before the item bound, reserved 8 bytes per item,
    /// 128 MiB for a data frame.
    pub const fn malloc_limit_mib(&self) -> u64 {
        2 * self.kind.max_message_len() as u64 / MIB + 1
    }

    /// Peak resident memory of the fuzzing process that fails the run, in MiB: the runtimes, then
    /// the decode budget under AddressSanitizer. It catches an amplification made of many small
    /// allocations, which the single-allocation limit does not see.
    pub const fn rss_limit_mib(&self) -> u64 {
        RUNTIME_MIB + SANITIZER_FACTOR * self.decode_budget().div_ceil(MIB)
    }

    /// The seed corpus of the target: every vector input in the shape the target reads, then its
    /// committed failing inputs as they are.
    pub fn seeds(&self) -> Vec<Vec<u8>> {
        let mut seeds: Vec<_> = vector_inputs()
            .iter()
            .map(|message| self.input.shape(message))
            .collect();
        seeds.extend(regression_inputs(self));
        seeds
    }
}

/// Every fuzz target.
pub const TARGETS: &[Target] = &[
    Target {
        name: "frame_control",
        input: Input::Frames,
        kind: SocketKind::Control,
        decoders: FRAME_DECODERS,
        check: |data| frames(SocketKind::Control, data),
    },
    Target {
        name: "frame_data",
        input: Input::Frames,
        kind: SocketKind::Data,
        decoders: FRAME_DECODERS,
        check: |data| frames(SocketKind::Data, data),
    },
    Target {
        name: "frame_control_repeated",
        input: Input::Repeated,
        kind: SocketKind::Control,
        decoders: FRAME_DECODERS,
        check: |data| repeated(SocketKind::Control, data),
    },
    Target {
        name: "frame_data_repeated",
        input: Input::Repeated,
        kind: SocketKind::Data,
        decoders: FRAME_DECODERS,
        check: |data| repeated(SocketKind::Data, data),
    },
    Target {
        name: "profile",
        input: Input::Message,
        kind: SocketKind::Control,
        decoders: &[
            "profile::decode",
            "profile::decode_with_max_items",
            "profile::scan_heads",
            "profile::require_round_trip",
        ],
        check: profile_bytes,
    },
    Target {
        name: "hello",
        input: Input::Message,
        kind: SocketKind::Data,
        decoders: &[
            "message::first_frame",
            "wire::decode",
            "wire::decode_with_max_items",
            "Hello",
        ],
        check: hello,
    },
    Target {
        name: "hello_reply",
        input: Input::Message,
        kind: SocketKind::Control,
        decoders: &["wire::decode_with_max_items", "HelloReply"],
        check: hello_reply,
    },
    Target {
        name: "closed_types",
        input: Input::Message,
        kind: SocketKind::Control,
        decoders: CLOSED_TYPES,
        check: closed_types,
    },
];

const FRAME_DECODERS: &[&str] = &[
    "frame::read_frame",
    "frame::read_message",
    "Message",
    "Request",
    "Response",
];

/// The target of that name.
///
/// # Panics
///
/// When no target bears the name, which is a binary of `src/bin/` without a target.
pub fn target(name: &str) -> &'static Target {
    TARGETS
        .iter()
        .find(|target| target.name == name)
        .unwrap_or_else(|| panic!("no fuzz target is named {name}"))
}

/// Declares the binary of one target, named after it: a libFuzzer entry point with the
/// `libfuzzer` feature, a replay of the files and directories given as arguments without it.
#[macro_export]
macro_rules! fuzz_target {
    () => {
        #[cfg(feature = "libfuzzer")]
        libfuzzer_sys::fuzz_target!(|data: &[u8]| {
            ($crate::target(env!("CARGO_BIN_NAME")).check)(data)
        });

        #[cfg(not(feature = "libfuzzer"))]
        fn main() -> std::process::ExitCode {
            $crate::replay_main(env!("CARGO_BIN_NAME"))
        }
    };
}

/// Runs the target's check on every file given as an argument, and on every file of every
/// directory given; a failing input panics, which names it in the message printed before.
pub fn replay_main(name: &str) -> ExitCode {
    let check = target(name).check;
    let paths: Vec<_> = std::env::args_os().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: {name} <input file or directory>...");
        return ExitCode::FAILURE;
    }
    for path in paths {
        for file in input_files(Path::new(&path)) {
            let bytes = std::fs::read(&file)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", file.display()));
            println!("{name}: {}", file.display());
            check(&bytes);
        }
    }
    ExitCode::SUCCESS
}

/// The file itself, or the files of the directory, sorted.
///
/// # Panics
///
/// When the directory cannot be listed.
pub fn input_files(path: &Path) -> Vec<PathBuf> {
    if !path.is_dir() {
        return vec![path.to_path_buf()];
    }
    let mut files: Vec<_> = std::fs::read_dir(path)
        .unwrap_or_else(|error| panic!("cannot list {}: {error}", path.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|file| file.is_file())
        .collect();
    files.sort();
    files
}

/// The E19 vector files of `vilicus-proto` whose inputs seed every target (Story 2.7, AC3).
pub const VECTOR_FILES: &[&str] = &["corpus.json", "invalid.json", "fuzz.json"];

/// Where the E19 vectors are committed, read in place rather than copied.
pub fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/vilicus-proto/tests/data/canonical-cbor")
}

/// Where the failing inputs of past runs are committed, one directory per target, replayed on
/// stable by `tests/regressions.rs` and added to the seeds of every run.
pub fn regressions_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/vilicus-proto/tests/data/fuzz")
}

/// Every input of the vector files (each item's `hex`), once, in file order.
///
/// # Panics
///
/// When a vector file cannot be read or holds an item whose `hex` is not hexadecimal.
pub fn vector_inputs() -> Vec<Vec<u8>> {
    const HEX_FIELD: &str = "\"hex\":\"";
    let mut inputs = Vec::new();
    for name in VECTOR_FILES {
        let path = vectors_dir().join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let (_, items) = text
            .split_once("\"items\":[")
            .unwrap_or_else(|| panic!("{} has no items", path.display()));
        for field in items.split(HEX_FIELD).skip(1) {
            let hex = &field[..field.find('"').expect("a hex string ends")];
            let input = decode_hex(hex)
                .unwrap_or_else(|| panic!("{} holds an item whose hex is {hex:?}", path.display()));
            if !inputs.contains(&input) {
                inputs.push(input);
            }
        }
    }
    inputs
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(hex.get(at..at + 2)?, 16).ok())
        .collect()
}

/// The committed failing inputs of the target, sorted by file name; none when it has no
/// directory.
pub fn regression_inputs(target: &Target) -> Vec<Vec<u8>> {
    let directory = regressions_dir().join(target.name);
    if !directory.is_dir() {
        return Vec::new();
    }
    input_files(&directory)
        .iter()
        .map(|file| {
            std::fs::read(file)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", file.display()))
        })
        .collect()
}

/// Panics unless the value is nested at most [`MAX_DEPTH`] arrays, maps or tags deep and holds
/// at most `max_items` data items, counted as the profile counts them. Iterative, so a value
/// that broke the depth bound cannot overflow the stack here.
pub fn assert_within_bounds(value: &CBOR, max_items: usize) {
    let mut pending = vec![(value, 0usize)];
    let mut items = 0usize;
    while let Some((item, enclosing)) = pending.pop() {
        items += 1;
        assert!(items <= max_items, "decoded more than {max_items} items");
        let depth = enclosing + 1;
        match item.as_case() {
            CBORCase::Array(elements) => {
                assert!(depth <= MAX_DEPTH, "decoded deeper than {MAX_DEPTH} levels");
                pending.extend(elements.iter().map(|element| (element, depth)));
            }
            CBORCase::Map(map) => {
                assert!(depth <= MAX_DEPTH, "decoded deeper than {MAX_DEPTH} levels");
                for (key, entry) in map.iter() {
                    pending.push((key, depth));
                    pending.push((entry, depth));
                }
            }
            CBORCase::Tagged(_, inner) => {
                assert!(depth <= MAX_DEPTH, "decoded deeper than {MAX_DEPTH} levels");
                pending.push((inner, depth));
            }
            _ => {}
        }
    }
}

/// Panics unless `value`, accepted from `bytes`, encodes back to exactly `bytes`.
fn assert_round_trip<T: Wire + core::fmt::Debug>(value: &T, bytes: &[u8]) {
    let again = wire::encode(value).unwrap_or_else(|rejection| {
        panic!("an accepted {value:?} has no canonical encoding: {rejection}")
    });
    assert_eq!(again, bytes, "an accepted {value:?} encodes to other bytes");
}

/// A request body for the frame targets, standing in for the protocols later stories define: a
/// reading request and a writing one, so that both `call_id` rules are fuzzed.
#[derive(Debug, PartialEq, Eq)]
pub enum Body {
    /// A reading request without payload.
    Get,
    /// A writing request with a payload.
    Put(Source),
}

impl Wire for Body {
    fn to_cbor(&self) -> CBOR {
        match self {
            Self::Get => CBOR::from("get"),
            Self::Put(source) => wire::tagged("put", source.to_cbor()),
        }
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        const TYPE: &str = "Body";
        let read = wire::variant(value, TYPE)?;
        match read.name {
            "get" => read.no_payload(TYPE).map(|()| Self::Get),
            "put" => Source::from_cbor(read.payload(TYPE)?).map(Self::Put),
            _ => Err(read.unknown(TYPE)),
        }
    }
}

impl RequestBody for Body {
    fn writes(&self) -> bool {
        matches!(self, Self::Put(_))
    }
}

/// The messages the frame targets read after the handshake.
pub type FuzzMessage = Message<Body, Source>;

/// Reads every frame of a stream, as a socket of `kind` would, each decoded as a [`FuzzMessage`].
/// A frame whose message is refused is skipped, so that one input exercises the frames after it.
fn frames(kind: SocketKind, data: &[u8]) {
    let mut rest = data;
    loop {
        let before = rest;
        let read = frame::read_message::<FuzzMessage>(&mut rest, kind);
        let consumed = &before[..before.len() - rest.len()];
        match read {
            Ok(message) => {
                let mut again = Vec::new();
                frame::write_message(&mut again, kind, &message).unwrap_or_else(|error| {
                    panic!("an accepted {message:?} cannot be written: {error}")
                });
                assert_eq!(
                    again, consumed,
                    "an accepted {message:?} frames to other bytes"
                );
                let value = profile::decode(&consumed[LENGTH_PREFIX_LEN..])
                    .expect("an accepted message is canonical");
                assert_within_bounds(&value, kind.max_items());
            }
            Err(FrameError::TooLarge { len, max }) => {
                assert!(
                    len > u64::from(max),
                    "a length of {len} refused below {max}"
                );
                assert_eq!(
                    consumed.len(),
                    LENGTH_PREFIX_LEN,
                    "message bytes read past a refused length"
                );
                return;
            }
            Err(FrameError::Io(_)) => return,
            Err(FrameError::Message(error)) => {
                let message = &consumed[LENGTH_PREFIX_LEN..];
                if passes_item_bound_first(message, kind.max_items()) {
                    assert_eq!(
                        error,
                        DecodeError::Profile(Rejection::TooManyItems(kind.max_items())),
                        "a message of more than {} items was decoded",
                        kind.max_items()
                    );
                }
            }
        }
    }
}

/// Whether the head walk of the profile meets item `max_items + 1` before anything else it
/// refuses: then the only verdict the item bound allows is `TooManyItems`, whatever a decode
/// without the bound would make of the message. Walks the heads without decoding and without
/// recursion, as the profile does, and stops at the first head the profile refuses earlier (a
/// malformed or truncated head, a string past the input, a tag outside [`LISTED_TAGS`], a float, nesting past
/// [`MAX_DEPTH`]), so its only allocation is the stack of open containers, at most
/// [`MAX_DEPTH`] deep.
pub fn passes_item_bound_first(bytes: &[u8], max_items: usize) -> bool {
    let mut expected: Vec<u64> = vec![1];
    let mut pos = 0usize;
    let mut items = 0usize;
    while let Some(&remaining) = expected.last() {
        if remaining == 0 {
            expected.pop();
            continue;
        }
        let top = expected.len() - 1;
        expected[top] = remaining - 1;
        items += 1;
        if items > max_items {
            return true;
        }
        let Some(&initial) = bytes.get(pos) else {
            return false;
        };
        let (major, additional) = (initial >> 5, initial & 0x1f);
        let width = match additional {
            0..=23 => 0,
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return false,
        };
        let Some(argument_bytes) = bytes.get(pos + 1..pos + 1 + width) else {
            return false;
        };
        let argument = if width == 0 {
            u64::from(additional)
        } else {
            argument_bytes
                .iter()
                .fold(0, |acc, byte| (acc << 8) | u64::from(*byte))
        };
        pos += 1 + width;
        match major {
            2 | 3 => {
                match usize::try_from(argument)
                    .ok()
                    .and_then(|len| pos.checked_add(len))
                    .filter(|end| *end <= bytes.len())
                {
                    Some(end) => pos = end,
                    None => return false,
                }
            }
            4..=6 => {
                if major == 6 && !LISTED_TAGS.contains(&argument) {
                    return false;
                }
                if expected.len() > MAX_DEPTH {
                    return false;
                }
                let count = match major {
                    4 => Some(argument),
                    5 => argument.checked_mul(2),
                    _ => Some(1),
                };
                let Some(count) = count else {
                    return false;
                };
                expected.push(count);
            }
            7 if width >= 2 => return false,
            _ => {}
        }
    }
    false
}

/// Reads a repetition: a 4-byte big-endian count, a 4-byte big-endian prefix length, the prefix,
/// then a unit. The message is the prefix, then an array of the unit repeated `count` times, or
/// as many times as fit in `max` bytes, its head in the shortest form. An array of many small
/// items is how a frame amplifies in memory (Story 2.5's review): this way the fuzzer reaches one
/// from a few bytes, at any depth the prefix opens. `None` when the input is shorter than its
/// header and prefix, or the prefix leaves no room in `max`.
pub fn expand(data: &[u8], max: usize) -> Option<Vec<u8>> {
    const LONGEST_HEAD: usize = 9;
    let (header, rest) = data.split_first_chunk::<8>()?;
    let [c0, c1, c2, c3, p0, p1, p2, p3] = *header;
    let count = u64::from(u32::from_be_bytes([c0, c1, c2, c3]));
    let prefix_len = u32::from_be_bytes([p0, p1, p2, p3]) as usize;
    if prefix_len > rest.len() {
        return None;
    }
    let (prefix, unit) = rest.split_at(prefix_len);
    let room = max.checked_sub(prefix_len + LONGEST_HEAD)?;
    // An empty unit declares the count with no element after it, which the profile refuses.
    let repeats = match unit.len() {
        0 => count,
        unit_len => count.min((room / unit_len) as u64),
    };
    let body_len = unit.len() * repeats as usize;
    let mut message = Vec::with_capacity(prefix_len + LONGEST_HEAD + body_len);
    message.extend_from_slice(prefix);
    message.extend_from_slice(&array_head(repeats));
    if !unit.is_empty() {
        for _ in 0..repeats {
            message.extend_from_slice(unit);
        }
    }
    Some(message)
}

/// The shortest head of an array of `len` elements.
fn array_head(len: u64) -> Vec<u8> {
    const ARRAY: u8 = 4 << 5;
    match len {
        0..=23 => vec![ARRAY | len as u8],
        24..=0xff => vec![ARRAY | 24, len as u8],
        0x100..=0xffff => [&[ARRAY | 25][..], &(len as u16).to_be_bytes()].concat(),
        0x1_0000..=0xffff_ffff => [&[ARRAY | 26][..], &(len as u32).to_be_bytes()].concat(),
        _ => [&[ARRAY | 27][..], &len.to_be_bytes()].concat(),
    }
}

/// One frame of the socket kind holding the message [`expand`] reads from the input.
fn repeated(kind: SocketKind, data: &[u8]) {
    let max = kind.max_message_len() as usize;
    let Some(message) = expand(data, max) else {
        return;
    };
    let len = u32::try_from(message.len()).expect("at most the frame maximum");
    let mut stream = Vec::with_capacity(LENGTH_PREFIX_LEN + message.len());
    stream.extend_from_slice(&len.to_be_bytes());
    stream.extend_from_slice(&message);
    drop(message);
    frames(kind, &stream);
}

/// The D130 profile on raw bytes, under the control item bound: an accepted input is canonical,
/// within the bounds, and accepted by the unbounded decoder and the head walk too; the bound
/// holds exactly at the number of items. The unbounded decoder never runs on an input the bound
/// refused, whose decoding the bound exists to prevent.
fn profile_bytes(data: &[u8]) {
    let max_items = SocketKind::Control.max_items();
    match profile::decode_with_max_items(data, max_items) {
        Ok(value) => {
            assert_eq!(
                profile::scan_heads(data),
                Ok(()),
                "accepted, refused by the head walk"
            );
            assert_eq!(profile::check_value(&value), Ok(()));
            assert_eq!(profile::require_round_trip(&value, data), Ok(()));
            assert_eq!(
                profile::encode(&value).as_deref(),
                Ok(data),
                "accepted, encodes otherwise"
            );
            assert_within_bounds(&value, max_items);
            assert_eq!(profile::decode(data), Ok(value.clone()));
            let items = count_items(&value);
            assert!(profile::decode_with_max_items(data, items).is_ok());
            assert_eq!(
                profile::decode_with_max_items(data, items - 1),
                Err(Rejection::TooManyItems(items - 1))
            );
        }
        Err(Rejection::TooManyItems(_)) => {}
        Err(rejection) => {
            assert_eq!(
                profile::decode(data),
                Err(rejection),
                "the verdict depends on the bound"
            );
        }
    }
}

fn count_items(value: &CBOR) -> usize {
    let mut pending = vec![value];
    let mut items = 0;
    while let Some(item) = pending.pop() {
        items += 1;
        match item.as_case() {
            CBORCase::Array(elements) => pending.extend(elements),
            CBORCase::Map(map) => pending.extend(map.iter().flat_map(|(key, entry)| [key, entry])),
            CBORCase::Tagged(_, inner) => pending.push(inner),
            _ => {}
        }
    }
    items
}

/// The first frame of a connection, on both socket kinds, and the bare `Hello` decoder: an
/// accepted `Hello` round-trips and negotiates its own highest version. The unbounded decoder
/// runs only on an input the data item bound does not refuse.
fn hello(data: &[u8]) {
    let bare = match wire::decode_with_max_items::<Hello>(data, SocketKind::Data.max_items()) {
        Err(DecodeError::Profile(Rejection::TooManyItems(_))) => return,
        bounded => {
            assert_eq!(
                wire::decode::<Hello>(data),
                bounded,
                "the verdict depends on the bound"
            );
            bounded
        }
    };
    if let Ok(hello) = &bare {
        assert_round_trip(hello, data);
        let highest = *hello.versions.last().expect("versions are non-empty");
        assert_eq!(
            message::negotiate(hello, &hello.protocol, &hello.versions),
            HelloReply::Accepted(highest)
        );
    }
    for kind in [SocketKind::Control, SocketKind::Data] {
        match first_frame(data, kind) {
            Ok(hello) => {
                assert_eq!(bare.as_ref(), Ok(&hello), "first_frame and decode disagree");
                assert_within_bounds(&profile::decode(data).expect("canonical"), kind.max_items());
            }
            Err(refusal) => assert_eq!(refusal, HelloRefusal::NotHello),
        }
    }
}

/// The bare `HelloReply` decoder, under the control item bound.
fn hello_reply(data: &[u8]) {
    if let Ok(reply) =
        wire::decode_with_max_items::<HelloReply>(data, SocketKind::Control.max_items())
    {
        assert_round_trip(&reply, data);
    }
}

/// Decodes `value`, accepted from `data`, as `T`; an accepted `T` round-trips.
fn decode_as<T: Wire + core::fmt::Debug>(value: &CBOR, data: &[u8]) {
    if let Ok(decoded) = T::from_cbor(value) {
        assert_round_trip(&decoded, data);
    }
}

/// Declares the types of the `closed_types` target and its check from one list, so that the
/// names it reports are the types it decodes.
macro_rules! closed_types {
    ($($name:ident $(<$parameter:ty>)?),+ $(,)?) => {
        /// The types the `closed_types` target decodes, by name.
        pub const CLOSED_TYPES: &[&str] = &[$(stringify!($name)),+];

        /// The closed-type decoders on one profile-accepted value, under the control item bound.
        fn closed_types(data: &[u8]) {
            let Ok(value) = profile::decode_with_max_items(data, SocketKind::Control.max_items()) else {
                return;
            };
            $(decode_as::<$name $(<$parameter>)?>(&value, data);)+
        }
    };
}

closed_types!(
    Source,
    Taint,
    Tier,
    Principal,
    DataType,
    ExceptionClass,
    RetryClass,
    OperatorSetting,
    ClientError,
    ErrorCode,
    MessageKey,
    ModuleName,
    Id,
    UtcMillis,
    HelloRefusal,
    bool,
    u16,
    u64,
    i64,
    String,
    Vec<Source>,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repetition_builds_an_array_of_its_unit_after_its_prefix() {
        let mut input = [3u32.to_be_bytes(), 2u32.to_be_bytes()].concat();
        input.extend_from_slice(&[0xa1, 0x00, 0x81, 0x00]);
        // The prefix {0: ...}, then an array of three [0].
        let message = expand(&input, 64).expect("expanded");
        assert_eq!(
            message,
            [0xa1, 0x00, 0x83, 0x81, 0x00, 0x81, 0x00, 0x81, 0x00]
        );
        assert!(profile::decode(&message).is_ok());
        assert_eq!(expand(&input[..7], 64), None, "shorter than its header");
        let long_prefix = [0u32.to_be_bytes(), 9u32.to_be_bytes()].concat();
        assert_eq!(expand(&long_prefix, 64), None, "shorter than its prefix");
    }

    #[test]
    fn a_repetition_never_passes_the_maximum() {
        let input = [u32::MAX.to_be_bytes(), 0u32.to_be_bytes(), [0x00; 4]].concat();
        for max in [9usize, 10, 1 << 20, 16 << 20] {
            let message = expand(&input, max).expect("expanded");
            assert!(
                message.len() <= max,
                "{} bytes for a maximum of {max}",
                message.len()
            );
        }
        let prefix_too_long =
            [1u32.to_be_bytes(), 8u32.to_be_bytes(), [0x00; 4], [0x00; 4]].concat();
        assert_eq!(expand(&prefix_too_long, 16), None);
    }

    #[test]
    fn array_heads_are_in_the_shortest_form() {
        for len in [0u32, 23, 24, 255, 256, 65_535, 65_536] {
            let mut message = array_head(u64::from(len));
            message.resize(message.len() + len as usize, 0x00);
            assert!(
                profile::decode(&message).is_ok(),
                "an array of {len} is canonical"
            );
        }
        assert_eq!(
            array_head(u64::from(u32::MAX)),
            [0x9a, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn the_item_bound_is_passed_first_only_before_any_other_refusal() {
        let zeros = |n: u8| [&[0x80 | n][..], &vec![0x00; n as usize]].concat();
        // [0, 0, 0]: four items.
        assert!(passes_item_bound_first(&zeros(3), 3));
        assert!(!passes_item_bound_first(&zeros(3), 4));
        // A float, a tag or a truncation before the fourth item is refused first.
        assert!(!passes_item_bound_first(
            &[0x83, 0xf9, 0x3c, 0x00, 0x00, 0x00],
            3
        ));
        assert!(!passes_item_bound_first(&[0x83, 0xc0, 0x00, 0x00, 0x00], 3));
        assert!(!passes_item_bound_first(&[0x83, 0x00], 3));
        // After the fourth item, what follows does not matter: the bound comes first.
        assert!(passes_item_bound_first(&[0x84, 0x00, 0x00, 0x00, 0xf9], 3));
        // A map entry counts its key and its value.
        assert!(passes_item_bound_first(&[0xa1, 0x00, 0x00], 2));
        let mut deep = vec![0x81; MAX_DEPTH + 1];
        deep.push(0x00);
        assert!(!passes_item_bound_first(&deep, usize::MAX));
        for (bytes, max) in [(zeros(3), 3usize), (vec![0xa1, 0x00, 0x00], 2)] {
            assert_eq!(
                profile::decode_with_max_items(&bytes, max),
                Err(Rejection::TooManyItems(max))
            );
        }
    }

    #[test]
    fn every_seed_shape_is_read_back_by_its_target() {
        let message = [0x82, 0x00, 0x01];
        assert_eq!(Input::Message.shape(&message), message);
        assert_eq!(
            Input::Frames.shape(&message),
            [0, 0, 0, 3, 0x82, 0x00, 0x01]
        );
        let repeated = Input::Repeated.shape(&message);
        assert_eq!(
            expand(&repeated, 64).expect("expanded"),
            [0x81, 0x82, 0x00, 0x01]
        );
    }

    #[test]
    fn memory_limits_grow_with_the_frame_maximum_and_the_item_bound() {
        let control = target("frame_control");
        let data = target("frame_data");
        assert!(data.decode_budget() > control.decode_budget());
        for target in TARGETS {
            let kind = target.kind;
            assert!(target.decode_budget() >= MESSAGE_COPIES * u64::from(kind.max_message_len()));
            assert!(target.malloc_limit_mib() * MIB > 2 * u64::from(kind.max_message_len()));
            assert!(target.rss_limit_mib() * MIB > RUNTIME_MIB * MIB + target.decode_budget());
            assert_eq!(
                target.max_len(),
                u64::from(kind.max_message_len()) + LENGTH_PREFIX_LEN as u64
            );
        }
    }
}
