//! Length-prefixed frames on the internal sockets (spine AD-12, D19).
//!
//! A frame is a 4-byte big-endian length followed by one CBOR message. Each socket kind declares
//! its maximum length and its maximum number of data items. A length above the maximum is refused
//! from the four length bytes alone, before any byte of the message is read; the message buffer
//! grows only as bytes arrive; and the item count is checked by the head walk before `dcbor`
//! builds anything, since a decoded item costs far more memory than its encoded byte.

use core::fmt;
use std::io::{self, Read, Write};

use crate::wire::{self, DecodeError, Wire};

/// Bytes of the length prefix.
pub const LENGTH_PREFIX_LEN: usize = 4;

/// The first part of a message the buffer is sized for, before any byte of it arrives.
const FIRST_READ: usize = 64 * 1024;

/// The kind of an internal socket, which sets its largest frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketKind {
    /// A control socket: requests, responses and the handshake.
    Control,
    /// A data socket, for larger payloads.
    Data,
}

impl SocketKind {
    /// Largest message a frame of this socket kind may carry, in bytes: 1 MiB for control, 16 MiB
    /// for data (spine AD-12, `[ASSUMPTION]`).
    pub const fn max_message_len(self) -> u32 {
        match self {
            Self::Control => 1 << 20,
            Self::Data => 16 << 20,
        }
    }

    /// Most data items a message of this socket kind may hold, counted as
    /// [`profile::decode_with_max_items`](crate::profile::decode_with_max_items) counts them.
    /// `[ASSUMPTION]` of Story 2.5, no document fixes them: 65 536 for control and 262 144 for
    /// data, which keep the decoding of a worst-case frame within the peak memory Story 2.5
    /// measured (its Result).
    pub const fn max_items(self) -> usize {
        match self {
            Self::Control => 1 << 16,
            Self::Data => 1 << 18,
        }
    }
}

/// Why a frame was not read or written.
#[derive(Debug)]
pub enum FrameError {
    /// The declared or given length is above the socket kind's maximum.
    TooLarge {
        /// The length declared by the prefix, or of the message to send.
        len: u64,
        /// The socket kind's maximum.
        max: u32,
    },
    /// The stream failed or ended inside a frame.
    Io(io::Error),
    /// The message is not a valid message of the expected closed type.
    Message(DecodeError),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { len, max } => {
                write!(f, "frame of {len} bytes exceeds the maximum of {max}")
            }
            Self::Io(error) => write!(f, "frame I/O failed: {error}"),
            Self::Message(error) => write!(f, "invalid message: {error}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<DecodeError> for FrameError {
    fn from(error: DecodeError) -> Self {
        Self::Message(error)
    }
}

/// Reads one frame and returns its message bytes, still undecoded. The length is checked against
/// the socket kind's maximum before any byte of the message is read. The buffer is never reserved
/// from the declared length: it holds 64 KiB at first, then doubles only once the bytes it holds
/// have arrived, and never grows past the declared length, so a frame at the maximum takes one
/// buffer of exactly its size.
pub fn read_frame(reader: &mut impl Read, kind: SocketKind) -> Result<Vec<u8>, FrameError> {
    let mut prefix = [0u8; LENGTH_PREFIX_LEN];
    reader.read_exact(&mut prefix)?;
    let len = u32::from_be_bytes(prefix);
    let max = kind.max_message_len();
    if len > max {
        return Err(FrameError::TooLarge {
            len: u64::from(len),
            max,
        });
    }
    let len = len as usize;
    let mut message = Vec::new();
    while message.len() < len {
        let received = message.len();
        let next = received.max(FIRST_READ).min(len - received);
        message.reserve_exact(next);
        message.resize(received + next, 0);
        reader
            .read_exact(&mut message[received..])
            .map_err(|error| match error.kind() {
                io::ErrorKind::UnexpectedEof => FrameError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the stream ended inside a frame",
                )),
                _ => FrameError::Io(error),
            })?;
    }
    Ok(message)
}

/// Reads one frame and decodes its message as `T`, through the canonical profile (head walk
/// first, so the nesting and item bounds hold before any decoding) and the closed-type check.
pub fn read_message<T: Wire>(reader: &mut impl Read, kind: SocketKind) -> Result<T, FrameError> {
    Ok(wire::decode_with_max_items(
        &read_frame(reader, kind)?,
        kind.max_items(),
    )?)
}

/// Writes one message as a frame, refusing a message above the socket kind's maximum.
pub fn write_frame(
    writer: &mut impl Write,
    kind: SocketKind,
    message: &[u8],
) -> Result<(), FrameError> {
    let max = kind.max_message_len();
    let len = u32::try_from(message.len())
        .ok()
        .filter(|len| *len <= max)
        .ok_or(FrameError::TooLarge {
            len: message.len() as u64,
            max,
        })?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(message)?;
    Ok(())
}

/// Encodes a message under the canonical profile and writes it as a frame.
pub fn write_message<T: Wire>(
    writer: &mut impl Write,
    kind: SocketKind,
    message: &T,
) -> Result<(), FrameError> {
    let bytes = wire::encode(message).map_err(DecodeError::Profile)?;
    write_frame(writer, kind, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{MAX_DEPTH, Rejection};

    /// A reader that counts the bytes taken from it, to show what was read before a refusal.
    struct Counting<'a> {
        bytes: &'a [u8],
        taken: usize,
    }

    impl Read for Counting<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.bytes.len() - self.taken);
            buf[..n].copy_from_slice(&self.bytes[self.taken..self.taken + n]);
            self.taken += n;
            Ok(n)
        }
    }

    fn framed(len: u32, body: &[u8]) -> Vec<u8> {
        let mut bytes = len.to_be_bytes().to_vec();
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn maxima_are_those_of_ad_12() {
        assert_eq!(SocketKind::Control.max_message_len(), 1024 * 1024);
        assert_eq!(SocketKind::Data.max_message_len(), 16 * 1024 * 1024);
    }

    #[test]
    fn a_length_above_the_maximum_is_refused_from_the_prefix_alone() {
        for kind in [SocketKind::Control, SocketKind::Data] {
            let max = kind.max_message_len();
            let bytes = framed(max + 1, &[0x00; 16]);
            let mut reader = Counting {
                bytes: &bytes,
                taken: 0,
            };
            assert!(matches!(
                read_frame(&mut reader, kind),
                Err(FrameError::TooLarge { len, max: m }) if len == u64::from(max) + 1 && m == max
            ));
            assert_eq!(reader.taken, LENGTH_PREFIX_LEN, "no message byte was read");
        }
    }

    /// A reader that hands out one byte per call, as a slow socket may.
    struct OneByteAtATime<'a>(&'a [u8]);

    impl Read for OneByteAtATime<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match (self.0.split_first(), buf.first_mut()) {
                (Some((byte, rest)), Some(slot)) => {
                    *slot = *byte;
                    self.0 = rest;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    /// A message of one byte string filling `len` bytes: a 5-byte head and its content.
    fn byte_string_message(len: u32) -> Vec<u8> {
        let mut message = vec![0x5a];
        message.extend_from_slice(&(len - 5).to_be_bytes());
        message.resize(len as usize, 0xab);
        message
    }

    /// An array of `elements` zeros, at least 256 of them, which holds `elements + 1` data items.
    fn zeros(elements: u32) -> Vec<u8> {
        let mut message = match u16::try_from(elements) {
            Ok(short) => [&[0x99][..], &short.to_be_bytes()].concat(),
            Err(_) => [&[0x9a][..], &elements.to_be_bytes()].concat(),
        };
        message.resize(message.len() + elements as usize, 0x00);
        message
    }

    #[test]
    fn a_frame_at_the_maximum_is_read() {
        for kind in [SocketKind::Control, SocketKind::Data] {
            let max = kind.max_message_len();
            let bytes = framed(max, &byte_string_message(max));
            let read = read_frame(&mut bytes.as_slice(), kind).expect("at the maximum");
            assert_eq!(read.len(), max as usize);
            assert!(crate::profile::decode(&read).is_ok());
        }
    }

    /// Story 2.7: the fuzz job's limit on a single allocation found that reading a frame at the
    /// maximum reserved twice its size (`read_to_end` doubles its buffer to probe for the end), a
    /// 32 MiB allocation for a 16 MiB data frame. The buffer now ends at the declared length.
    #[test]
    fn a_frame_is_read_into_a_buffer_no_larger_than_its_length() {
        for kind in [SocketKind::Control, SocketKind::Data] {
            let max = kind.max_message_len();
            for len in [
                0,
                1,
                FIRST_READ as u32,
                FIRST_READ as u32 + 1,
                max / 2 + 1,
                max,
            ] {
                let bytes = framed(len, &vec![0xab; len as usize]);
                let read = read_frame(&mut bytes.as_slice(), kind).expect("within the maximum");
                assert_eq!(read.len(), len as usize);
                assert_eq!(
                    read.capacity(),
                    len as usize,
                    "{kind:?} frame of {len} bytes"
                );
                let slow = read_frame(&mut OneByteAtATime(&bytes), kind).expect("read slowly");
                assert_eq!(slow, read);
            }
        }
    }

    #[test]
    fn items_at_the_bound_are_decoded_and_one_more_is_refused_before_decoding() {
        for kind in [SocketKind::Control, SocketKind::Data] {
            let max_items = u32::try_from(kind.max_items()).expect("bound fits a u32");
            let at = zeros(max_items - 1);
            let bytes = framed(u32::try_from(at.len()).expect("small"), &at);
            let read: Vec<u64> = read_message(&mut bytes.as_slice(), kind).expect("at the bound");
            assert_eq!(read.len(), kind.max_items() - 1);

            let over = zeros(max_items);
            let bytes = framed(u32::try_from(over.len()).expect("small"), &over);
            assert!(matches!(
                read_message::<Vec<u64>>(&mut bytes.as_slice(), kind),
                Err(FrameError::Message(DecodeError::Profile(Rejection::TooManyItems(n))))
                    if n == kind.max_items()
            ));
        }
    }

    #[test]
    fn a_zero_length_frame_holds_no_message() {
        let bytes = framed(0, &[]);
        assert_eq!(
            read_frame(&mut bytes.as_slice(), SocketKind::Control).expect("empty frame"),
            Vec::<u8>::new()
        );
        assert!(matches!(
            read_message::<u64>(&mut bytes.as_slice(), SocketKind::Control),
            Err(FrameError::Message(DecodeError::Profile(
                Rejection::Malformed(_)
            )))
        ));
    }

    #[test]
    fn a_stream_that_stops_inside_a_frame_is_an_io_error() {
        // A prefix declaring the largest data frame, then ten bytes and the end of the stream.
        let bytes = framed(SocketKind::Data.max_message_len(), &[0x00; 10]);
        assert!(matches!(
            read_frame(&mut bytes.as_slice(), SocketKind::Data),
            Err(FrameError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn a_reader_giving_one_byte_at_a_time_reads_the_same_frames() {
        let mut out = Vec::new();
        write_message(&mut out, SocketKind::Control, &vec![1u64, 2, 3]).expect("written");
        let read: Vec<u64> =
            read_message(&mut OneByteAtATime(&out), SocketKind::Control).expect("read");
        assert_eq!(read, [1, 2, 3]);
        let bytes = framed(SocketKind::Control.max_message_len() + 1, &[0x00; 4]);
        assert!(matches!(
            read_frame(&mut OneByteAtATime(&bytes), SocketKind::Control),
            Err(FrameError::TooLarge { .. })
        ));
    }

    #[test]
    fn writing_refuses_a_message_above_the_maximum() {
        let message = vec![0u8; SocketKind::Control.max_message_len() as usize + 1];
        let mut out = Vec::new();
        assert!(matches!(
            write_frame(&mut out, SocketKind::Control, &message),
            Err(FrameError::TooLarge { .. })
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn a_truncated_frame_is_an_io_error() {
        let bytes = framed(8, &[0x00; 3]);
        assert!(matches!(
            read_frame(&mut bytes.as_slice(), SocketKind::Control),
            Err(FrameError::Io(_))
        ));
        assert!(matches!(
            read_frame(&mut [0u8, 0].as_slice(), SocketKind::Control),
            Err(FrameError::Io(_))
        ));
    }

    /// AC1: a control frame full of nested array heads is refused by the head walk, on a small
    /// stack, before `dcbor` decodes anything.
    #[test]
    fn a_frame_nested_deeper_than_the_profile_is_refused_before_decoding() {
        let refused = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let max = SocketKind::Control.max_message_len();
                let bytes = framed(max, &vec![0x81; max as usize]);
                read_message::<Vec<u64>>(&mut bytes.as_slice(), SocketKind::Control)
            })
            .expect("thread")
            .join()
            .expect("no stack overflow");
        assert!(matches!(
            refused,
            Err(FrameError::Message(DecodeError::Profile(
                Rejection::TooDeep
            )))
        ));
        let mut within = vec![0x81; MAX_DEPTH - 1];
        within.push(0x80);
        assert!(crate::profile::decode(&within).is_ok());
    }

    #[test]
    fn messages_round_trip_through_frames() {
        let mut out = Vec::new();
        write_message(&mut out, SocketKind::Data, &vec![1u64, 2, 3]).expect("written");
        assert_eq!(&out[..LENGTH_PREFIX_LEN], &4u32.to_be_bytes());
        let read: Vec<u64> = read_message(&mut out.as_slice(), SocketKind::Data).expect("read");
        assert_eq!(read, [1, 2, 3]);
    }
}
