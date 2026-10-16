//! Reads the raw ClientHello off a TCP stream before rustls sees it, to record what the client
//! offered. rustls exposes the offered `supported_groups` but not which groups carry a key share,
//! and the key shares decide whether the server answers directly or with a HelloRetryRequest.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

const RECORD_HEADER_LEN: usize = 5;
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const EXTENSION_SUPPORTED_GROUPS: u16 = 10;
const EXTENSION_KEY_SHARE: u16 = 51;
/// A ClientHello with a hybrid key share is about 1.5 KiB; anything far beyond is not a client
/// this spike tests.
const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;

/// What a client offered in its first ClientHello.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Offer {
    /// `supported_groups`, in the client's order of preference.
    pub groups: Vec<u16>,
    /// Groups for which the client sent a key share, in the client's order.
    pub key_shares: Vec<u16>,
}

/// A ClientHello read off the wire: the parsed offer plus every byte consumed, which the caller
/// replays to rustls.
#[derive(Debug)]
pub struct Captured {
    pub offer: Offer,
    pub raw: Vec<u8>,
}

/// Reads TLS records from `stream` until one complete ClientHello handshake message is buffered.
pub async fn read(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Captured> {
    let mut raw = Vec::new();
    let mut handshake = Vec::new();
    loop {
        let mut header = [0u8; RECORD_HEADER_LEN];
        stream.read_exact(&mut header).await?;
        if header[0] != CONTENT_TYPE_HANDSHAKE {
            return Err(invalid("first record is not a handshake record"));
        }
        let record_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if raw.len() + RECORD_HEADER_LEN + record_len > MAX_CLIENT_HELLO_BYTES {
            return Err(invalid("ClientHello larger than the spike accepts"));
        }
        let mut fragment = vec![0u8; record_len];
        stream.read_exact(&mut fragment).await?;
        raw.extend_from_slice(&header);
        raw.extend_from_slice(&fragment);
        handshake.extend_from_slice(&fragment);

        if handshake.len() >= 4 {
            if handshake[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
                return Err(invalid("first handshake message is not a ClientHello"));
            }
            let body_len = u24(&handshake[1..4]);
            if handshake.len() >= 4 + body_len {
                let offer = parse_body(&handshake[4..4 + body_len])?;
                return Ok(Captured { offer, raw });
            }
        }
    }
}

/// Parses a ClientHello body (after the 4-byte handshake header) for the two extensions this
/// spike records.
pub fn parse_body(body: &[u8]) -> io::Result<Offer> {
    let mut reader = Reader(body);
    reader.skip(2 + 32)?; // legacy_version, random
    let session_id_len = usize::from(reader.u8()?);
    reader.skip(session_id_len)?;
    let suites_len = usize::from(reader.u16()?);
    reader.skip(suites_len)?;
    let compression_len = usize::from(reader.u8()?);
    reader.skip(compression_len)?;

    let mut offer = Offer::default();
    if reader.0.is_empty() {
        return Ok(offer);
    }
    let extensions_len = usize::from(reader.u16()?);
    let mut extensions = Reader(reader.take(extensions_len)?);
    while !extensions.0.is_empty() {
        let extension_type = extensions.u16()?;
        let data_len = usize::from(extensions.u16()?);
        let mut data = Reader(extensions.take(data_len)?);
        match extension_type {
            EXTENSION_SUPPORTED_GROUPS => {
                let list_len = usize::from(data.u16()?);
                let mut list = Reader(data.take(list_len)?);
                while !list.0.is_empty() {
                    offer.groups.push(list.u16()?);
                }
            }
            EXTENSION_KEY_SHARE => {
                let list_len = usize::from(data.u16()?);
                let mut list = Reader(data.take(list_len)?);
                while !list.0.is_empty() {
                    offer.key_shares.push(list.u16()?);
                    let share_len = usize::from(list.u16()?);
                    list.skip(share_len)?;
                }
            }
            _ => {}
        }
    }
    Ok(offer)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        if self.0.len() < len {
            return Err(invalid("truncated ClientHello"));
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }

    fn skip(&mut self, len: usize) -> io::Result<()> {
        self.take(len).map(|_| ())
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

fn u24(bytes: &[u8]) -> usize {
    (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ClientHello body: empty session id, one suite, null compression, then the
    /// given extensions block.
    fn body_with_extensions(extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend_from_slice(extensions);
        body
    }

    #[test]
    fn reads_groups_and_key_shares_in_client_order() {
        let extensions = [
            0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x11, 0xec, 0x00, 0x1d, // supported_groups
            0x00, 0x33, 0x00, 0x0f, 0x00, 0x0d, // key_share, two entries:
            0x11, 0xec, 0x00, 0x03, 0x01, 0x02, 0x03, // X25519MLKEM768, 3-byte share
            0x00, 0x1d, 0x00, 0x02, 0xaa, 0xbb, // X25519, 2-byte share
        ];
        let offer = parse_body(&body_with_extensions(&extensions)).unwrap();
        assert_eq!(offer.groups, vec![0x11ec, 0x001d]);
        assert_eq!(offer.key_shares, vec![0x11ec, 0x001d]);
    }

    #[test]
    fn rejects_a_truncated_extension() {
        let extensions = [0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x11];
        assert!(parse_body(&body_with_extensions(&extensions)).is_err());
    }

    #[tokio::test]
    async fn reassembles_a_client_hello_split_across_two_records() {
        let extensions = [0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d];
        let body = body_with_extensions(&extensions);
        let mut message = vec![HANDSHAKE_TYPE_CLIENT_HELLO, 0];
        message.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        message.extend_from_slice(&body);
        let (first, second) = message.split_at(10);
        let mut wire = Vec::new();
        for fragment in [first, second] {
            wire.extend_from_slice(&[CONTENT_TYPE_HANDSHAKE, 0x03, 0x01]);
            wire.extend_from_slice(&u16::try_from(fragment.len()).unwrap().to_be_bytes());
            wire.extend_from_slice(fragment);
        }
        let captured = read(&mut wire.as_slice()).await.unwrap();
        assert_eq!(captured.offer.groups, vec![0x001d]);
        assert_eq!(captured.raw, wire);
    }

    #[tokio::test]
    async fn rejects_a_client_hello_beyond_the_size_cap() {
        // A ClientHello announcing more than the cap, sent as full-size records.
        let mut wire = Vec::new();
        let mut message = vec![HANDSHAKE_TYPE_CLIENT_HELLO, 0x02, 0x00, 0x00];
        message.resize(MAX_CLIENT_HELLO_BYTES + 1024, 0);
        for fragment in message.chunks(16 * 1024) {
            wire.extend_from_slice(&[CONTENT_TYPE_HANDSHAKE, 0x03, 0x01]);
            wire.extend_from_slice(&u16::try_from(fragment.len()).unwrap().to_be_bytes());
            wire.extend_from_slice(fragment);
        }
        let error = read(&mut wire.as_slice()).await.unwrap_err();
        assert!(error.to_string().contains("larger than"), "{error}");
    }

    #[tokio::test]
    async fn rejects_a_first_handshake_message_that_is_not_a_client_hello() {
        let wire = [
            CONTENT_TYPE_HANDSHAKE,
            0x03,
            0x03,
            0x00,
            0x04,
            0x02,
            0x00,
            0x00,
            0x00,
        ];
        let error = read(&mut wire.as_slice()).await.unwrap_err();
        assert!(error.to_string().contains("not a ClientHello"), "{error}");
    }

    #[tokio::test]
    async fn rejects_a_non_handshake_first_record() {
        let wire = [0x17, 0x03, 0x03, 0x00, 0x01, 0x00];
        assert!(read(&mut wire.as_slice()).await.is_err());
    }
}
