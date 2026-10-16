//! The first TLS record a caller sends in a tunnel: its ClientHello must name the CONNECT host in
//! SNI and carry no Encrypted Client Hello extension.
//!
//! This narrows domain fronting by SNI. It cannot see the HTTP Host header, which is encrypted,
//! so a front end that routes on the Host header can still be fronted (story 1.12, finding 2).
//! The parser reads only what it needs and refuses anything it does not understand.

/// TLS record header length.
pub const RECORD_HEADER: usize = 5;
/// Largest TLS plaintext record body (RFC 8446 section 5.1).
pub const MAX_RECORD_BODY: usize = 16_384;

const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXTENSION_SERVER_NAME: u16 = 0;
const EXTENSION_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const NAME_TYPE_HOST: u8 = 0;

/// How many bytes the first record occupies, once its header is known. `Err` when the bytes do
/// not start a TLS handshake record of a valid size.
///
/// # Errors
/// Returns a fixed reason when the header is not a handshake record of a valid length.
pub fn record_length(header: &[u8; RECORD_HEADER]) -> Result<usize, &'static str> {
    if header[0] != CONTENT_HANDSHAKE || header[1] != 3 {
        return Err("first bytes in the tunnel are not a TLS handshake record");
    }
    let body = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if body == 0 || body > MAX_RECORD_BODY {
        return Err("TLS record length out of range");
    }
    Ok(RECORD_HEADER + body)
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        if self.bytes.len() < n {
            return Err("truncated ClientHello");
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn vector8(&mut self) -> Result<&'a [u8], &'static str> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }

    fn vector16(&mut self) -> Result<&'a [u8], &'static str> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
}

/// Checks a complete first record (header included) against the CONNECT host.
///
/// # Errors
/// Returns a fixed reason when the record is not a single-record ClientHello, has no SNI host
/// name, names another host, or offers Encrypted Client Hello.
pub fn check_client_hello(record: &[u8], host: &str) -> Result<(), &'static str> {
    let mut reader = Reader {
        bytes: record.get(RECORD_HEADER..).ok_or("truncated record")?,
    };
    if reader.u8()? != HANDSHAKE_CLIENT_HELLO {
        return Err("first handshake message is not a ClientHello");
    }
    let length = reader.take(3)?;
    let length =
        usize::from(length[0]) << 16 | usize::from(length[1]) << 8 | usize::from(length[2]);
    let mut hello = Reader {
        bytes: reader
            .take(length)
            .map_err(|_| "ClientHello spans several records")?,
    };
    hello.take(2 + 32)?;
    hello.vector8()?;
    hello.vector16()?;
    hello.vector8()?;
    let mut extensions = Reader {
        bytes: hello.vector16()?,
    };
    let mut server_name = None;
    while !extensions.bytes.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vector16()?;
        match kind {
            EXTENSION_ENCRYPTED_CLIENT_HELLO => return Err("Encrypted Client Hello offered"),
            EXTENSION_SERVER_NAME => {
                if server_name.is_some() {
                    return Err("duplicate server_name extension");
                }
                let mut list = Reader {
                    bytes: Reader { bytes: data }.vector16()?,
                };
                if list.u8()? != NAME_TYPE_HOST {
                    return Err("server_name is not a host name");
                }
                let name = list.vector16()?;
                if !list.bytes.is_empty() {
                    return Err("several server names");
                }
                server_name = Some(name);
            }
            _ => {}
        }
    }
    let name = server_name.ok_or("no SNI host name")?;
    if name.eq_ignore_ascii_case(host.as_bytes()) {
        Ok(())
    } else {
        Err("SNI does not match the CONNECT host")
    }
}

/// Test support: builds ClientHello records. Compiled for tests and the test-network build only.
#[cfg(any(test, feature = "test-network"))]
pub mod test_support {
    use super::{
        CONTENT_HANDSHAKE, EXTENSION_ENCRYPTED_CLIENT_HELLO, EXTENSION_SERVER_NAME,
        HANDSHAKE_CLIENT_HELLO, NAME_TYPE_HOST,
    };

    fn vector16(body: &[u8]) -> Vec<u8> {
        let mut out = u16::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    /// A minimal TLS 1.3 style ClientHello record.
    pub fn client_hello(sni: Option<&str>, ech: bool) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(name) = sni {
            let mut entry = vec![NAME_TYPE_HOST];
            entry.extend(vector16(name.as_bytes()));
            extensions.extend(EXTENSION_SERVER_NAME.to_be_bytes());
            extensions.extend(vector16(&vector16(&entry)));
        }
        if ech {
            extensions.extend(EXTENSION_ENCRYPTED_CLIENT_HELLO.to_be_bytes());
            extensions.extend(vector16(&[0, 1, 2, 3]));
        }
        extensions.extend(0x002b_u16.to_be_bytes());
        extensions.extend(vector16(&[2, 3, 4]));
        let mut hello = vec![3, 3];
        hello.extend([7_u8; 32]);
        hello.push(0);
        hello.extend(vector16(&[0x13, 0x01]));
        hello.extend([1, 0]);
        hello.extend(vector16(&extensions));
        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        handshake.extend(&u32::try_from(hello.len()).unwrap().to_be_bytes()[1..]);
        handshake.extend(hello);
        let mut record = vec![CONTENT_HANDSHAKE, 3, 1];
        record.extend(vector16(&handshake));
        record
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::client_hello;
    use super::*;

    #[test]
    fn matching_sni_passes_case_insensitively() {
        assert_eq!(
            check_client_hello(&client_hello(Some("allowed.test"), false), "allowed.test"),
            Ok(())
        );
        assert_eq!(
            check_client_hello(&client_hello(Some("Allowed.TEST"), false), "allowed.test"),
            Ok(())
        );
    }

    #[test]
    fn fronting_ech_and_malformed_hellos_are_refused() {
        let cases = [
            (
                client_hello(Some("forbidden.test"), false),
                "does not match",
            ),
            (
                client_hello(Some("allowed.test"), true),
                "Encrypted Client Hello",
            ),
            (client_hello(None, false), "no SNI"),
            (
                client_hello(Some("allowed.test.forbidden.test"), false),
                "does not match",
            ),
        ];
        for (record, reason) in cases {
            let error = check_client_hello(&record, "allowed.test").unwrap_err();
            assert!(error.contains(reason), "{error}");
        }
        let full = client_hello(Some("allowed.test"), false);
        assert!(check_client_hello(&full[..full.len() - 3], "allowed.test").is_err());
        let mut split = full.clone();
        split[4] -= 10;
        assert!(check_client_hello(&split[..split.len() - 10], "allowed.test").is_err());
    }

    #[test]
    fn record_headers_are_checked() {
        let full = client_hello(Some("allowed.test"), false);
        let header: [u8; RECORD_HEADER] = full[..RECORD_HEADER].try_into().unwrap();
        assert_eq!(record_length(&header), Ok(full.len()));
        assert!(record_length(b"GET /").is_err());
        assert!(record_length(&[22, 3, 1, 0x40, 0x01]).is_err());
        assert!(record_length(&[22, 3, 1, 0, 0]).is_err());
    }
}
