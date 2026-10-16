//! A minimal PNG encoder for the web app icons, so the spike needs no image crate.
//!
//! Pixels are written uncompressed in zlib stored blocks; browsers only need a valid PNG of the
//! declared size for the installability check.

const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
const STORED_BLOCK_MAX: usize = 65_535;

/// Encodes a square RGBA icon of `size` pixels: a filled background with a centred square.
pub fn icon(size: u32) -> Vec<u8> {
    let side = size as usize;
    let mut raw = Vec::with_capacity(side * (side * 4 + 1));
    for y in 0..side {
        raw.push(0); // filter type "none" for this scanline
        for x in 0..side {
            let inner =
                (side / 4..side * 3 / 4).contains(&x) && (side / 4..side * 3 / 4).contains(&y);
            let pixel: [u8; 4] = if inner {
                [0xf2, 0xf2, 0xea, 0xff]
            } else {
                [0x2e, 0x5e, 0x4e, 0xff]
            };
            raw.extend_from_slice(&pixel);
        }
    }

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&size.to_be_bytes());
    ihdr.extend_from_slice(&size.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit depth, RGBA, deflate, adaptive, no interlace

    let mut png = SIGNATURE.to_vec();
    push_chunk(&mut png, b"IHDR", &ihdr);
    push_chunk(&mut png, b"IDAT", &zlib_stored(&raw));
    push_chunk(&mut png, b"IEND", &[]);
    png
}

fn push_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    let length = u32::try_from(data.len()).expect("PNG chunk larger than 4 GiB");
    out.extend_from_slice(&length.to_be_bytes());
    let start = out.len();
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let crc = crc32(&out[start..]);
    out.extend_from_slice(&crc.to_be_bytes());
}

fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let mut blocks = data.chunks(STORED_BLOCK_MAX).peekable();
    if blocks.peek().is_none() {
        out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    }
    while let Some(block) = blocks.next() {
        out.push(u8::from(blocks.peek().is_none()));
        let len = u16::try_from(block.len()).expect("stored block bounded by STORED_BLOCK_MAX");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(block);
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1_u32, 0_u32);
    for &byte in data {
        a = (a + u32::from(byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums_match_reference_values() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
        assert_eq!(crc32(b"IEND"), 0xae42_6082);
    }

    #[test]
    fn icon_declares_its_size_and_ends_with_iend() {
        let png = icon(192);
        assert_eq!(&png[..8], &SIGNATURE);
        assert_eq!(&png[12..16], b"IHDR");
        assert_eq!(u32::from_be_bytes(png[16..20].try_into().unwrap()), 192);
        assert_eq!(u32::from_be_bytes(png[20..24].try_into().unwrap()), 192);
        assert_eq!(&png[png.len() - 8..png.len() - 4], b"IEND");
    }

    #[test]
    fn stored_blocks_cover_the_whole_image() {
        let side = 512_usize;
        let raw_len = side * (side * 4 + 1);
        let zlib = zlib_stored(&vec![0; raw_len]);
        let blocks = raw_len.div_ceil(STORED_BLOCK_MAX);
        assert_eq!(zlib.len(), 2 + blocks * 5 + raw_len + 4);
    }
}
