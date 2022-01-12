#[cfg(feature = "alloc")]
use crate::Vec;
use crate::{decoded_len, Error};

/// Decode a mixed Base16 (hex) string into the provided destination buffer.
pub fn decode(src: impl AsRef<[u8]>, dst: &mut [u8]) -> Result<&[u8], Error> {
    let src = src.as_ref();
    let dst = dst
        .get_mut(..decoded_len(src)?)
        .ok_or(Error::InvalidLength)?;

    let mut err: u16 = 0;
    for (src, dst) in src.chunks_exact(2).zip(dst.iter_mut()) {
        let byte = (decode_nibble(src[0]) << 4) | decode_nibble(src[1]);
        err |= byte >> 8;
        *dst = byte as u8;
    }

    match err {
        0 => Ok(dst),
        _ => Err(Error::InvalidEncoding),
    }
}

/// Decode a mixed Base16 (hex) string into a byte vector.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn decode_vec(input: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
    let mut output = vec![0u8; decoded_len(input.as_ref())?];
    decode(input, &mut output)?;
    Ok(output)
}

/// Decode a single nibble of lower hex
#[inline(always)]
fn decode_nibble(src: u8) -> u16 {
    // 0-9  0x30-0x39
    // A-F  0x41-0x46 or a-f  0x61-0x66
    let byte = src as i16;
    let mut ret: i16 = -1;

    // 0-9  0x30-0x39
    // if (byte > 0x2f && byte < 0x3a) ret += byte - 0x30 + 1; // -47
    ret += (((0x2fi16 - byte) & (byte - 0x3a)) >> 8) & (byte - 47);
    // A-F  0x41-0x46
    // if (byte > 0x40 && byte < 0x47) ret += byte - 0x41 + 10 + 1; // -54
    ret += (((0x40i16 - byte) & (byte - 0x47)) >> 8) & (byte - 54);
    // a-f  0x61-0x66
    // if (byte > 0x60 && byte < 0x67) ret += byte - 0x61 + 10 + 1; // -86
    ret += (((0x60i16 - byte) & (byte - 0x67)) >> 8) & (byte - 86);

    ret as u16
}
