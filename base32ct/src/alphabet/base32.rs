//! RFC4648 Base32 (lower case).

use super::Alphabet;

/// RFC4648 lower case Base32 encoding with `=` padding.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Base32;

impl Alphabet for Base32 {
    const PADDED: bool = true;

    fn decode_5bits(byte: u8) -> i16 {
        decode_5bits_lower(byte)
    }

    fn encode_5bits(src: u8) -> u8 {
        encode_5bits_lower(src)
    }
}

/// RFC4648 lower case Base32 encoding *without* padding.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Base32Unpadded;

impl Alphabet for Base32Unpadded {
    const PADDED: bool = false;

    fn decode_5bits(byte: u8) -> i16 {
        decode_5bits_lower(byte)
    }

    fn encode_5bits(src: u8) -> u8 {
        encode_5bits_lower(src)
    }
}

/// Decode 5-bits of lower-case Base32.
fn decode_5bits_lower(byte: u8) -> i16 {
    let src = byte as i16;
    let mut ret: i16 = -1;

    // if (src > 96 && src < 123) ret += src - 97 + 1; // -64
    ret += (((0x60 - src) & (src - 0x7b)) >> 8) & (src - 96);

    // if (src > 0x31 && src < 0x38) ret += src - 24 + 1; // -23
    ret += (((0x31 - src) & (src - 0x38)) >> 8) & (src - 23);

    ret
}

/// Encode 5-bits of lower-case Base32.
fn encode_5bits_lower(src: u8) -> u8 {
    let mut diff: i16 = 0x61;

    // if (src > 25) ret -= 72;
    diff -= ((25i16 - src as i16) >> 8) & 73;

    (src as i16 + diff) as u8
}
