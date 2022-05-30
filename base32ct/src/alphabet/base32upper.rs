//! RFC4648 Base32 (upper case).

use super::Alphabet;

/// RFC4648 upper case Base32 encoding with `=` padding.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Base32Upper;

impl Alphabet for Base32Upper {
    const PADDED: bool = true;

    fn decode_5bits(byte: u8) -> i16 {
        decode_5bits_upper(byte)
    }

    fn encode_5bits(src: u8) -> u8 {
        encode_5bits_upper(src)
    }
}

/// Decode 5-bits of upper-case Base32.
fn decode_5bits_upper(byte: u8) -> i16 {
    let src = byte as i16;
    let mut ret: i16 = -1;

    // if (src > 64 && src < 91) ret += src - 65 + 1; // -64
    ret += (((0x40 - src) & (src - 0x5b)) >> 8) & (src - 64);

    // if ($src > 0x31 && $src < 0x38) $ret += $src - 24 + 1; // -23
    ret += (((0x31 - src) & (src - 0x38)) >> 8) & (src - 23);

    ret
}

/// Encode 5-bits of upper-case Base32.
fn encode_5bits_upper(src: u8) -> u8 {
    let mut diff: i16 = 0x41;

    // if ($src > 25) $ret -= 40;
    diff -= ((25 - src as i16) >> 8) & 41;

    (src as i16 + diff) as u8
}
