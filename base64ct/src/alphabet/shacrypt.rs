//! `crypt(3)` Base64 encoding for sha* family.

use super::{Alphabet, DecodeStep, EncodeStep, LittleEndianAlphabetEncoding};

/// `crypt(3)` Base64 encoding for the following schemes.
///  * sha1_crypt,
///  * sha256_crypt,
///  * sha512_crypt,
///  * md5_crypt
///
/// ```text
/// [.-9]      [A-Z]      [a-z]
/// 0x2e-0x39, 0x41-0x5a, 0x61-0x7a
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Base64ShaCrypt;

impl Alphabet for Base64ShaCrypt {
    const BASE: u8 = b'.';

    const DECODER: &'static [DecodeStep] = &[
        DecodeStep::Range(b'.'..=b'9', -45),
        DecodeStep::Range(b'A'..=b'Z', -52),
        DecodeStep::Range(b'a'..=b'z', -58),
    ];

    const ENCODER: &'static [EncodeStep] =
        &[EncodeStep::Apply(b'9', 7), EncodeStep::Apply(b'Z', 6)];

    const PADDED: bool = false;

    type Unpadded = Self;
}

impl LittleEndianAlphabetEncoding for Base64ShaCrypt {}
