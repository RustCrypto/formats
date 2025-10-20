//! `crypt(3)` Base64 encoding.

use super::{Alphabet, DecodeStep, EncodeStep};

/// `crypt(3)` Base64 encoding.
///
/// ```text
/// [.-9]      [A-Z]      [a-z]
/// 0x2e-0x39, 0x41-0x5a, 0x61-0x7a
/// ```
///
/// Note this encodes using a big endian variant of Base64. Most modern algorithms which can be
/// used via `crypt(3)` use the little endian [`Base64ShaCrypt`][`crate::Base64ShaCrypt`] variant.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Base64Crypt;

impl Alphabet for Base64Crypt {
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
