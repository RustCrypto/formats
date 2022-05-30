//! Pure Rust implementation of Base32 ([RFC 4648]).
//!
//! Implements Base32 variants without data-dependent branches
//! or lookup  tables, thereby providing portable "best effort" constant-time
//! operation. Not constant-time with respect to message length (only data).
//!
//! Supports `no_std` environments and avoids heap allocations in the core API
//! (but also provides optional `alloc` support for convenience).
//!
//! Adapted from: <https://github.com/paragonie/constant_time_encoding/blob/master/src/Base32.php>
//!
//! [RFC 4648]: https://tools.ietf.org/html/rfc4648

// Copyright (c) 2016 - 2018 Paragon Initiative Enterprises.
// Copyright (c) 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com).
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::unwrap_used, missing_docs, rust_2018_idioms)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod encoding;
mod error;

pub use crate::{
    encoding::Encoding,
    error::{Error, Result},
};

/// RFC4648 lower case Base32 encoding with `=` padding.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Base32;

impl Encoding for Base32 {
    const PADDED: bool = true;

    fn decode_5bits(byte: u8) -> i16 {
        decode_5bits_lower(byte)
    }

    fn encode_5bits(src: u8) -> u8 {
        encode_5bits_lower(src)
    }
}

/// RFC4648 upper case Base32 encoding with `=` padding.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Base32Upper;

impl Encoding for Base32Upper {
    const PADDED: bool = true;

    fn decode_5bits(byte: u8) -> i16 {
        decode_5bits_upper(byte)
    }

    fn encode_5bits(src: u8) -> u8 {
        encode_5bits_upper(src)
    }
}

/// RFC4648 lower case Base32 encoding *without* padding.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Base32Unpadded;

impl Encoding for Base32Unpadded {
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

/// Encode 5-bits of lower-case Base32.
fn encode_5bits_lower(src: u8) -> u8 {
    let mut diff: i16 = 0x61;

    // if (src > 25) ret -= 72;
    diff -= ((25i16 - src as i16) >> 8) & 73;

    (src as i16 + diff) as u8
}

/// Encode 5-bits of upper-case Base32.
fn encode_5bits_upper(src: u8) -> u8 {
    let mut diff: i16 = 0x41;

    // if ($src > 25) $ret -= 40;
    diff -= ((25 - src as i16) >> 8) & 41;

    (src as i16 + diff) as u8
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use crate::{Base32, Base32Unpadded, Base32Upper, Encoding, Error};

    #[derive(Debug)]
    struct TestVector {
        decoded: &'static [u8],
        encoded: &'static str,
    }

    const LOWER_PADDED_VECTORS: &[TestVector] = &[
        TestVector {
            decoded: &[0],
            encoded: "aa======",
        },
        TestVector {
            decoded: &[1, 2, 3, 5, 9, 17, 33, 65, 129],
            encoded: "aebagbijcequdai=",
        },
        TestVector {
            decoded: &[32, 7],
            encoded: "eadq====",
        },
    ];

    const LOWER_UNPADDED_VECTORS: &[TestVector] = &[
        TestVector {
            decoded: &[0],
            encoded: "aa",
        },
        TestVector {
            decoded: &[1, 2, 3, 5, 9, 17, 33, 65, 129],
            encoded: "aebagbijcequdai",
        },
        TestVector {
            decoded: &[32, 7],
            encoded: "eadq",
        },
    ];

    const UPPER_PADDED_VECTORS: &[TestVector] = &[
        TestVector {
            decoded: &[0],
            encoded: "AA======",
        },
        TestVector {
            decoded: &[1, 2, 3, 5, 9, 17, 33, 65, 129],
            encoded: "AEBAGBIJCEQUDAI=",
        },
        TestVector {
            decoded: &[32, 7],
            encoded: "EADQ====",
        },
    ];

    #[test]
    fn decode_valid_base32() {
        for vector in LOWER_PADDED_VECTORS {
            assert_eq!(&Base32::decode_vec(vector.encoded).unwrap(), vector.decoded);
        }

        for vector in LOWER_UNPADDED_VECTORS {
            assert_eq!(
                &Base32Unpadded::decode_vec(vector.encoded).unwrap(),
                vector.decoded
            );
        }

        for vector in UPPER_PADDED_VECTORS {
            assert_eq!(
                &Base32Upper::decode_vec(vector.encoded).unwrap(),
                vector.decoded
            );
        }
    }

    #[test]
    fn decode_padding_error() {
        let truncated =
            &LOWER_PADDED_VECTORS[0].encoded[..(&LOWER_PADDED_VECTORS[0].encoded.len() - 1)];
        assert_eq!(Base32::decode_vec(truncated), Err(Error::InvalidEncoding));
    }

    #[test]
    fn decode_range_error() {
        assert_eq!(
            Base32::decode_vec(core::str::from_utf8(&[0, 0, 0]).unwrap()),
            Err(Error::InvalidEncoding)
        );
    }

    #[test]
    fn encode_base32() {
        for vector in LOWER_PADDED_VECTORS {
            assert_eq!(&Base32::encode_string(vector.decoded), vector.encoded);
        }

        for vector in LOWER_UNPADDED_VECTORS {
            assert_eq!(
                &Base32Unpadded::encode_string(vector.decoded),
                vector.encoded
            );
        }

        for vector in UPPER_PADDED_VECTORS {
            assert_eq!(&Base32Upper::encode_string(vector.decoded), vector.encoded);
        }
    }
}
