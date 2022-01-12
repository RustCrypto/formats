#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/base16ct/0.0.0"
)]
#![doc = include_str!("../README.md")]

//! # Implementation
//!
//! Implemented using integer arithmetic alone without any lookup tables or
//! data-dependent branches, thereby providing portable "best effort"
//! constant-time operation.
//!
//! Not constant-time with respect to message length (only data).
//!
//! Adapted from this C++ implementation:
//!
//! <https://github.com/Sc00bz/ConstTimeEncoding/blob/master/hex.cpp>
//!
//! Copyright (c) 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com)
//! Derived code is dual licensed MIT + Apache 2.0 (with permission from @Sc00bz)

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use core::fmt;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

/// Error type
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Invalid encoding of provided Base16 string.
    InvalidEncoding,

    /// Insufficient output buffer length.
    InvalidLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidEncoding => f.write_str("invalid Base16 encoding"),
            Error::InvalidLength => f.write_str("invalid Base16 length"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Base16 encoding (a.k.a. hexadecimal)
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Base16 {
    /// Upper or lower case
    case: Case,
}

impl Base16 {
    /// Lower case hex: 0-9 a-f
    pub fn lower_case() -> Base16 {
        Base16 { case: Case::Lower }
    }

    /// Upper case hex: 0-9 A-F
    pub fn upper_case() -> Base16 {
        Base16 { case: Case::Upper }
    }
}

impl Base16 {
    /// Decode a Base16 (hex) string into the provided destination buffer.
    pub fn decode<'a>(&self, src: impl AsRef<[u8]>, dst: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let src = src.as_ref();

        let dst_length = Self::decoded_len(src)?;
        if dst_length > dst.len() {
            return Err(Error::InvalidLength);
        }

        let mut err: usize = 0;

        for (i, dst_byte) in dst.iter_mut().enumerate().take(dst_length) {
            let src_offset = i * 2;
            let byte = (self.case.decode_nibble(src[src_offset]) << 4)
                | self.case.decode_nibble(src[src_offset + 1]);
            err |= byte >> 8;
            *dst_byte = byte as u8;
        }

        if err == 0 {
            Ok(&dst[..dst_length])
        } else {
            Err(Error::InvalidEncoding)
        }
    }

    /// Decode a Base16 (hex) string into a byte vector.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn decode_vec(&self, input: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        let mut output = vec![0u8; Self::decoded_len(input.as_ref())?];
        self.decode(input, &mut output)?;
        Ok(output)
    }

    /// Compute decoded length of the given input.
    pub fn decoded_len(bytes: &[u8]) -> Result<usize, Error> {
        if bytes.len() & 1 == 0 {
            Ok(bytes.len() >> 1)
        } else {
            Err(Error::InvalidLength)
        }
    }

    /// Encode the input byte slice as Base16 (hex).
    ///
    /// Writes the result into the provided destination slice, returning an
    /// ASCII-encoded Base16 (hex) string value.
    pub fn encode<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> Result<&'a [u8], Error> {
        if Self::encoded_len(src) > dst.len() {
            return Err(Error::InvalidLength);
        }

        for (i, src_byte) in src.iter().enumerate() {
            let offset = i * 2;
            dst[offset] = self.case.encode_nibble(src_byte >> 4);
            dst[offset + 1] = self.case.encode_nibble(src_byte & 0x0f);
        }

        Ok(&dst[..(src.len() * 2)])
    }

    /// Encode input byte slice into a [`String`] containing Base16 (hex).
    ///
    /// # Panics
    /// If `input` length is greater than `usize::MAX/2`.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn encode_string(&self, input: &[u8]) -> String {
        let elen = Self::encoded_len(input);
        let mut dst = vec![0u8; elen];
        let res = self.encode(input, &mut dst).expect("encoding error");

        debug_assert_eq!(elen, res.len());
        String::from_utf8(dst).expect("character encoding error")
    }

    /// Get the length of Base16 (hex) produced by encoding the given bytes.
    ///
    /// WARNING: this function will return `0` for lengths greater than `usize::MAX/2`!
    pub fn encoded_len(bytes: &[u8]) -> usize {
        bytes.len() * 2
    }
}

/// Lower or upper case encoders
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
enum Case {
    Lower,
    Upper,
}

impl Case {
    /// Decode a single nibble of hex (lower or upper case)
    #[inline]
    fn decode_nibble(self, src: u8) -> usize {
        // 0-9  0x30-0x39
        // A-F  0x41-0x46 or a-f  0x61-0x66
        let byte = src as isize;
        let mut ret: isize = -1;

        // 0-9  0x30-0x39
        // if (byte > 0x2f && byte < 0x3a) ret += byte - 0x30 + 1; // -47
        ret += (((0x2fisize - byte) & (byte - 0x3a)) >> 8) & (byte - 47);

        ret += match self {
            Case::Lower => {
                // a-f  0x61-0x66
                // if (byte > 0x60 && byte < 0x67) ret += byte - 0x61 + 10 + 1; // -86
                (((0x60isize - byte) & (byte - 0x67)) >> 8) & (byte - 86)
            }
            Case::Upper => {
                // A-F  0x41-0x46
                // if (byte > 0x40 && byte < 0x47) ret += byte - 0x41 + 10 + 1; // -54
                (((0x40isize - byte) & (byte - 0x47)) >> 8) & (byte - 54)
            }
        };

        ret as usize
    }

    /// Encode a single nibble of hex
    #[inline]
    fn encode_nibble(self, src: u8) -> u8 {
        let mut ret = src as isize + 0x30;

        ret += match self {
            Case::Lower => {
                // 0-9  0x30-0x39
                // a-f  0x61-0x66
                ((0x39isize - ret) >> 8) & (0x61isize - 0x3a)
            }
            Case::Upper => {
                // 0-9  0x30-0x39
                // A-F  0x41-0x46
                ((0x39isize - ret) >> 8) & (0x41isize - 0x3a)
            }
        };

        ret as u8
    }
}

impl Default for Case {
    /// Default: lower case
    fn default() -> Case {
        Case::Lower
    }
}
