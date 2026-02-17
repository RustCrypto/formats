//! Base64 encoding variants.

#![cfg(feature = "base64")]

use base64ct::{
    Base64Bcrypt, Base64Pbkdf2, Base64ShaCrypt, Base64Unpadded as B64, Encoding as _,
    Error as B64Error,
};

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

/// Base64 encoding variants used in various MCF encodings.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Base64 {
    /// "B64" encoding: standard Base64 without padding, as used by the PHC string format.
    ///
    /// ```text
    /// [A-Z]      [a-z]      [0-9]      +     /
    /// 0x41-0x5a, 0x61-0x7a, 0x30-0x39, 0x2b, 0x2f
    /// ```
    /// <https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#b64>
    B64,

    /// bcrypt encoding.
    ///
    /// ```text
    /// ./         [A-Z]      [a-z]      [0-9]
    /// 0x2e-0x2f, 0x41-0x5a, 0x61-0x7a, 0x30-0x39
    /// ```
    Bcrypt,

    /// `crypt(3)` Base64 encoding.
    ///
    /// Used by the following schemes:
    /// - MD5-Crypt
    /// - scrypt
    /// - SHA1-Crypt
    /// - SHA256-Crypt
    /// - SHA512-Crypt
    /// - yescrypt
    ///
    /// ```text
    /// [.-9]      [A-Z]      [a-z]
    /// 0x2e-0x39, 0x41-0x5a, 0x61-0x7a
    /// ```
    Crypt,

    /// PBKDF2 Base64 encoding.
    ///
    /// This is a variant of the unpadded standard Base64 with `.` in place of `+`:
    ///
    /// ```text
    /// [A-Z]      [a-z]      [0-9]      .     /
    /// 0x41-0x5a, 0x61-0x7a, 0x30-0x39, 0x2e, 0x2f
    /// ```
    Pbkdf2,
}

impl Base64 {
    /// Decode a Base64 string into the provided destination buffer.
    pub fn decode(self, src: impl AsRef<[u8]>, dst: &mut [u8]) -> Result<&[u8], B64Error> {
        match self {
            Self::B64 => B64::decode(src, dst),
            Self::Bcrypt => Base64Bcrypt::decode(src, dst),
            Self::Crypt => Base64ShaCrypt::decode(src, dst),
            Self::Pbkdf2 => Base64Pbkdf2::decode(src, dst),
        }
    }

    /// Decode a Base64 string into a byte vector.
    #[cfg(feature = "alloc")]
    pub fn decode_vec(self, input: &str) -> Result<Vec<u8>, B64Error> {
        match self {
            Self::B64 => B64::decode_vec(input),
            Self::Bcrypt => Base64Bcrypt::decode_vec(input),
            Self::Crypt => Base64ShaCrypt::decode_vec(input),
            Self::Pbkdf2 => Base64Pbkdf2::decode_vec(input),
        }
    }

    /// Encode the input byte slice as Base64.
    ///
    /// Writes the result into the provided destination slice, returning an
    /// ASCII-encoded Base64 string value.
    pub fn encode<'a>(self, src: &[u8], dst: &'a mut [u8]) -> Result<&'a str, B64Error> {
        match self {
            Self::B64 => B64::encode(src, dst),
            Self::Bcrypt => Base64Bcrypt::encode(src, dst),
            Self::Crypt => Base64ShaCrypt::encode(src, dst),
            Self::Pbkdf2 => Base64Pbkdf2::encode(src, dst),
        }
        .map_err(Into::into)
    }

    /// Encode input byte slice into a [`String`] containing Base64.
    ///
    /// # Panics
    /// If `input` length is greater than `usize::MAX/4`.
    #[cfg(feature = "alloc")]
    pub fn encode_string(self, input: &[u8]) -> String {
        match self {
            Self::B64 => B64::encode_string(input),
            Self::Bcrypt => Base64Bcrypt::encode_string(input),
            Self::Crypt => Base64ShaCrypt::encode_string(input),
            Self::Pbkdf2 => Base64Pbkdf2::encode_string(input),
        }
    }

    /// Get the length of Base64 produced by encoding the given bytes.
    pub fn encoded_len(self, bytes: &[u8]) -> usize {
        match self {
            Self::B64 => B64::encoded_len(bytes),
            Self::Bcrypt => Base64Bcrypt::encoded_len(bytes),
            Self::Crypt => Base64ShaCrypt::encoded_len(bytes),
            Self::Pbkdf2 => Base64Pbkdf2::encoded_len(bytes),
        }
    }
}
