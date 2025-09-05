//! Base64 encoding variants.

use base64ct::{Base64Bcrypt, Base64Crypt, Base64ShaCrypt, Encoding as _, Error as B64Error};

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

/// Base64 encoding variants used in various MCF encodings.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Base64 {
    /// bcrypt encoding. Also used by the following schemes:
    /// - scrypt
    /// - yescrypt
    ///
    /// ```text
    /// ./         [0-9]      [A-Z]      [a-z]
    /// 0x2e-0x2f, 0x30-0x39, 0x41-0x5a, 0x61-0x7a
    /// ```
    Bcrypt,

    /// `crypt(3)` encoding.
    ///
    /// ```text
    /// [.-9]      [A-Z]      [a-z]
    /// 0x2e-0x39, 0x41-0x5a, 0x61-0x7a
    /// ```
    Crypt,

    /// `crypt(3)` Base64 encoding. Used by the following schemes:
    /// - sha1_crypt,
    /// - sha256_crypt,
    /// - sha512_crypt,
    /// - md5_crypt
    ///
    /// ```text
    /// [.-9]      [A-Z]      [a-z]
    /// 0x2e-0x39, 0x41-0x5a, 0x61-0x7a
    /// ```
    ShaCrypt,
}

impl Base64 {
    /// Decode a Base64 string into the provided destination buffer.
    pub fn decode(self, src: impl AsRef<[u8]>, dst: &mut [u8]) -> Result<&[u8], B64Error> {
        match self {
            Self::Bcrypt => Base64Bcrypt::decode(src, dst),
            Self::Crypt => Base64Crypt::decode(src, dst),
            Self::ShaCrypt => Base64ShaCrypt::decode(src, dst),
        }
    }

    /// Decode a Base64 string into a byte vector.
    #[cfg(feature = "alloc")]
    pub fn decode_vec(self, input: &str) -> Result<Vec<u8>, B64Error> {
        match self {
            Self::Bcrypt => Base64Bcrypt::decode_vec(input),
            Self::Crypt => Base64Crypt::decode_vec(input),
            Self::ShaCrypt => Base64ShaCrypt::decode_vec(input),
        }
    }

    /// Encode the input byte slice as Base64.
    ///
    /// Writes the result into the provided destination slice, returning an
    /// ASCII-encoded Base64 string value.
    pub fn encode<'a>(self, src: &[u8], dst: &'a mut [u8]) -> Result<&'a str, B64Error> {
        match self {
            Self::Bcrypt => Base64Bcrypt::encode(src, dst),
            Self::Crypt => Base64Crypt::encode(src, dst),
            Self::ShaCrypt => Base64ShaCrypt::encode(src, dst),
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
            Self::Bcrypt => Base64Bcrypt::encode_string(input),
            Self::Crypt => Base64Crypt::encode_string(input),
            Self::ShaCrypt => Base64ShaCrypt::encode_string(input),
        }
    }

    /// Get the length of Base64 produced by encoding the given bytes.
    pub fn encoded_len(self, bytes: &[u8]) -> usize {
        match self {
            Self::Bcrypt => Base64Bcrypt::encoded_len(bytes),
            Self::Crypt => Base64Crypt::encoded_len(bytes),
            Self::ShaCrypt => Base64ShaCrypt::encoded_len(bytes),
        }
    }
}
