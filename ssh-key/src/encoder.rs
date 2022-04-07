//! Encoder-side implementation of the SSH protocol's data type representations
//! as described in [RFC4251 § 5].
//!
//! [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5

use crate::{checked::CheckedSum, Result};
use core::str;
use pem_rfc7468 as pem;

#[cfg(feature = "alloc")]
use {
    crate::Error,
    alloc::{string::String, vec::Vec},
};

#[cfg(feature = "fingerprint")]
use sha2::{Digest, Sha256};

/// Get the estimated length of data when encoded as Base64.
///
/// This is an upper bound where the actual length might be slightly shorter.
#[cfg(feature = "alloc")]
#[allow(clippy::integer_arithmetic)]
pub(crate) fn base64_encoded_len(input_len: usize) -> usize {
    // TODO(tarcieri): checked arithmetic
    (((input_len * 4) / 3) + 3) & !3
}

/// Stateful Base64 encoder.
pub(crate) type Base64Encoder<'o> = base64ct::Encoder<'o, base64ct::Base64>;

/// Encoding trait.
///
/// This trait describes how to encode a given type.
pub(crate) trait Encode {
    /// Get the length of this type encoded in bytes, prior to Base64 encoding.
    fn encoded_len(&self) -> Result<usize>;

    /// Encode this value using the provided [`Encoder`].
    fn encode(&self, encoder: &mut impl Encoder) -> Result<()>;

    /// Encode this value, first prepending a `uint32` length prefix
    /// set to [`Encode::encoded_len`].
    fn encode_nested(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.encoded_len()?.encode(encoder)?;
        self.encode(encoder)
    }
}

/// Encode a `uint32` as described in [RFC4251 § 5]:
///
/// > Represents a 32-bit unsigned integer.  Stored as four bytes in the
/// > order of decreasing significance (network byte order).
/// > For example: the value 699921578 (0x29b7f4aa) is stored as 29 b7 f4 aa.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Encode for u32 {
    fn encoded_len(&self) -> Result<usize> {
        Ok(4)
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        encoder.write(&self.to_be_bytes())
    }
}

/// Encode a `uint64` as described in [RFC4251 § 5]:
///
/// > Represents a 64-bit unsigned integer.  Stored as eight bytes in
/// > the order of decreasing significance (network byte order).
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Encode for u64 {
    fn encoded_len(&self) -> Result<usize> {
        Ok(8)
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        encoder.write(&self.to_be_bytes())
    }
}

/// Encode a `usize` as a `uint32` as described in [RFC4251 § 5].
///
/// Uses [`Encode`] impl on `u32` after converting from a `usize`, handling
/// potential overflow if `usize` is bigger than `u32`.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Encode for usize {
    fn encoded_len(&self) -> Result<usize> {
        Ok(4)
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        u32::try_from(*self)?.encode(encoder)
    }
}

/// Encodes `[u8]` into `byte[n]` as described in [RFC4251 § 5]:
///
/// > A byte represents an arbitrary 8-bit value (octet).  Fixed length
/// > data is sometimes represented as an array of bytes, written
/// > byte[n], where n is the number of bytes in the array.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Encode for [u8] {
    fn encoded_len(&self) -> Result<usize> {
        [4, self.len()].checked_sum()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.len().encode(encoder)?;
        encoder.write(self)
    }
}

/// Encodes `[u8; N]` into `byte[n]` as described in [RFC4251 § 5]:
///
/// > A byte represents an arbitrary 8-bit value (octet).  Fixed length
/// > data is sometimes represented as an array of bytes, written
/// > byte[n], where n is the number of bytes in the array.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl<const N: usize> Encode for [u8; N] {
    fn encoded_len(&self) -> Result<usize> {
        self.as_slice().encoded_len()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.as_slice().encode(encoder)
    }
}

/// Encode a `string` as described in [RFC4251 § 5]:
///
/// > Arbitrary length binary string.  Strings are allowed to contain
/// > arbitrary binary data, including null characters and 8-bit
/// > characters.  They are stored as a uint32 containing its length
/// > (number of bytes that follow) and zero (= empty string) or more
/// > bytes that are the value of the string.  Terminating null
/// > characters are not used.
/// >
/// > Strings are also used to store text.  In that case, US-ASCII is
/// > used for internal names, and ISO-10646 UTF-8 for text that might
/// > be displayed to the user.  The terminating null character SHOULD
/// > NOT normally be stored in the string.  For example: the US-ASCII
/// > string "testing" is represented as 00 00 00 07 t e s t i n g.  The
/// > UTF-8 mapping does not alter the encoding of US-ASCII characters.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Encode for &str {
    fn encoded_len(&self) -> Result<usize> {
        self.as_bytes().encoded_len()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.as_bytes().encode(encoder)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl Encode for Vec<u8> {
    fn encoded_len(&self) -> Result<usize> {
        self.as_slice().encoded_len()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.as_slice().encode(encoder)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl Encode for String {
    fn encoded_len(&self) -> Result<usize> {
        self.as_str().encoded_len()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.as_str().encode(encoder)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl Encode for Vec<String> {
    fn encoded_len(&self) -> Result<usize> {
        self.iter().try_fold(4usize, |acc, string| {
            acc.checked_add(string.encoded_len()?).ok_or(Error::Length)
        })
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.encoded_len()?
            .checked_sub(4)
            .ok_or(Error::Length)?
            .encode(encoder)?;

        for entry in self {
            entry.encode(encoder)?;
        }

        Ok(())
    }
}

/// Encoder extension trait.
pub(crate) trait Encoder: Sized {
    /// Write the given bytes to the encoder.
    fn write(&mut self, bytes: &[u8]) -> Result<()>;
}

impl Encoder for Base64Encoder<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        Ok(self.encode(bytes)?)
    }
}

impl Encoder for pem::Encoder<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        Ok(self.encode(bytes)?)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl Encoder for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

#[cfg(feature = "fingerprint")]
impl Encoder for Sha256 {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.update(bytes);
        Ok(())
    }
}
