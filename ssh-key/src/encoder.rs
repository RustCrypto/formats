//! Encoder support.
//!
//! Support for encoding SSH keys to the OpenSSH wire format.

use crate::Result;
use core::str;
use pem_rfc7468 as pem;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "fingerprint")]
use sha2::{Digest, Sha256};

/// Get the estimated length of data when encoded as Base64.
///
/// This is an upper bound where the actual length might be slightly shorter.
#[cfg(feature = "alloc")]
pub(crate) fn encoded_len(input_len: usize) -> usize {
    (((input_len * 4) / 3) + 3) & !3
}

/// Stateful Base64 encoder.
pub(crate) type Base64Encoder<'o> = base64ct::Encoder<'o, base64ct::Base64>;

/// Encoder trait.
pub(crate) trait Encode: Sized {
    /// Get the length of this type encoded in bytes, prior to Base64 encoding.
    fn encoded_len(&self) -> Result<usize>;

    /// Attempt to encode a value of this type using the provided [`Encoder`].
    fn encode(&self, encoder: &mut impl Encoder) -> Result<()>;
}

/// Encoder extension trait.
pub(crate) trait Encoder: Sized {
    /// Encode the given byte slice containing raw unstructured data.
    ///
    /// This is the base encoding method on which the rest of the trait is
    /// implemented in terms of.
    fn encode_raw(&mut self, bytes: &[u8]) -> Result<()>;

    /// Encode a `uint32` as described in [RFC4251 § 5]:
    ///
    /// > Represents a 32-bit unsigned integer.  Stored as four bytes in the
    /// > order of decreasing significance (network byte order).
    /// > For example: the value 699921578 (0x29b7f4aa) is stored as 29 b7 f4 aa.
    ///
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    fn encode_u32(&mut self, num: u32) -> Result<()> {
        self.encode_raw(&num.to_be_bytes())
    }

    /// Encode a `usize` as a `uint32` as described in [RFC4251 § 5].
    ///
    /// Uses [`Encoder::encode_u32`] after converting from a `usize`, handling
    /// potential overflow if `usize` is bigger than `u32`.
    ///
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    fn encode_usize(&mut self, num: usize) -> Result<()> {
        self.encode_u32(u32::try_from(num)?)
    }

    /// Encodes length-prefixed nested data.
    ///
    /// Encodes a `uint32` which identifies the length of some encapsulated
    /// data, then encodes the value.
    fn encode_length_prefixed<T: Encode>(&mut self, value: &T) -> Result<()> {
        self.encode_usize(value.encoded_len()?)?;
        value.encode(self)
    }

    /// Encodes `[u8]` into `byte[n]` as described in [RFC4251 § 5]:
    ///
    /// > A byte represents an arbitrary 8-bit value (octet).  Fixed length
    /// > data is sometimes represented as an array of bytes, written
    /// > byte[n], where n is the number of bytes in the array.
    ///
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    fn encode_byte_slice(&mut self, bytes: &[u8]) -> Result<()> {
        self.encode_usize(bytes.len())?;
        self.encode_raw(bytes)
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
    fn encode_str(&mut self, s: &str) -> Result<()> {
        self.encode_byte_slice(s.as_bytes())
    }
}

impl Encoder for Base64Encoder<'_> {
    fn encode_raw(&mut self, bytes: &[u8]) -> Result<()> {
        Ok(self.encode(bytes)?)
    }
}

impl Encoder for pem::Encoder<'_, '_> {
    fn encode_raw(&mut self, bytes: &[u8]) -> Result<()> {
        Ok(self.encode(bytes)?)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl Encoder for Vec<u8> {
    fn encode_raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

#[cfg(feature = "fingerprint")]
impl Encoder for Sha256 {
    fn encode_raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.update(bytes);
        Ok(())
    }
}
