//! Base64 support.
//!
//! Provides helper types which use the `base64ct` crate's constant-time Base64
//! implementation for decoding.

use crate::{Error, Result};
use core::str;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

/// Decoder trait.
pub(crate) trait Decode: Sized {
    /// Attempt to decode a value of this type using the provided [`Decoder`].
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self>;
}

/// Stateful Base64 decoder.
pub(crate) struct Decoder<'i> {
    inner: base64ct::Decoder<'i, base64ct::Base64>,
}

impl<'i> Decoder<'i> {
    /// Maximum size of a `usize` this library will accept.
    const MAX_SIZE: usize = 0xFFFFF;

    /// Create a new decoder for a byte slice containing contiguous
    /// (non-newline-delimited) Base64-encoded data.
    pub(crate) fn new(input: &'i [u8]) -> Result<Self> {
        Ok(Self {
            inner: base64ct::Decoder::new(input)?,
        })
    }

    /// Decode as much Base64 as is needed to exactly fill `out`.
    ///
    /// # Returns
    /// - `Ok(bytes)` if the expected amount of data was read
    /// - `Err(Error::Length)` if the exact amount of data couldn't be read
    pub(crate) fn decode_into<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        Ok(self.inner.decode(out)?)
    }

    /// Decodes a single byte.
    #[cfg(feature = "ecdsa")]
    pub(crate) fn decode_u8(&mut self) -> Result<u8> {
        let mut buf = [0];
        self.decode_into(&mut buf)?;
        Ok(buf[0])
    }

    /// Decode a `uint32` as described in [RFC4251 § 5]:
    ///
    /// > Represents a 32-bit unsigned integer.  Stored as four bytes in the
    /// > order of decreasing significance (network byte order).
    /// > For example: the value 699921578 (0x29b7f4aa) is stored as 29 b7 f4 aa.
    ///
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    pub(crate) fn decode_u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.decode_into(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// Decode a `usize`.
    ///
    /// Uses [`Decoder::decode_u32`] and then converts to a `usize`, handling
    /// potential overflow if `usize` is smaller than `u32`.
    pub(crate) fn decode_usize(&mut self) -> Result<usize> {
        let result = usize::try_from(self.decode_u32()?)?;

        if result <= Self::MAX_SIZE {
            Ok(result)
        } else {
            Err(Error::Length)
        }
    }

    /// Decodes `[u8]` from `byte[n]` as described in [RFC4251 § 5]:
    ///
    /// > A byte represents an arbitrary 8-bit value (octet).  Fixed length
    /// > data is sometimes represented as an array of bytes, written
    /// > byte[n], where n is the number of bytes in the array.
    ///
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    pub(crate) fn decode_byte_slice<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        let len = self.decode_usize()?;
        let result = out.get_mut(..len).ok_or(Error::Length)?;
        self.decode_into(result)?;
        Ok(result)
    }

    /// Decodes `Vec<u8>` from `byte[n]` as described in [RFC4251 § 5]:
    ///
    /// > A byte represents an arbitrary 8-bit value (octet).  Fixed length
    /// > data is sometimes represented as an array of bytes, written
    /// > byte[n], where n is the number of bytes in the array.
    ///
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    #[cfg(feature = "alloc")]
    pub(crate) fn decode_byte_vec(&mut self) -> Result<Vec<u8>> {
        let len = self.decode_usize()?;
        let mut result = vec![0u8; len];
        self.decode_into(&mut result)?;
        Ok(result)
    }

    /// Decode a `string` as described in [RFC4251 § 5]:
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
    pub(crate) fn decode_str<'o>(&mut self, buf: &'o mut [u8]) -> Result<&'o str> {
        Ok(str::from_utf8(self.decode_byte_slice(buf)?)?)
    }

    /// Decodes heap allocated `String`: owned equivalent of [`Decoder::decode_str`].
    #[cfg(feature = "alloc")]
    pub(crate) fn decode_string(&mut self) -> Result<String> {
        String::from_utf8(self.decode_byte_vec()?).map_err(|_| Error::CharacterEncoding)
    }

    /// Has all of the input data been decoded?
    pub(crate) fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }
}

impl<'i> From<pem_rfc7468::Decoder<'i>> for Decoder<'i> {
    fn from(decoder: pem_rfc7468::Decoder<'i>) -> Decoder<'i> {
        Decoder {
            inner: decoder.into(),
        }
    }
}

/// Encoder trait.
pub(crate) trait Encode: Sized {
    /// Get the length of this type encoded in bytes, prior to Base64 encoding.
    fn encoded_len(&self) -> Result<usize>;

    /// Attempt to encode a value of this type using the provided [`Encoder`].
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<()>;
}

/// Stateful Base64 encoder.
pub(crate) struct Encoder<'o> {
    inner: base64ct::Encoder<'o, base64ct::Base64>,
}

impl<'o> Encoder<'o> {
    /// Create a new decoder for a byte slice containing contiguous
    /// (non-newline-delimited) Base64-encoded data.
    pub(crate) fn new(buffer: &'o mut [u8]) -> Result<Self> {
        Ok(Self {
            inner: base64ct::Encoder::new(buffer)?,
        })
    }

    /// Encode the given byte slice as Base64.
    pub(crate) fn encode(&mut self, bytes: &[u8]) -> Result<()> {
        Ok(self.inner.encode(bytes)?)
    }

    /// Encode a `uint32` as described in [RFC4251 § 5]:
    ///
    /// > Represents a 32-bit unsigned integer.  Stored as four bytes in the
    /// > order of decreasing significance (network byte order).
    /// > For example: the value 699921578 (0x29b7f4aa) is stored as 29 b7 f4 aa.
    ///
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    pub(crate) fn encode_u32(&mut self, num: u32) -> Result<()> {
        self.encode(&num.to_be_bytes())
    }

    /// Encode a `usize` as a `uint32` as described in [RFC4251 § 5].
    ///
    /// Uses [`Encoder::encode_u32`] after converting from a `usize`, handling
    /// potential overflow if `usize` is bigger than `u32`.
    ///
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    pub(crate) fn encode_usize(&mut self, num: usize) -> Result<()> {
        self.encode_u32(u32::try_from(num)?)
    }

    /// Encodes `[u8]` into `byte[n]` as described in [RFC4251 § 5]:
    ///
    /// > A byte represents an arbitrary 8-bit value (octet).  Fixed length
    /// > data is sometimes represented as an array of bytes, written
    /// > byte[n], where n is the number of bytes in the array.
    ///
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    pub(crate) fn encode_byte_slice(&mut self, bytes: &[u8]) -> Result<()> {
        self.encode_usize(bytes.len())?;
        self.encode(bytes)
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
    pub(crate) fn encode_str(&mut self, s: &str) -> Result<()> {
        self.encode_byte_slice(s.as_bytes())
    }

    /// Finish encoding, returning the encoded Base64 as a `str`.
    pub(crate) fn finish(self) -> Result<&'o str> {
        Ok(self.inner.finish()?)
    }
}

#[cfg(test)]
mod tests {
    use super::{Decoder, Encoder};

    /// From `id_ecdsa_p256.pub`
    const EXAMPLE_BASE64: &str =
        "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHwf2HMM5TRXvo2SQJjsNkiDD5KqiiNjrGVv3UUh+mMT5RHxiRtOnlqvjhQtBq0VpmpCV/PwUdhOig4vkbqAcEc=";
    const EXAMPLE_BIN: &[u8] = &[
        0, 0, 0, 19, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50,
        53, 54, 0, 0, 0, 8, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 65, 4, 124, 31, 216, 115,
        12, 229, 52, 87, 190, 141, 146, 64, 152, 236, 54, 72, 131, 15, 146, 170, 138, 35, 99, 172,
        101, 111, 221, 69, 33, 250, 99, 19, 229, 17, 241, 137, 27, 78, 158, 90, 175, 142, 20, 45,
        6, 173, 21, 166, 106, 66, 87, 243, 240, 81, 216, 78, 138, 14, 47, 145, 186, 128, 112, 71,
    ];

    #[test]
    fn decode_into() {
        let mut decoder = Decoder::new(EXAMPLE_BASE64.as_bytes()).unwrap();
        let mut buf = [0u8; EXAMPLE_BIN.len()];
        let decoded = decoder.decode_into(&mut buf).unwrap();
        assert_eq!(EXAMPLE_BIN, decoded);
    }

    #[test]
    fn encode() {
        let mut buffer = [0u8; EXAMPLE_BASE64.len()];
        let mut encoder = Encoder::new(&mut buffer).unwrap();
        encoder.encode(EXAMPLE_BIN).unwrap();
        assert_eq!(EXAMPLE_BASE64, encoder.finish().unwrap());
    }
}
