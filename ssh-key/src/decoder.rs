//! Decoder-side implementation of the SSH protocol's data type representations
//! as described in [RFC4251 § 5].
//!
//! [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5

use crate::{Error, Result};
use core::str;
use pem_rfc7468 as pem;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

/// Maximum size of a `usize` this library will accept.
const MAX_SIZE: usize = 0xFFFFF;

/// Stateful Base64 decoder.
pub(crate) type Base64Decoder<'i> = base64ct::Decoder<'i, base64ct::Base64>;

/// Decoder trait.
///
/// This trait describes how to decode a given type.
pub(crate) trait Decode: Sized {
    /// Attempt to decode a value of this type using the provided [`Decoder`].
    fn decode(decoder: &mut impl Decoder) -> Result<Self>;
}

/// Decode a single byte from the input data.
impl Decode for u8 {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        let mut buf = [0];
        decoder.read(&mut buf)?;
        Ok(buf[0])
    }
}

/// Decode a `uint32` as described in [RFC4251 § 5]:
///
/// > Represents a 32-bit unsigned integer.  Stored as four bytes in the
/// > order of decreasing significance (network byte order).
/// > For example: the value 699921578 (0x29b7f4aa) is stored as 29 b7 f4 aa.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Decode for u32 {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        let mut bytes = [0u8; 4];
        decoder.read(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }
}

/// Decode a `uint64` as described in [RFC4251 § 5]:
///
/// > Represents a 64-bit unsigned integer.  Stored as eight bytes in
/// > the order of decreasing significance (network byte order).
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl Decode for u64 {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        let mut bytes = [0u8; 8];
        decoder.read(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }
}

/// Decode a `usize`.
///
/// Uses [`Decode`] impl on `u32` and then converts to a `usize`, handling
/// potential overflow if `usize` is smaller than `u32`.
///
/// Enforces a library-internal limit of 1048575, as the main use case for
/// `usize` is length prefixes.
impl Decode for usize {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        let n = usize::try_from(u32::decode(decoder)?)?;

        if n <= MAX_SIZE {
            Ok(n)
        } else {
            Err(Error::Length)
        }
    }
}

/// Decodes a byte array from `byte[n]` as described in [RFC4251 § 5]:
///
/// > A byte represents an arbitrary 8-bit value (octet).  Fixed length
/// > data is sometimes represented as an array of bytes, written
/// > byte[n], where n is the number of bytes in the array.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
impl<const N: usize> Decode for [u8; N] {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        decoder.read_nested(|decoder, _len| {
            let mut result = [(); N].map(|_| 0);
            decoder.read(&mut result)?;
            Ok(result)
        })
    }
}

/// Decodes `Vec<u8>` from `byte[n]` as described in [RFC4251 § 5]:
///
/// > A byte represents an arbitrary 8-bit value (octet).  Fixed length
/// > data is sometimes represented as an array of bytes, written
/// > byte[n], where n is the number of bytes in the array.
///
/// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl Decode for Vec<u8> {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        decoder.read_nested(|decoder, len| {
            let mut result = vec![0u8; len];
            decoder.read(&mut result)?;
            Ok(result)
        })
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl Decode for String {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        String::from_utf8(Vec::decode(decoder)?).map_err(|_| Error::CharacterEncoding)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl Decode for Vec<String> {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        decoder.read_nested(|decoder, len| {
            let mut entries = Self::new();
            let offset = decoder.remaining_len();

            while offset.saturating_sub(decoder.remaining_len()) < len {
                entries.push(String::decode(decoder)?);
            }

            Ok(entries)
        })
    }
}

/// Decoder trait.
pub(crate) trait Decoder: Sized {
    /// Read as much data as is needed to exactly fill `out`.
    ///
    /// This is the base decoding method on which the rest of the trait is
    /// implemented in terms of.
    ///
    /// # Returns
    /// - `Ok(bytes)` if the expected amount of data was read
    /// - `Err(Error::Length)` if the exact amount of data couldn't be read
    fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]>;

    /// Get the length of the remaining data after Base64 decoding.
    fn remaining_len(&self) -> usize;

    /// Is decoding finished?
    fn is_finished(&self) -> bool {
        self.remaining_len() == 0
    }

    /// Decode length-prefixed nested data.
    ///
    /// Decodes a `uint32` which identifies the length of some encapsulated
    /// data, then calls the given nested decoder function with the length of
    /// the remaining data.
    ///
    /// As a postcondition, this function checks that the total amount of data
    /// consumed matches the length prefix.
    // TODO(tarcieri): enforce that data can't be read past the given length
    fn read_nested<T, F>(&mut self, f: F) -> Result<T>
    where
        Self: Sized,
        F: FnOnce(&mut Self, usize) -> Result<T>,
    {
        let len = usize::decode(self)?;
        let offset = self.remaining_len();
        let ret = f(self, len)?;

        if self.remaining_len().checked_add(len) == Some(offset) {
            Ok(ret)
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
    /// Storage for the byte array must be provided as mutable byte slice in
    /// order to accommodate `no_std` use cases.
    ///
    /// The [`Decode`] impl on [`Vec<u8>`] can be used to allocate a buffer for
    /// the result.
    ///
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    fn read_byten<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        self.read_nested(|decoder, len| {
            let slice = out.get_mut(..len).ok_or(Error::Length)?;
            decoder.read(slice)?;
            Ok(&slice[..])
        })
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
    /// Storage for the string data must be provided as mutable byte slice in
    /// order to accommodate `no_std` use cases.
    ///
    /// The [`Decode`] impl on [`String`] can be used to allocate a buffer for
    /// the result.
    ///
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    fn read_string<'o>(&mut self, buf: &'o mut [u8]) -> Result<&'o str> {
        Ok(str::from_utf8(self.read_byten(buf)?)?)
    }

    /// Drain the given number of bytes from the decoder, discarding them.
    fn drain(&mut self, n_bytes: usize) -> Result<()> {
        let mut byte = [0];
        for _ in 0..n_bytes {
            self.read(&mut byte)?;
        }
        Ok(())
    }

    /// Decode a `u32` length prefix, and then drain the length of the body.
    ///
    /// Upon success, returns the number of bytes drained sans the length of
    /// the `u32` length prefix (4-bytes).
    fn drain_prefixed(&mut self) -> Result<usize> {
        self.read_nested(|decoder, len| {
            decoder.drain(len)?;
            Ok(len)
        })
    }
}

impl Decoder for Base64Decoder<'_> {
    fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        Ok(self.decode(out)?)
    }

    fn remaining_len(&self) -> usize {
        self.remaining_len()
    }
}

impl Decoder for pem::Decoder<'_> {
    fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        Ok(self.decode(out)?)
    }

    fn remaining_len(&self) -> usize {
        self.remaining_len()
    }
}

impl Decoder for &[u8] {
    fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        if self.len() >= out.len() {
            let (head, tail) = self.split_at(out.len());
            *self = tail;
            out.copy_from_slice(head);
            Ok(out)
        } else {
            Err(Error::Length)
        }
    }

    fn remaining_len(&self) -> usize {
        self.len()
    }
}
