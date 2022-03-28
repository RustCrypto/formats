//! Decoder support.
//!
//! Support for decoding SSH keys from the OpenSSH wire format.

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
pub(crate) trait Decode: Sized {
    /// Attempt to decode a value of this type using the provided [`Decoder`].
    fn decode(decoder: &mut impl Decoder) -> Result<Self>;
}

/// Decoder extension trait.
pub(crate) trait Decoder {
    /// Decode as much data as is needed to exactly fill `out`.
    ///
    /// This is the base decoding method on which the rest of the trait is
    /// implemented in terms of.
    ///
    /// # Returns
    /// - `Ok(bytes)` if the expected amount of data was read
    /// - `Err(Error::Length)` if the exact amount of data couldn't be read
    fn decode_raw<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]>;

    /// Get the length of the remaining data after Base64 decoding.
    fn remaining_len(&self) -> usize;

    /// Is decoding finished?
    fn is_finished(&self) -> bool;

    /// Decodes a single byte.
    #[cfg(feature = "ecdsa")]
    fn decode_u8(&mut self) -> Result<u8> {
        let mut buf = [0];
        self.decode_raw(&mut buf)?;
        Ok(buf[0])
    }

    /// Decode a `uint32` as described in [RFC4251 § 5]:
    ///
    /// > Represents a 32-bit unsigned integer.  Stored as four bytes in the
    /// > order of decreasing significance (network byte order).
    /// > For example: the value 699921578 (0x29b7f4aa) is stored as 29 b7 f4 aa.
    ///
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    fn decode_u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.decode_raw(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// Decode a `usize`.
    ///
    /// Uses [`Decoder::decode_u32`] and then converts to a `usize`, handling
    /// potential overflow if `usize` is smaller than `u32`.
    fn decode_usize(&mut self) -> Result<usize> {
        let result = usize::try_from(self.decode_u32()?)?;

        if result <= MAX_SIZE {
            Ok(result)
        } else {
            Err(Error::Length)
        }
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
    fn decode_length_prefixed<T, F>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Self, usize) -> Result<T>,
    {
        let len = self.decode_usize()?;
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
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    fn decode_byte_slice<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        self.decode_length_prefixed(|decoder, len| {
            let slice = out.get_mut(..len).ok_or(Error::Length)?;
            decoder.decode_raw(slice)?;
            Ok(&slice[..])
        })
    }

    /// Decodes `Vec<u8>` from `byte[n]` as described in [RFC4251 § 5]:
    ///
    /// > A byte represents an arbitrary 8-bit value (octet).  Fixed length
    /// > data is sometimes represented as an array of bytes, written
    /// > byte[n], where n is the number of bytes in the array.
    ///
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    #[cfg(feature = "alloc")]
    fn decode_byte_vec(&mut self) -> Result<Vec<u8>> {
        self.decode_length_prefixed(|decoder, len| {
            let mut result = vec![0u8; len];
            decoder.decode_raw(&mut result)?;
            Ok(result)
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
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    fn decode_str<'o>(&mut self, buf: &'o mut [u8]) -> Result<&'o str> {
        Ok(str::from_utf8(self.decode_byte_slice(buf)?)?)
    }

    /// Decodes heap allocated `String`: owned equivalent of [`Decoder::decode_str`].
    #[cfg(feature = "alloc")]
    fn decode_string(&mut self) -> Result<String> {
        String::from_utf8(self.decode_byte_vec()?).map_err(|_| Error::CharacterEncoding)
    }

    /// Drain the given number of bytes from the decoder, discarding them.
    fn drain(&mut self, n_bytes: usize) -> Result<()> {
        let mut byte = [0];
        for _ in 0..n_bytes {
            self.decode_raw(&mut byte)?;
        }
        Ok(())
    }

    /// Decode a `u32` length prefix, and then drain the length of the body.
    fn drain_prefixed(&mut self) -> Result<()> {
        self.decode_length_prefixed(|decoder, len| decoder.drain(len))
    }
}

impl Decoder for Base64Decoder<'_> {
    fn decode_raw<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        Ok(self.decode(out)?)
    }

    fn remaining_len(&self) -> usize {
        self.remaining_len()
    }

    fn is_finished(&self) -> bool {
        self.is_finished()
    }
}

impl Decoder for pem::Decoder<'_> {
    fn decode_raw<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        Ok(self.decode(out)?)
    }

    fn remaining_len(&self) -> usize {
        self.remaining_len()
    }

    fn is_finished(&self) -> bool {
        self.is_finished()
    }
}

impl Decoder for &[u8] {
    fn decode_raw<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
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

    fn is_finished(&self) -> bool {
        self.is_empty()
    }
}
