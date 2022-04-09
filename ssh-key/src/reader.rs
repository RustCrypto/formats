//! Reader trait and associated implementations.

use crate::{decode::Decode, Error, Result};
use core::str;
use pem_rfc7468 as pem;

/// Constant-time Base64 reader implementation.
pub(crate) type Base64Reader<'i> = base64ct::Decoder<'i, base64ct::Base64>;

/// Reader trait which decodes the binary SSH protocol serialization from
/// various inputs.
pub(crate) trait Reader: Sized {
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
    /// data, then calls the given nested reader function with the length of
    /// the remaining data.
    ///
    /// As a postcondition, this function checks that the total amount of data
    /// consumed matches the length prefix.
    // TODO(tarcieri): enforce that data can't be read past the given length
    fn read_nested<'r, T, F>(&'r mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut NestedReader<'r, Self>) -> Result<T>,
    {
        let len = usize::decode(self)?;

        f(&mut NestedReader {
            inner: self,
            remaining_len: len,
        })
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
        self.read_nested(|reader| {
            let slice = out.get_mut(..reader.remaining_len()).ok_or(Error::Length)?;
            reader.read(slice)?;
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

    /// Drain the given number of bytes from the reader, discarding them.
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
        self.read_nested(|reader| {
            let len = reader.remaining_len();
            reader.drain(len)?;
            Ok(len)
        })
    }

    /// Finish decoding, returning the given value if there is no remaining
    /// data, or an error otherwise.
    fn finish<T>(self, value: T) -> Result<T> {
        if self.is_finished() {
            Ok(value)
        } else {
            Err(Error::TrailingData {
                remaining: self.remaining_len(),
            })
        }
    }
}

impl Reader for Base64Reader<'_> {
    fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        Ok(self.decode(out)?)
    }

    fn remaining_len(&self) -> usize {
        self.remaining_len()
    }
}

impl Reader for pem::Decoder<'_> {
    fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        Ok(self.decode(out)?)
    }

    fn remaining_len(&self) -> usize {
        self.remaining_len()
    }
}

impl Reader for &[u8] {
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

/// Reader type used by [`Reader::read_nested`].
pub(crate) struct NestedReader<'r, R: Reader> {
    /// Inner reader type.
    inner: &'r mut R,

    /// Remaining length in the nested reader.
    remaining_len: usize,
}

impl<'r, R: Reader> Reader for NestedReader<'r, R> {
    fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        let remaining_len = self
            .remaining_len
            .checked_sub(out.len())
            .ok_or(Error::Length)?;

        let ret = self.inner.read(out)?;
        self.remaining_len = remaining_len;
        Ok(ret)
    }

    fn remaining_len(&self) -> usize {
        self.remaining_len
    }
}
