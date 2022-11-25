//! Common handling for types backed by `String` slices with enforcement of a
//! library-level length limitation i.e. `Length::max()`.

use crate::{
    ByteSlice, DecodeValue, EncodeValue, Header, Length, Reader, Result, StrSlice, Writer,
};
use alloc::string::String;
use core::str;

/// String slice newtype which respects the [`Length::max`] limit.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Str {
    /// Inner value
    pub(crate) inner: String,

    /// Precomputed `Length` (avoids possible panicking conversions)
    pub(crate) length: Length,
}

impl Str {
    /// Create a new [`Str`], ensuring that the byte representation of
    /// the provided `str` value is shorter than `Length::max()`.
    pub fn new(s: &str) -> Result<Self> {
        Ok(Self {
            inner: String::from(s),
            length: Length::try_from(s.as_bytes().len())?,
        })
    }

    /// Parse a [`StrSlice`] from UTF-8 encoded bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::new(str::from_utf8(bytes)?)
    }

    /// Borrow the inner `str`
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Borrow the inner byte slice
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    // /// Get the [`Length`] of this [`StrSlice`]
    // pub fn len(self) -> Length {
    //     self.length
    // }

    // /// Is this [`StrSlice`] empty?
    // pub fn is_empty(self) -> bool {
    //     self.len() == Length::ZERO
    // }
}

impl AsRef<str> for Str {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for Str {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a> DecodeValue<'a> for Str {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        Self::from_bytes(ByteSlice::decode_value(reader, header)?.as_slice())
    }
}

impl EncodeValue for Str {
    fn value_len(&self) -> Result<Length> {
        Ok(self.length)
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> Result<()> {
        writer.write(self.as_ref())
    }
}

impl<'a> From<StrSlice<'a>> for Str {
    fn from(input: StrSlice<'a>) -> Str {
        Str {
            length: input.length,
            inner: String::from(input.inner),
        }
    }
}
