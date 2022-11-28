//! Common handling for types backed by `String` with enforcement of a
//! library-level length limitation i.e. `Length::max()`.

use crate::{
    referenced::OwnedToRef, ByteSlice, DecodeValue, EncodeValue, Header, Length, Reader, Result,
    StrSlice, Writer,
};
use alloc::string::String as StringA;
use core::str;

/// String newtype which respects the [`Length::max`] limit.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct String {
    /// Inner value
    pub(crate) inner: StringA,

    /// Precomputed `Length` (avoids possible panicking conversions)
    pub(crate) length: Length,
}

impl String {
    /// Create a new [`StrSlice`], ensuring that the byte representation of
    /// the provided `str` value is shorter than `Length::max()`.
    pub fn new(s: &str) -> Result<Self> {
        Ok(Self {
            inner: StringA::from(s),
            length: Length::try_from(s.as_bytes().len())?,
        })
    }

    /// Parse a [`StrSlice`] from UTF-8 encoded bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: StringA::from_utf8(bytes.to_vec())?,
            length: Length::try_from(bytes.len())?,
        })
    }

    /// Borrow the inner `str`
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Borrow the inner byte slice
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Get the [`Length`] of this [`StrSlice`]
    pub fn len(&self) -> Length {
        self.length
    }

    /// Is this [`StrSlice`] empty?
    pub fn is_empty(&self) -> bool {
        self.len() == Length::ZERO
    }
}

impl AsRef<str> for String {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for String {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a> DecodeValue<'a> for String {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        Self::from_bytes(ByteSlice::decode_value(reader, header)?.as_slice())
    }
}

impl EncodeValue for String {
    fn value_len(&self) -> Result<Length> {
        Ok(self.length)
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> Result<()> {
        writer.write(self.as_ref())
    }
}

impl From<StrSlice<'_>> for String {
    fn from(s: StrSlice<'_>) -> String {
        Self {
            inner: StringA::from(s.inner),
            length: s.length,
        }
    }
}

impl OwnedToRef for String {
    type Borrowed<'a> = StrSlice<'a>;
    fn to_ref(&self) -> Self::Borrowed<'_> {
        StrSlice {
            length: self.length,
            inner: self.inner.as_ref(),
        }
    }
}
