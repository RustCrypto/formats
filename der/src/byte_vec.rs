//! Common handling for types backed by byte slices with enforcement of a
//! library-level length limitation i.e. `Length::max()`.

use crate::{
    str_slice::StrSlice, DecodeValue, DerOrd, EncodeValue, Error, Header, Length, Reader, Result,
    Writer,
};
use alloc::vec::Vec;
use core::cmp::Ordering;

/// Byte slice newtype which respects the `Length::max()` limit.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) struct ByteVec {
    /// Precomputed `Length` (avoids possible panicking conversions)
    length: Length,

    /// Inner value
    inner: Vec<u8>,
}

impl ByteVec {
    /// Create a new [`ByteVec`], ensuring that the provided `slice` value
    /// is shorter than `Length::max()`.
    pub fn new(slice: &[u8]) -> Result<Self> {
        Ok(Self {
            length: Length::try_from(slice.len())?,
            inner: Vec::from(slice),
        })
    }

    /// Borrow the inner byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Get the [`Length`] of this [`ByteSlice`]
    pub fn len(&self) -> Length {
        self.length
    }
}

impl AsRef<[u8]> for ByteVec {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a> DecodeValue<'a> for ByteVec {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        reader.read_slice(header.length).and_then(Self::new)
    }
}

impl EncodeValue for ByteVec {
    fn value_len(&self) -> Result<Length> {
        Ok(self.length)
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> Result<()> {
        writer.write(self.as_ref())
    }
}

impl Default for ByteVec {
    fn default() -> Self {
        Self {
            length: Length::ZERO,
            inner: Vec::new(),
        }
    }
}

impl DerOrd for ByteVec {
    fn der_cmp(&self, other: &Self) -> Result<Ordering> {
        Ok(self.as_slice().cmp(other.as_slice()))
    }
}

impl From<&[u8; 1]> for ByteVec {
    fn from(byte: &[u8; 1]) -> ByteVec {
        Self {
            length: Length::ONE,
            inner: vec![byte[0]],
        }
    }
}

impl From<StrSlice<'_>> for ByteVec {
    fn from(s: StrSlice<'_>) -> ByteVec {
        let bytes = s.as_bytes();
        debug_assert_eq!(bytes.len(), usize::try_from(s.length).expect("overflow"));

        ByteVec {
            inner: Vec::from(bytes),
            length: s.length,
        }
    }
}

impl TryFrom<&[u8]> for ByteVec {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self> {
        Self::new(slice)
    }
}
