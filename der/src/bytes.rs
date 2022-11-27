//! Common handling for types backed by byte allocation with enforcement of a
//! library-level length limitation i.e. `Length::max()`.

use crate::{
    str_slice::StrSlice, DecodeValue, DerOrd, EncodeValue, Error, Header, Length, Reader, Result,
    Writer,
};
use alloc::boxed::Box;
use core::cmp::Ordering;

/// Byte slice newtype which respects the `Length::max()` limit.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) struct Bytes {
    /// Precomputed `Length` (avoids possible panicking conversions)
    length: Length,

    /// Inner value
    inner: Box<[u8]>,
}

impl Bytes {
    /// Create a new [`Bytes`], ensuring that the provided `slice` value
    /// is shorter than `Length::max()`.
    pub fn new(slice: &[u8]) -> Result<Self> {
        Ok(Self {
            length: Length::try_from(slice.len())?,
            inner: Box::from(slice),
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

    /// Is this [`Bytes`] empty?
    pub fn is_empty(&self) -> bool {
        self.len() == Length::ZERO
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a> DecodeValue<'a> for Bytes {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        reader.read_slice(header.length).and_then(Self::new)
    }
}

impl EncodeValue for Bytes {
    fn value_len(&self) -> Result<Length> {
        Ok(self.length)
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> Result<()> {
        writer.write(self.as_ref())
    }
}

impl Default for Bytes {
    fn default() -> Self {
        Self {
            length: Length::ZERO,
            inner: Box::new([]),
        }
    }
}

impl DerOrd for Bytes {
    fn der_cmp(&self, other: &Self) -> Result<Ordering> {
        Ok(self.as_slice().cmp(other.as_slice()))
    }
}

impl From<&[u8; 1]> for Bytes {
    fn from(byte: &[u8; 1]) -> Bytes {
        Self {
            length: Length::ONE,
            inner: Box::new([byte[0]]),
        }
    }
}

impl From<StrSlice<'_>> for Bytes {
    fn from(s: StrSlice<'_>) -> Bytes {
        let bytes = s.as_bytes();
        debug_assert_eq!(bytes.len(), usize::try_from(s.length).expect("overflow"));

        Bytes {
            inner: Box::from(bytes),
            length: s.length,
        }
    }
}

impl TryFrom<&[u8]> for Bytes {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self> {
        Self::new(slice)
    }
}
