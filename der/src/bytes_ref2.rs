//! Common handling for types backed by byte slices with enforcement of a
//! library-level length limitation i.e. `Length::MAX`.

use crate::{DecodeValue, DerOrd, EncodeValue, Error, Header, Length, Reader, Result, Writer};
use core::cmp::Ordering;

/// Byte slice newtype which respects the `Length::MAX` limit.
#[derive(Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[repr(transparent)]
pub(crate) struct BytesRef([u8]);

impl BytesRef {
    /// Create a new [`BytesRef`], ensuring that the provided `slice` value
    /// is shorter than `Length::MAX`.
    pub const fn new(slice: &[u8]) -> Result<&Self> {
        match Length::new_usize(slice.len()) {
            Ok(_) => Ok(Self::new_unchecked(slice)),
            Err(err) => Err(err),
        }
    }

    /// Perform a raw conversion of a byte slice to `Self` without first performing a length check.
    const fn new_unchecked(slice: &[u8]) -> &Self {
        // SAFETY: `Self` is a `repr(transparent)` newtype for `[u8]`
        #[allow(unsafe_code)]
        unsafe {
            &*(slice as *const [u8] as *const Self)
        }
    }

    /// Borrow the inner byte slice
    pub const fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Get the [`Length`] of this [`BytesRef`]
    pub fn len(&self) -> Length {
        // TODO(tarcieri): non-panicking constructor
        Length::new_usize(self.0.len()).expect("constructor should check length")
    }

    /// Is this [`BytesRef`] empty?
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get a prefix of a [`crate::bytes_ref::BytesRef`] of the given length.
    #[allow(dead_code)]
    pub fn prefix(&self, length: Length) -> Result<&Self> {
        let inner = self
            .as_slice()
            .get(..usize::try_from(length)?)
            .ok_or_else(|| Error::incomplete(self.len()))?;

        Ok(Self::new_unchecked(inner))
    }
}

impl AsRef<[u8]> for &BytesRef {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a> DecodeValue<'a> for &'a BytesRef {
    type Error = Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        BytesRef::new(reader.read_slice(header.length)?)
    }
}

impl EncodeValue for BytesRef {
    fn value_len(&self) -> Result<Length> {
        Ok(self.len())
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        writer.write(self.as_ref())
    }
}

impl DerOrd for BytesRef {
    fn der_cmp(&self, other: &Self) -> Result<Ordering> {
        Ok(self.as_slice().cmp(other.as_slice()))
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a BytesRef {
    type Error = Error;

    fn try_from(slice: &'a [u8]) -> Result<Self> {
        BytesRef::new(slice)
    }
}
