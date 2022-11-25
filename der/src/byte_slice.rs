//! Common handling for types backed by byte slices with enforcement of a
//! library-level length limitation i.e. `Length::max()`.

use crate::{
    str_slice::StrSlice, DecodeValue, DerOrd, EncodeValue, Error, Header, Length, Reader, Result,
    Writer,
};
use core::cmp::Ordering;

/// Byte slice newtype which respects the `Length::max()` limit.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) struct ByteSlice<'a> {
    /// Precomputed `Length` (avoids possible panicking conversions)
    length: Length,

    /// Inner value
    inner: &'a [u8],
}

impl<'a> ByteSlice<'a> {
    /// Constant value representing an empty byte slice.
    pub const EMPTY: Self = Self {
        length: Length::ZERO,
        inner: &[],
    };

    /// Create a new [`ByteSlice`], ensuring that the provided `slice` value
    /// is shorter than `Length::max()`.
    pub fn new(slice: &'a [u8]) -> Result<Self> {
        Ok(Self {
            length: Length::try_from(slice.len())?,
            inner: slice,
        })
    }

    /// Borrow the inner byte slice
    pub fn as_slice(&self) -> &'a [u8] {
        self.inner
    }

    /// Get the [`Length`] of this [`ByteSlice`]
    pub fn len(self) -> Length {
        self.length
    }

    /// Is this [`ByteSlice`] empty?
    pub fn is_empty(self) -> bool {
        self.len() == Length::ZERO
    }
}

impl AsRef<[u8]> for ByteSlice<'_> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a> DecodeValue<'a> for ByteSlice<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        reader.read_slice(header.length).and_then(Self::new)
    }
}

impl EncodeValue for ByteSlice<'_> {
    fn value_len(&self) -> Result<Length> {
        Ok(self.length)
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> Result<()> {
        writer.write(self.as_ref())
    }
}

impl Default for ByteSlice<'_> {
    fn default() -> Self {
        Self {
            length: Length::ZERO,
            inner: &[],
        }
    }
}

impl DerOrd for ByteSlice<'_> {
    fn der_cmp(&self, other: &Self) -> Result<Ordering> {
        Ok(self.as_slice().cmp(other.as_slice()))
    }
}

impl<'a> From<&'a [u8; 1]> for ByteSlice<'a> {
    fn from(byte: &'a [u8; 1]) -> ByteSlice<'a> {
        Self {
            length: Length::ONE,
            inner: byte,
        }
    }
}

impl<'a> From<StrSlice<'a>> for ByteSlice<'a> {
    fn from(s: StrSlice<'a>) -> ByteSlice<'a> {
        let bytes = s.as_bytes();
        debug_assert_eq!(bytes.len(), usize::try_from(s.length).expect("overflow"));

        ByteSlice {
            inner: bytes,
            length: s.length,
        }
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<&'a crate::Str> for ByteSlice<'a> {
    fn from(s: &'a crate::Str) -> ByteSlice<'a> {
        let bytes = s.as_bytes();
        debug_assert_eq!(bytes.len(), usize::try_from(s.length).expect("overflow"));

        ByteSlice {
            inner: bytes,
            length: s.length,
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for ByteSlice<'a> {
    type Error = Error;

    fn try_from(slice: &'a [u8]) -> Result<Self> {
        Self::new(slice)
    }
}

#[cfg(feature = "alloc")]
pub(crate) use self::alloc::ByteVec;

#[cfg(feature = "alloc")]
mod alloc {
    use super::ByteSlice;
    use crate::{
        str_slice::StrSlice, DecodeValue, DerOrd, EncodeValue, Error, Header, Length, Reader,
        Result, Writer,
    };
    use ::alloc::vec::Vec;
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
        ///// Constant value representing an empty byte slice.
        //pub const EMPTY: Self = Self {
        //    length: Length::ZERO,
        //    inner: Vec::new(),
        //};

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

        /// Get the [`Length`] of this [`ByteVec`]
        pub fn len(&self) -> Length {
            self.length
        }

        ///// Is this [`ByteVec`] empty?
        //pub fn is_empty(&self) -> bool {
        //    self.len() == Length::ZERO
        //}
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
                inner: Vec::from(&byte[..]),
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

    impl From<ByteSlice<'_>> for ByteVec {
        fn from(s: ByteSlice<'_>) -> ByteVec {
            ByteVec {
                inner: Vec::from(s.inner),
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
}
