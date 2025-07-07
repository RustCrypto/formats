//! Common handling for types backed by byte slices with enforcement of a
//! library-level length limitation i.e. `Length::max()`.

use crate::{
    DecodeValue, DerOrd, EncodeValue, Error, ErrorKind, Header, Length, Reader, Result, StringRef,
    Writer,
};
use core::cmp::Ordering;

#[cfg(feature = "alloc")]
use crate::StringOwned;

/// Byte slice newtype which respects the `Length::max()` limit.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub(crate) struct BytesRef<'a> {
    /// Precomputed `Length` (avoids possible panicking conversions)
    pub length: Length,

    /// Inner value
    pub inner: &'a [u8],
}

impl<'a> BytesRef<'a> {
    /// Constant value representing an empty byte slice.
    pub const EMPTY: Self = Self {
        length: Length::ZERO,
        inner: &[],
    };

    /// Create a new [`BytesRef`], ensuring that the provided `slice` value
    /// is shorter than `Length::max()`.
    pub const fn new(slice: &'a [u8]) -> Result<Self> {
        match Length::new_usize(slice.len()) {
            Ok(length) => Ok(Self {
                length,
                inner: slice,
            }),
            Err(err) => Err(err),
        }
    }

    /// Borrow the inner byte slice
    pub fn as_slice(&self) -> &'a [u8] {
        self.inner
    }

    /// Get the [`Length`] of this [`BytesRef`]
    pub fn len(self) -> Length {
        self.length
    }

    /// Is this [`BytesRef`] empty?
    pub fn is_empty(self) -> bool {
        self.len() == Length::ZERO
    }

    /// Get a prefix of a [`BytesRef`] of the given length.
    pub fn prefix(self, length: Length) -> Result<Self> {
        let inner = self
            .as_slice()
            .get(..usize::try_from(length)?)
            .ok_or_else(|| Error::incomplete(self.length))?;

        Ok(Self { length, inner })
    }
}

impl AsRef<[u8]> for BytesRef<'_> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a> DecodeValue<'a> for BytesRef<'a> {
    type Error = Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        if header.length.is_indefinite() && !header.tag.is_constructed() {
            return Err(reader.error(ErrorKind::IndefiniteLength));
        }

        reader.read_slice(header.length).and_then(Self::new)
    }
}

impl EncodeValue for BytesRef<'_> {
    fn value_len(&self) -> Result<Length> {
        Ok(self.length)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        writer.write(self.as_ref())
    }
}

impl Default for BytesRef<'_> {
    fn default() -> Self {
        Self {
            length: Length::ZERO,
            inner: &[],
        }
    }
}

impl DerOrd for BytesRef<'_> {
    fn der_cmp(&self, other: &Self) -> Result<Ordering> {
        Ok(self.as_slice().cmp(other.as_slice()))
    }
}

impl<'a> From<StringRef<'a>> for BytesRef<'a> {
    fn from(s: StringRef<'a>) -> BytesRef<'a> {
        let bytes = s.as_bytes();
        debug_assert_eq!(bytes.len(), usize::try_from(s.length).expect("overflow"));

        BytesRef {
            inner: bytes,
            length: s.length,
        }
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<&'a StringOwned> for BytesRef<'a> {
    fn from(s: &'a StringOwned) -> BytesRef<'a> {
        let bytes = s.as_bytes();
        debug_assert_eq!(bytes.len(), usize::try_from(s.length).expect("overflow"));

        BytesRef {
            inner: bytes,
            length: s.length,
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for BytesRef<'a> {
    type Error = Error;

    fn try_from(slice: &'a [u8]) -> Result<Self> {
        Self::new(slice)
    }
}

// Implement by hand because the derive would create invalid values.
// Make sure the length and the inner.len matches.
#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for BytesRef<'a> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let length = u.arbitrary()?;
        Ok(Self {
            length,
            inner: u.bytes(u32::from(length) as usize)?,
        })
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        arbitrary::size_hint::and(Length::size_hint(depth), (0, None))
    }
}

#[cfg(feature = "alloc")]
pub(crate) mod allocating {
    use super::BytesRef;
    use crate::{
        DecodeValue, DerOrd, EncodeValue, Error, Header, Length, Reader, Result, StringRef, Writer,
        length::indefinite::read_constructed_vec,
        referenced::{OwnedToRef, RefToOwned},
    };
    use alloc::{boxed::Box, vec::Vec};
    use core::cmp::Ordering;

    /// Byte slice newtype which respects the `Length::max()` limit.
    #[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
    pub(crate) struct BytesOwned {
        /// Precomputed `Length` (avoids possible panicking conversions)
        length: Length,

        /// Inner value
        inner: Box<[u8]>,
    }

    impl BytesOwned {
        /// Create a new [`BytesOwned`], ensuring that the provided `slice` value
        /// is shorter than `Length::max()`.
        pub fn new(data: impl Into<Box<[u8]>>) -> Result<Self> {
            let inner: Box<[u8]> = data.into();

            Ok(Self {
                length: Length::try_from(inner.len())?,
                inner,
            })
        }

        /// Borrow the inner byte slice
        pub const fn as_slice(&self) -> &[u8] {
            &self.inner
        }

        /// Get the [`Length`] of this [`BytesRef`]
        pub const fn len(&self) -> Length {
            self.length
        }

        /// Is this [`BytesOwned`] empty?
        pub const fn is_empty(&self) -> bool {
            self.len().is_zero()
        }

        /// Create [`BytesRef`] from allocated [`BytesOwned`].
        pub const fn to_ref(&self) -> BytesRef<'_> {
            BytesRef {
                length: self.length,
                inner: &self.inner,
            }
        }
    }

    impl AsRef<[u8]> for BytesOwned {
        fn as_ref(&self) -> &[u8] {
            self.as_slice()
        }
    }

    impl<'a> DecodeValue<'a> for BytesOwned {
        type Error = Error;

        fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
            // Reassemble indefinite length string types
            if header.length.is_indefinite() && !header.tag.is_constructed() {
                return Self::new(read_constructed_vec(reader, header)?);
            }

            reader.read_vec(header.length).and_then(Self::new)
        }
    }

    impl EncodeValue for BytesOwned {
        fn value_len(&self) -> Result<Length> {
            Ok(self.length)
        }

        fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
            writer.write(self.as_ref())
        }
    }

    impl Default for BytesOwned {
        fn default() -> Self {
            Self {
                length: Length::ZERO,
                inner: Box::new([]),
            }
        }
    }

    impl DerOrd for BytesOwned {
        fn der_cmp(&self, other: &Self) -> Result<Ordering> {
            Ok(self.as_slice().cmp(other.as_slice()))
        }
    }

    impl From<BytesOwned> for Box<[u8]> {
        fn from(bytes: BytesOwned) -> Box<[u8]> {
            bytes.inner
        }
    }

    impl From<StringRef<'_>> for BytesOwned {
        fn from(s: StringRef<'_>) -> BytesOwned {
            let bytes = s.as_bytes();
            debug_assert_eq!(bytes.len(), usize::try_from(s.length).expect("overflow"));

            BytesOwned {
                inner: Box::from(bytes),
                length: s.length,
            }
        }
    }

    impl OwnedToRef for BytesOwned {
        type Borrowed<'a> = BytesRef<'a>;
        fn owned_to_ref(&self) -> Self::Borrowed<'_> {
            BytesRef {
                length: self.length,
                inner: self.inner.as_ref(),
            }
        }
    }

    impl<'a> RefToOwned<'a> for BytesRef<'a> {
        type Owned = BytesOwned;
        fn ref_to_owned(&self) -> Self::Owned {
            BytesOwned::from(*self)
        }
    }

    impl From<BytesRef<'_>> for BytesOwned {
        fn from(s: BytesRef<'_>) -> BytesOwned {
            BytesOwned {
                length: s.length,
                inner: Box::from(s.inner),
            }
        }
    }

    impl TryFrom<&[u8]> for BytesOwned {
        type Error = Error;

        fn try_from(bytes: &[u8]) -> Result<Self> {
            Self::new(bytes)
        }
    }

    impl TryFrom<Box<[u8]>> for BytesOwned {
        type Error = Error;

        fn try_from(bytes: Box<[u8]>) -> Result<Self> {
            Self::new(bytes)
        }
    }

    impl TryFrom<Vec<u8>> for BytesOwned {
        type Error = Error;

        fn try_from(bytes: Vec<u8>) -> Result<Self> {
            Self::new(bytes)
        }
    }

    // Implement by hand because the derive would create invalid values.
    // Make sure the length and the inner.len matches.
    #[cfg(feature = "arbitrary")]
    impl<'a> arbitrary::Arbitrary<'a> for BytesOwned {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            let length = u.arbitrary()?;
            Ok(Self {
                length,
                inner: Box::from(u.bytes(u32::from(length) as usize)?),
            })
        }

        fn size_hint(depth: usize) -> (usize, Option<usize>) {
            arbitrary::size_hint::and(Length::size_hint(depth), (0, None))
        }
    }
}
