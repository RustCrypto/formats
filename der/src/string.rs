//! Common handling for types backed by `str` slices with enforcement of a
//! library-level length limitation i.e. `Length::max()`.

use crate::{BytesRef, DecodeValue, EncodeValue, Error, Header, Length, Reader, Result, Writer};
use core::str;

/// String slice newtype which respects the [`Length::max`] limit.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct StringRef<'a> {
    /// Inner value
    pub(crate) inner: &'a str,

    /// Precomputed `Length` (avoids possible panicking conversions)
    pub(crate) length: Length,
}

impl<'a> StringRef<'a> {
    /// Create a new [`StringRef`], ensuring that the byte representation of
    /// the provided `str` value is shorter than `Length::max()`.
    pub fn new(s: &'a str) -> Result<Self> {
        Ok(Self {
            inner: s,
            length: Length::try_from(s.len())?,
        })
    }

    /// Parse a [`StringRef`] from UTF-8 encoded bytes.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        Self::new(str::from_utf8(bytes)?)
    }

    /// Borrow the inner `str`
    pub fn as_str(&self) -> &'a str {
        self.inner
    }

    /// Borrow the inner byte slice
    pub fn as_bytes(&self) -> &'a [u8] {
        self.inner.as_bytes()
    }

    /// Get the [`Length`] of this [`StringRef`]
    pub fn len(self) -> Length {
        self.length
    }

    /// Is this [`StringRef`] empty?
    pub fn is_empty(self) -> bool {
        self.len() == Length::ZERO
    }
}

impl AsRef<str> for StringRef<'_> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for StringRef<'_> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a> DecodeValue<'a> for StringRef<'a> {
    type Error = Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        Self::from_bytes(BytesRef::decode_value(reader, header)?.as_slice())
    }
}

impl EncodeValue for StringRef<'_> {
    fn value_len(&self) -> Result<Length> {
        Ok(self.length)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        writer.write(self.as_ref())
    }
}

#[cfg(feature = "alloc")]
pub(crate) mod allocating {
    use super::StringRef;
    use crate::referenced::RefToOwned;
    use crate::{
        BytesRef, DecodeValue, EncodeValue, Error, Header, Length, Reader, Result, Writer,
        referenced::OwnedToRef,
    };
    use alloc::string::String;
    use core::str;

    /// String newtype which respects the [`Length::max`] limit.
    #[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
    pub struct StringOwned {
        /// Inner value
        pub(crate) inner: String,

        /// Precomputed `Length` (avoids possible panicking conversions)
        pub(crate) length: Length,
    }

    impl StringOwned {
        /// Create a new [`StringOwned`], ensuring that the byte representation of
        /// the provided `str` value is shorter than `Length::max()`.
        pub fn new(s: String) -> Result<Self> {
            let length = Length::try_from(s.len())?;

            Ok(Self { inner: s, length })
        }

        /// Parse a [`String`] from UTF-8 encoded bytes.
        pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
            Ok(Self {
                inner: String::from_utf8(bytes.to_vec())?,
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

        /// Get the [`Length`] of this [`StringOwned`]
        pub fn len(&self) -> Length {
            self.length
        }

        /// Is this [`StringOwned`] empty?
        pub fn is_empty(&self) -> bool {
            self.len() == Length::ZERO
        }
    }

    impl AsRef<str> for StringOwned {
        fn as_ref(&self) -> &str {
            self.as_str()
        }
    }

    impl AsRef<[u8]> for StringOwned {
        fn as_ref(&self) -> &[u8] {
            self.as_bytes()
        }
    }

    impl<'a> DecodeValue<'a> for StringOwned {
        type Error = Error;

        fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
            Self::from_bytes(BytesRef::decode_value(reader, header)?.as_slice())
        }
    }

    impl EncodeValue for StringOwned {
        fn value_len(&self) -> Result<Length> {
            Ok(self.length)
        }

        fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
            writer.write(self.as_ref())
        }
    }

    impl From<StringRef<'_>> for StringOwned {
        fn from(s: StringRef<'_>) -> StringOwned {
            Self {
                inner: String::from(s.inner),
                length: s.length,
            }
        }
    }

    impl OwnedToRef for StringOwned {
        type Borrowed<'a> = StringRef<'a>;
        fn owned_to_ref(&self) -> Self::Borrowed<'_> {
            StringRef {
                length: self.length,
                inner: self.inner.as_ref(),
            }
        }
    }

    impl<'a> RefToOwned<'a> for StringRef<'a> {
        type Owned = StringOwned;
        fn ref_to_owned(&self) -> Self::Owned {
            StringOwned::from(*self)
        }
    }
}
