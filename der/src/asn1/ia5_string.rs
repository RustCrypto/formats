//! ASN.1 `IA5String` support.

use crate::{
    asn1::AnyRef, ord::OrdIsValueOrd, BytesRef, DecodeValue, EncodeValue, Error, FixedTag, Header,
    Length, Reader, Result, StrRef, Tag, Writer,
};
use core::{fmt, ops::Deref, str};

#[cfg(feature = "alloc")]
use crate::asn1::Any;

macro_rules! impl_ia5_string {
    ($type: ty) => {
        impl_ia5_string!($type,);
    };
    ($type: ty, $($li: lifetime)?) => {
        impl<$($li),*> AsRef<str> for $type {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl<$($li),*> AsRef<[u8]> for $type {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }

        impl<'__der: $($li),*, $($li),*> DecodeValue<'__der> for $type {
            fn decode_value<R: Reader<'__der>>(reader: &mut R, header: Header) -> Result<Self> {
                Self::new(BytesRef::decode_value(reader, header)?.as_slice())
            }
        }

        impl<$($li),*> EncodeValue for $type {
            fn value_len(&self) -> Result<Length> {
                self.inner.value_len()
            }

            fn encode_value(&self, writer: &mut dyn Writer) -> Result<()> {
                self.inner.encode_value(writer)
            }
        }

        impl<$($li),*> FixedTag for $type {
            const TAG: Tag = Tag::Ia5String;
        }

        impl<$($li),*> OrdIsValueOrd for $type {}

        impl<'__der: $($li),*, $($li),*> TryFrom<AnyRef<'__der>> for $type {
            type Error = Error;

            fn try_from(any: AnyRef<'__der>) -> Result<$type> {
                any.decode_into()
            }
        }

        #[cfg(feature = "alloc")]
        impl<'__der: $($li),*, $($li),*> TryFrom<&'__der Any> for $type {
            type Error = Error;

            fn try_from(any: &'__der Any) -> Result<$type> {
                any.decode_into()
            }
        }

        impl<$($li),*> fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl<$($li),*> fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "Ia5String({:?})", self.as_str())
            }
        }
    };
}

/// ASN.1 `IA5String` type.
///
/// Supports the [International Alphabet No. 5 (IA5)] character encoding, i.e.
/// the lower 128 characters of the ASCII alphabet. (Note: IA5 is now
/// technically known as the International Reference Alphabet or IRA as
/// specified in the ITU-T's T.50 recommendation).
///
/// For UTF-8, use [`Utf8StringRef`][`crate::asn1::Utf8StringRef`].
///
/// This is a zero-copy reference type which borrows from the input data.
///
/// [International Alphabet No. 5 (IA5)]: https://en.wikipedia.org/wiki/T.50_%28standard%29
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct Ia5StringRef<'a> {
    /// Inner value
    inner: StrRef<'a>,
}

impl<'a> Ia5StringRef<'a> {
    /// Create a new `IA5String`.
    pub fn new<T>(input: &'a T) -> Result<Self>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        let input = input.as_ref();

        // Validate all characters are within IA5String's allowed set
        if input.iter().any(|&c| c > 0x7F) {
            return Err(Self::TAG.value_error());
        }

        StrRef::from_bytes(input)
            .map(|inner| Self { inner })
            .map_err(|_| Self::TAG.value_error())
    }
}

impl_ia5_string!(Ia5StringRef<'a>, 'a);

impl<'a> Deref for Ia5StringRef<'a> {
    type Target = StrRef<'a>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a> From<&Ia5StringRef<'a>> for Ia5StringRef<'a> {
    fn from(value: &Ia5StringRef<'a>) -> Ia5StringRef<'a> {
        *value
    }
}

impl<'a> From<Ia5StringRef<'a>> for AnyRef<'a> {
    fn from(internationalized_string: Ia5StringRef<'a>) -> AnyRef<'a> {
        AnyRef::from_tag_and_value(Tag::Ia5String, internationalized_string.inner.into())
    }
}

#[cfg(feature = "alloc")]
pub use self::allocation::Ia5String;

#[cfg(feature = "alloc")]
mod allocation {
    use super::Ia5StringRef;
    use crate::{
        asn1::{Any, AnyRef},
        ord::OrdIsValueOrd,
        referenced::{OwnedToRef, RefToOwned},
        BytesRef, DecodeValue, EncodeValue, Error, FixedTag, Header, Length, Reader, Result,
        StrOwned, Tag, Writer,
    };
    use core::{fmt, ops::Deref, str};

    /// ASN.1 `IA5String` type.
    ///
    /// Supports the [International Alphabet No. 5 (IA5)] character encoding, i.e.
    /// the lower 128 characters of the ASCII alphabet. (Note: IA5 is now
    /// technically known as the International Reference Alphabet or IRA as
    /// specified in the ITU-T's T.50 recommendation).
    ///
    /// For UTF-8, use [`String`][`alloc::string::String`].
    ///
    /// [International Alphabet No. 5 (IA5)]: https://en.wikipedia.org/wiki/T.50_%28standard%29
    #[derive(Clone, Eq, PartialEq, PartialOrd, Ord)]
    pub struct Ia5String {
        /// Inner value
        inner: StrOwned,
    }

    impl Ia5String {
        /// Create a new `IA5String`.
        pub fn new<T>(input: &T) -> Result<Self>
        where
            T: AsRef<[u8]> + ?Sized,
        {
            let input = input.as_ref();
            Ia5StringRef::new(input)?;

            StrOwned::from_bytes(input)
                .map(|inner| Self { inner })
                .map_err(|_| Self::TAG.value_error())
        }
    }

    impl_ia5_string!(Ia5String);

    impl Deref for Ia5String {
        type Target = StrOwned;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl<'a> From<Ia5StringRef<'a>> for Ia5String {
        fn from(international_string: Ia5StringRef<'a>) -> Ia5String {
            let inner = international_string.inner.into();
            Self { inner }
        }
    }

    impl<'a> From<&'a Ia5String> for AnyRef<'a> {
        fn from(international_string: &'a Ia5String) -> AnyRef<'a> {
            AnyRef::from_tag_and_value(Tag::Ia5String, (&international_string.inner).into())
        }
    }

    impl<'a> RefToOwned<'a> for Ia5StringRef<'a> {
        type Owned = Ia5String;
        fn to_owned(&self) -> Self::Owned {
            Ia5String {
                inner: self.inner.to_owned(),
            }
        }
    }

    impl OwnedToRef for Ia5String {
        type Borrowed<'a> = Ia5StringRef<'a>;
        fn to_ref(&self) -> Self::Borrowed<'_> {
            Ia5StringRef {
                inner: self.inner.to_ref(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Ia5StringRef;
    use crate::Decode;
    use hex_literal::hex;

    #[test]
    fn parse_bytes() {
        let example_bytes = hex!("16 0d 74 65 73 74 31 40 72 73 61 2e 63 6f 6d");
        let internationalized_string = Ia5StringRef::from_der(&example_bytes).unwrap();
        assert_eq!(internationalized_string.as_str(), "test1@rsa.com");
    }
}
