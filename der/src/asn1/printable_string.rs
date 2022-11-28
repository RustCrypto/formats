//! ASN.1 `PrintableString` support.

use crate::{
    asn1::AnyRef, ord::OrdIsValueOrd, ByteSlice, DecodeValue, EncodeValue, Error, FixedTag, Header,
    Length, Reader, Result, StrSlice, Tag, Writer,
};
use core::{fmt, ops::Deref, str};

#[cfg(feature = "alloc")]
use crate::asn1::Any;

/// ASN.1 `PrintableString` type.
///
/// Supports a subset the ASCII character set (described below).
///
/// For UTF-8, use [`Utf8StringRef`][`crate::asn1::Utf8StringRef`] instead.
/// For the full ASCII character set, use
/// [`Ia5StringRef`][`crate::asn1::Ia5StringRef`].
///
/// This is a zero-copy reference type which borrows from the input data.
///
/// # Supported characters
///
/// The following ASCII characters/ranges are supported:
///
/// - `A..Z`
/// - `a..z`
/// - `0..9`
/// - "` `" (i.e. space)
/// - `\`
/// - `(`
/// - `)`
/// - `+`
/// - `,`
/// - `-`
/// - `.`
/// - `/`
/// - `:`
/// - `=`
/// - `?`
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct PrintableStringRef<'a> {
    /// Inner value
    inner: StrSlice<'a>,
}

impl<'a> PrintableStringRef<'a> {
    /// Create a new ASN.1 `PrintableString`.
    pub fn new<T>(input: &'a T) -> Result<Self>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        let input = input.as_ref();

        // Validate all characters are within PrintableString's allowed set
        for &c in input.iter() {
            match c {
                b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b' '
                | b'\''
                | b'('
                | b')'
                | b'+'
                | b','
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b'='
                | b'?' => (),
                _ => return Err(Self::TAG.value_error()),
            }
        }

        StrSlice::from_bytes(input)
            .map(|inner| Self { inner })
            .map_err(|_| Self::TAG.value_error())
    }
}

impl<'a> Deref for PrintableStringRef<'a> {
    type Target = StrSlice<'a>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AsRef<str> for PrintableStringRef<'_> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for PrintableStringRef<'_> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a> DecodeValue<'a> for PrintableStringRef<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        Self::new(ByteSlice::decode_value(reader, header)?.as_slice())
    }
}

impl<'a> EncodeValue for PrintableStringRef<'a> {
    fn value_len(&self) -> Result<Length> {
        self.inner.value_len()
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> Result<()> {
        self.inner.encode_value(writer)
    }
}

impl FixedTag for PrintableStringRef<'_> {
    const TAG: Tag = Tag::PrintableString;
}

impl OrdIsValueOrd for PrintableStringRef<'_> {}

impl<'a> From<&PrintableStringRef<'a>> for PrintableStringRef<'a> {
    fn from(value: &PrintableStringRef<'a>) -> PrintableStringRef<'a> {
        *value
    }
}

impl<'a> TryFrom<AnyRef<'a>> for PrintableStringRef<'a> {
    type Error = Error;

    fn try_from(any: AnyRef<'a>) -> Result<PrintableStringRef<'a>> {
        any.decode_into()
    }
}

#[cfg(feature = "alloc")]
impl<'a> TryFrom<&'a Any> for PrintableStringRef<'a> {
    type Error = Error;

    fn try_from(any: &'a Any) -> Result<PrintableStringRef<'a>> {
        any.decode_into()
    }
}

impl<'a> From<PrintableStringRef<'a>> for AnyRef<'a> {
    fn from(printable_string: PrintableStringRef<'a>) -> AnyRef<'a> {
        AnyRef::from_tag_and_value(Tag::PrintableString, printable_string.inner.into())
    }
}

impl<'a> fmt::Display for PrintableStringRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'a> fmt::Debug for PrintableStringRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrintableString({:?})", self.as_str())
    }
}

#[cfg(feature = "alloc")]
pub use self::allocation::PrintableString;

#[cfg(feature = "alloc")]
mod allocation {
    use super::PrintableStringRef;

    use crate::{
        asn1::{Any, AnyRef},
        ord::OrdIsValueOrd,
        referenced::{OwnedToRef, RefToOwned},
        ByteSlice, DecodeValue, EncodeValue, Error, FixedTag, Header, Length, Reader, Result,
        String, Tag, Writer,
    };
    use core::{fmt, ops::Deref, str};

    /// ASN.1 `PrintableString` type.
    ///
    /// Supports a subset the ASCII character set (described below).
    ///
    /// For UTF-8, use [`Utf8StringRef`][`crate::asn1::Utf8StringRef`] instead.
    /// For the full ASCII character set, use
    /// [`Ia5StringRef`][`crate::asn1::Ia5StringRef`].
    ///
    /// # Supported characters
    ///
    /// The following ASCII characters/ranges are supported:
    ///
    /// - `A..Z`
    /// - `a..z`
    /// - `0..9`
    /// - "` `" (i.e. space)
    /// - `\`
    /// - `(`
    /// - `)`
    /// - `+`
    /// - `,`
    /// - `-`
    /// - `.`
    /// - `/`
    /// - `:`
    /// - `=`
    /// - `?`
    #[derive(Clone, Eq, PartialEq, PartialOrd, Ord)]
    pub struct PrintableString {
        /// Inner value
        inner: String,
    }

    impl PrintableString {
        /// Create a new ASN.1 `PrintableString`.
        pub fn new<T>(input: &T) -> Result<Self>
        where
            T: AsRef<[u8]> + ?Sized,
        {
            let input = input.as_ref();
            PrintableStringRef::new(input)?;

            String::from_bytes(input)
                .map(|inner| Self { inner })
                .map_err(|_| Self::TAG.value_error())
        }
    }

    impl Deref for PrintableString {
        type Target = String;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl AsRef<str> for PrintableString {
        fn as_ref(&self) -> &str {
            self.as_str()
        }
    }

    impl AsRef<[u8]> for PrintableString {
        fn as_ref(&self) -> &[u8] {
            self.as_bytes()
        }
    }

    impl<'a> DecodeValue<'a> for PrintableString {
        fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
            Self::new(ByteSlice::decode_value(reader, header)?.as_slice())
        }
    }

    impl EncodeValue for PrintableString {
        fn value_len(&self) -> Result<Length> {
            self.inner.value_len()
        }

        fn encode_value(&self, writer: &mut dyn Writer) -> Result<()> {
            self.inner.encode_value(writer)
        }
    }

    impl FixedTag for PrintableString {
        const TAG: Tag = Tag::PrintableString;
    }

    impl OrdIsValueOrd for PrintableString {}

    impl<'a> From<PrintableStringRef<'a>> for PrintableString {
        fn from(value: PrintableStringRef<'a>) -> PrintableString {
            let inner =
                String::from_bytes(value.inner.as_bytes()).expect("Invalid PrintableString");
            Self { inner }
        }
    }

    impl<'a> TryFrom<&AnyRef<'a>> for PrintableString {
        type Error = Error;

        fn try_from(any: &AnyRef<'a>) -> Result<PrintableString> {
            (*any).decode_into()
        }
    }

    impl<'a> TryFrom<&'a Any> for PrintableString {
        type Error = Error;

        fn try_from(any: &'a Any) -> Result<PrintableString> {
            any.decode_into()
        }
    }

    impl<'a> From<&'a PrintableString> for AnyRef<'a> {
        fn from(printable_string: &'a PrintableString) -> AnyRef<'a> {
            AnyRef::from_tag_and_value(
                Tag::PrintableString,
                ByteSlice::new(printable_string.inner.as_bytes()).expect("Invalid PrintableString"),
            )
        }
    }

    impl fmt::Display for PrintableString {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.as_str())
        }
    }

    impl fmt::Debug for PrintableString {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "PrintableString({:?})", self.as_str())
        }
    }

    impl<'a> RefToOwned<'a> for PrintableStringRef<'a> {
        type Owned = PrintableString;
        fn to_owned(&self) -> Self::Owned {
            PrintableString {
                inner: self.inner.to_owned(),
            }
        }
    }

    impl OwnedToRef for PrintableString {
        type Borrowed<'a> = PrintableStringRef<'a>;
        fn to_ref(&self) -> Self::Borrowed<'_> {
            PrintableStringRef {
                inner: self.inner.to_ref(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PrintableStringRef;
    use crate::Decode;

    #[test]
    fn parse_bytes() {
        let example_bytes = &[
            0x13, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x65, 0x72, 0x20, 0x31,
        ];

        let printable_string = PrintableStringRef::from_der(example_bytes).unwrap();
        assert_eq!(printable_string.as_str(), "Test User 1");
    }
}
