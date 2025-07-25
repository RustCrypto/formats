//! ASN.1 `PrintableString` support.

use crate::{FixedTag, Result, StringRef, Tag, asn1::AnyRef};
use core::{fmt, ops::Deref};

macro_rules! impl_printable_string {
    ($type: ty) => {
        impl_printable_string!($type,);
    };
    ($type: ty, $($li: lifetime)?) => {
        impl_string_type!($type, $($li),*);

        impl<$($li),*> FixedTag for $type {
            const TAG: Tag = Tag::PrintableString;
        }

        impl<$($li),*> fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "PrintableString({:?})", self.as_str())
            }
        }
    };
}

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
    inner: &'a StringRef,
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
                _ => return Err(Self::TAG.value_error().into()),
            }
        }

        StringRef::from_bytes(input)
            .map(|inner| Self { inner })
            .map_err(|_| Self::TAG.value_error().into())
    }

    /// Borrow the inner `str`.
    pub fn as_str(&self) -> &'a str {
        self.inner.as_str()
    }
}

impl_printable_string!(PrintableStringRef<'a>, 'a);

impl<'a> Deref for PrintableStringRef<'a> {
    type Target = StringRef;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}
impl<'a> From<&PrintableStringRef<'a>> for PrintableStringRef<'a> {
    fn from(value: &PrintableStringRef<'a>) -> PrintableStringRef<'a> {
        *value
    }
}

impl<'a> From<PrintableStringRef<'a>> for AnyRef<'a> {
    fn from(printable_string: PrintableStringRef<'a>) -> AnyRef<'a> {
        AnyRef::from_tag_and_value(Tag::PrintableString, printable_string.inner.as_ref())
    }
}

#[cfg(feature = "alloc")]
pub use self::allocation::PrintableString;

#[cfg(feature = "alloc")]
mod allocation {
    use super::PrintableStringRef;

    use crate::{
        BytesRef, Error, FixedTag, Result, StringOwned, Tag,
        asn1::AnyRef,
        referenced::{OwnedToRef, RefToOwned},
    };
    use alloc::{borrow::ToOwned, string::String};
    use core::{fmt, ops::Deref};

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
        inner: StringOwned,
    }

    impl PrintableString {
        /// Create a new ASN.1 `PrintableString`.
        pub fn new<T>(input: &T) -> Result<Self>
        where
            T: AsRef<[u8]> + ?Sized,
        {
            let input = input.as_ref();
            PrintableStringRef::new(input)?;

            StringOwned::from_bytes(input)
                .map(|inner| Self { inner })
                .map_err(|_| Self::TAG.value_error().into())
        }
    }

    impl_printable_string!(PrintableString);

    impl Deref for PrintableString {
        type Target = StringOwned;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl<'a> From<PrintableStringRef<'a>> for PrintableString {
        fn from(value: PrintableStringRef<'a>) -> PrintableString {
            let inner =
                StringOwned::from_bytes(value.inner.as_bytes()).expect("Invalid PrintableString");
            Self { inner }
        }
    }

    impl<'a> From<&'a PrintableString> for AnyRef<'a> {
        fn from(printable_string: &'a PrintableString) -> AnyRef<'a> {
            AnyRef::from_tag_and_value(
                Tag::PrintableString,
                BytesRef::new(printable_string.inner.as_bytes()).expect("Invalid PrintableString"),
            )
        }
    }

    impl<'a> From<&'a PrintableString> for PrintableStringRef<'a> {
        fn from(printable_string: &'a PrintableString) -> PrintableStringRef<'a> {
            printable_string.owned_to_ref()
        }
    }

    impl<'a> RefToOwned<'a> for PrintableStringRef<'a> {
        type Owned = PrintableString;
        fn ref_to_owned(&self) -> Self::Owned {
            PrintableString {
                inner: self.inner.to_owned(),
            }
        }
    }

    impl OwnedToRef for PrintableString {
        type Borrowed<'a> = PrintableStringRef<'a>;
        fn owned_to_ref(&self) -> Self::Borrowed<'_> {
            PrintableStringRef {
                inner: self.inner.as_ref(),
            }
        }
    }

    impl TryFrom<String> for PrintableString {
        type Error = Error;

        fn try_from(input: String) -> Result<Self> {
            PrintableStringRef::new(&input)?;

            StringOwned::new(input)
                .map(|inner| Self { inner })
                .map_err(|_| Self::TAG.value_error().into())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
