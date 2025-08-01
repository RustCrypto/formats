//! ASN.1 `VideotexString` support.

use crate::{FixedTag, Result, StringRef, Tag, asn1::AnyRef};
use core::{fmt, ops::Deref};

/// ASN.1 `VideotexString` type.
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
/// For the practical purposes VideotexString is treated as IA5string, disallowing non-ASCII chars.
///
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct VideotexStringRef<'a> {
    /// Inner value
    inner: &'a StringRef,
}

impl<'a> VideotexStringRef<'a> {
    /// Create a new ASN.1 `VideotexString`.
    pub fn new<T>(input: &'a T) -> Result<Self>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        let input = input.as_ref();

        // Validate all characters are within VideotexString's allowed set
        // FIXME: treat as if it were IA5String
        if input.iter().any(|&c| c > 0x7F) {
            return Err(Self::TAG.value_error().into());
        }

        StringRef::from_bytes(input)
            .map(|inner| Self { inner })
            .map_err(|_| Self::TAG.value_error().into())
    }
}

impl_string_type!(VideotexStringRef<'a>, 'a);

impl<'a> Deref for VideotexStringRef<'a> {
    type Target = StringRef;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl FixedTag for VideotexStringRef<'_> {
    const TAG: Tag = Tag::VideotexString;
}

impl<'a> From<&VideotexStringRef<'a>> for VideotexStringRef<'a> {
    fn from(value: &VideotexStringRef<'a>) -> VideotexStringRef<'a> {
        *value
    }
}

impl<'a> From<VideotexStringRef<'a>> for AnyRef<'a> {
    fn from(videotex_string: VideotexStringRef<'a>) -> AnyRef<'a> {
        AnyRef::from_tag_and_value(Tag::VideotexString, videotex_string.inner.as_ref())
    }
}

impl<'a> From<VideotexStringRef<'a>> for &'a [u8] {
    fn from(videotex_string: VideotexStringRef<'a>) -> &'a [u8] {
        videotex_string.inner.as_bytes()
    }
}

impl fmt::Debug for VideotexStringRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VideotexString({:?})", self.as_str())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::VideotexStringRef;
    use crate::Decode;

    #[test]
    fn parse_bytes() {
        let example_bytes = &[
            0x15, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x65, 0x72, 0x20, 0x31,
        ];

        let videotex_string = VideotexStringRef::from_der(example_bytes).unwrap();
        assert_eq!(videotex_string.as_str(), "Test User 1");
    }
}
