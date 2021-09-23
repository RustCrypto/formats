//! Context-specific field.

use crate::{
    asn1::Any, ByteSlice, Choice, Encodable, Encoder, Error, Length, Result, Tag, TagNumber, Tagged,
};
use core::convert::TryFrom;

/// Context-specific field.
///
/// This type encodes a field which is specific to a particular context,
/// and is identified by a [`TagNumber`].
///
/// Any context-specific field can be decoded/encoded with this type.
/// The intended use is to dynamically dispatch off of the context-specific
/// tag number when decoding, which allows support for extensions, which are
/// denoted in an ASN.1 schema using the `...` ellipsis extension marker.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct ContextSpecific<'a> {
    /// Context-specific tag number sans the leading `0b10000000` class
    /// identifier bit and `0b100000` constructed flag.
    tag_number: TagNumber,

    /// Is the inner value constructed? (i.e. was the constructed bit set?)
    constructed: bool,

    /// Value of the field.
    value: ByteSlice<'a>,
}

impl<'a> ContextSpecific<'a> {
    /// Create a new [`ContextSpecific`] field with the given tag number,
    /// constructed bit, and value.
    pub fn new(tag_number: TagNumber, constructed: bool, value: &'a [u8]) -> Result<Self> {
        Ok(Self {
            tag_number,
            constructed,
            value: ByteSlice::new(value)?,
        })
    }

    /// Get the tag used to encode this [`ContextSpecific`] field.
    pub fn tag(self) -> Tag {
        Tag::ContextSpecific {
            constructed: self.constructed,
            number: self.tag_number,
        }
    }

    /// Get the tag number (lower 6-bits of the tag)
    pub fn tag_number(self) -> TagNumber {
        self.tag_number
    }

    /// Is the inner [`ContextSpecific`] value constructed (as opposed to primitive)?
    ///
    /// This maps to whether the inner type is constructed or primitive.
    pub fn constructed(self) -> bool {
        self.constructed
    }

    /// Get the [`Length`] of this [`ContextSpecific`] type's value.
    pub fn len(self) -> Length {
        self.value.len()
    }

    /// Is the value of this [`ContextSpecific`] type empty?
    pub fn is_empty(self) -> bool {
        self.value.is_empty()
    }

    /// Get the raw value for this [`ContextSpecific`] type as a byte slice.
    pub fn value(self) -> &'a [u8] {
        self.value.as_bytes()
    }

    /// Attempt to decode this [`ContextSpecific`] field as the given type.
    pub fn decode_value<D>(self) -> Result<D>
    where
        D: TryFrom<Any<'a>, Error = Error> + Tagged, // TODO(tarcieri): support `Decode`
    {
        D::try_from(Any::new(D::TAG, self.value.as_bytes())?)
    }
}

impl<'a> Choice<'a> for ContextSpecific<'a> {
    fn can_decode(tag: Tag) -> bool {
        matches!(tag, Tag::ContextSpecific { .. })
    }
}

impl<'a> Encodable for ContextSpecific<'a> {
    fn encoded_len(&self) -> Result<Length> {
        Any::from(*self).encoded_len()
    }

    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        Any::from(*self).encode(encoder)
    }
}

impl<'a> From<&ContextSpecific<'a>> for ContextSpecific<'a> {
    fn from(value: &ContextSpecific<'a>) -> ContextSpecific<'a> {
        *value
    }
}

impl<'a> From<ContextSpecific<'a>> for Any<'a> {
    fn from(context_specific: ContextSpecific<'a>) -> Any<'a> {
        Any::from_tag_and_value(context_specific.tag(), context_specific.value)
    }
}

impl<'a> TryFrom<Any<'a>> for ContextSpecific<'a> {
    type Error = Error;

    fn try_from(any: Any<'a>) -> Result<ContextSpecific<'a>> {
        match any.tag() {
            Tag::ContextSpecific {
                constructed,
                number,
            } => Ok(Self {
                tag_number: number,
                constructed,
                value: any.value,
            }),
            tag => Err(tag.unexpected_error(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ContextSpecific;
    use crate::{asn1::BitString, Decodable, Encodable};
    use hex_literal::hex;

    /// Test vector from RFC8410 Section 10.3:
    /// <https://datatracker.ietf.org/doc/html/rfc8410#section-10.3>
    ///
    /// ```text
    ///    81  33:   [1] 00 19 BF 44 09 69 84 CD FE 85 41 BA C1 67 DC 3B
    ///                  96 C8 50 86 AA 30 B6 B6 CB 0C 5C 38 AD 70 31 66
    ///                  E1
    /// ```
    const EXAMPLE_BYTES: &[u8] =
        &hex!("81210019BF44096984CDFE8541BAC167DC3B96C85086AA30B6B6CB0C5C38AD703166E1");

    #[test]
    fn round_trip() {
        let field = ContextSpecific::from_der(EXAMPLE_BYTES).unwrap();
        assert_eq!(field.tag_number.value(), 1);
        assert!(!field.constructed);
        assert_eq!(field.value.as_bytes(), &EXAMPLE_BYTES[2..]);

        let value = field.decode_value::<BitString<'_>>().unwrap();
        assert_eq!(value.as_bytes(), &EXAMPLE_BYTES[3..]);

        let mut buf = [0u8; 128];
        let encoded = field.encode_to_slice(&mut buf).unwrap();
        assert_eq!(encoded, EXAMPLE_BYTES);
    }
}
