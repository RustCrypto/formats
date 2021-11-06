//! ASN.1 `OCTET STRING` support.

use crate::{
    asn1::Any, ByteSlice, DecodeValue, Decoder, EncodeValue, Encoder, Error, ErrorKind, FixedTag,
    Length, Result, Tag,
};

/// ASN.1 `OCTET STRING` type.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct OctetString<'a> {
    /// Inner value
    inner: ByteSlice<'a>,
}

impl<'a> OctetString<'a> {
    /// Create a new ASN.1 `OCTET STRING` from a byte slice.
    pub fn new(slice: &'a [u8]) -> Result<Self> {
        ByteSlice::new(slice)
            .map(|inner| Self { inner })
            .map_err(|_| ErrorKind::Length { tag: Self::TAG }.into())
    }

    /// Borrow the inner byte slice.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.inner.as_bytes()
    }

    /// Get the length of the inner byte slice.
    pub fn len(&self) -> Length {
        self.inner.len()
    }

    /// Is the inner byte slice empty?
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl AsRef<[u8]> for OctetString<'_> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a> DecodeValue<'a> for OctetString<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, length: Length) -> Result<Self> {
        Ok(Self {
            inner: ByteSlice::decode_value(decoder, length)?,
        })
    }
}

impl<'a> EncodeValue for OctetString<'a> {
    fn value_len(&self) -> Result<Length> {
        self.inner.value_len()
    }

    fn encode_value(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        self.inner.encode_value(encoder)
    }
}

impl<'a> From<&OctetString<'a>> for OctetString<'a> {
    fn from(value: &OctetString<'a>) -> OctetString<'a> {
        *value
    }
}

impl<'a> TryFrom<Any<'a>> for OctetString<'a> {
    type Error = Error;

    fn try_from(any: Any<'a>) -> Result<OctetString<'a>> {
        any.decode_into()
    }
}

impl<'a> From<OctetString<'a>> for Any<'a> {
    fn from(octet_string: OctetString<'a>) -> Any<'a> {
        Any::from_tag_and_value(Tag::OctetString, octet_string.inner)
    }
}

impl<'a> From<OctetString<'a>> for &'a [u8] {
    fn from(octet_string: OctetString<'a>) -> &'a [u8] {
        octet_string.as_bytes()
    }
}

impl<'a> FixedTag for OctetString<'a> {
    const TAG: Tag = Tag::OctetString;
}
