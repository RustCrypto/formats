//! `data` content type [RFC 2315 § 8](https://datatracker.ietf.org/doc/html/rfc2315#section-8)

use core::convert::{From, TryFrom};
use der::{asn1::OctetString, DecodeValue, Decoder, EncodeValue, Encoder, Length, Tag, Tagged};

/// The content that is just an octet string.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DataContent<'a> {
    /// content bytes
    pub content: &'a [u8],
}

impl AsRef<[u8]> for DataContent<'_> {
    fn as_ref(&self) -> &[u8] {
        self.content
    }
}

impl<'a> From<&'a [u8]> for DataContent<'a> {
    fn from(bytes: &'a [u8]) -> DataContent<'a> {
        DataContent { content: bytes }
    }
}

impl<'a> From<DataContent<'a>> for &'a [u8] {
    fn from(data: DataContent<'a>) -> &'a [u8] {
        data.content
    }
}

impl<'a> DecodeValue<'a> for DataContent<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, length: Length) -> der::Result<DataContent<'a>> {
        Ok(OctetString::decode_value(decoder, length)?
            .as_bytes()
            .into())
    }
}

impl<'a> EncodeValue for DataContent<'a> {
    fn value_len(&self) -> der::Result<Length> {
        Length::try_from(self.content.len())
    }

    fn encode_value(&self, encoder: &mut Encoder<'_>) -> der::Result<()> {
        OctetString::new(self.content)?.encode_value(encoder)
    }
}

impl<'a> Tagged for DataContent<'a> {
    const TAG: Tag = Tag::OctetString;
}
