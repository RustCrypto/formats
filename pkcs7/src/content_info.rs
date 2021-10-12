use crate::{ContentType, DataContent};

use der::{
    asn1::ContextSpecific, Decodable, Decoder, Encodable, ErrorKind, Message, TagMode, TagNumber,
};

const CONTENT_TAG: TagNumber = TagNumber::new(0);

/// Content exchanged between entities
pub enum ContentInfo<'a> {
    /// Content type `data`
    Data(Option<DataContent<'a>>),
}

impl<'a> ContentInfo<'a> {
    /// return content type of content info
    pub fn content_type(&self) -> ContentType {
        match self {
            Self::Data(_) => ContentType::Data,
        }
    }
}

impl<'a> ContentInfo<'a> {
    /// new ContentInfo of `data` content type
    pub fn new_data(content: &'a [u8]) -> Self {
        ContentInfo::Data(Some(content.into()))
    }
}

impl<'a> Decodable<'a> for ContentInfo<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<ContentInfo<'a>> {
        decoder.sequence(|decoder| {
            let content_type = decoder.decode()?;
            match content_type {
                ContentType::Data => Ok(ContentInfo::Data(
                    decoder.context_specific::<DataContent<'_>>(CONTENT_TAG, TagMode::Explicit)?,
                )),
                _ => {
                    // TODO: support remaining content types
                    Err(decoder.error(ErrorKind::Failed))
                }
            }
        })
    }
}

impl<'a> Message<'a> for ContentInfo<'a> {
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        match self {
            Self::Data(data) => f(&[
                &self.content_type(),
                &data.as_ref().map(|d| ContextSpecific {
                    tag_number: CONTENT_TAG,
                    tag_mode: TagMode::Explicit,
                    value: *d,
                }),
            ]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ContentInfo, DataContent};
    use core::convert::TryFrom;
    use der::{asn1::OctetString, Decodable, Encodable, Encoder, Length, TagMode, TagNumber};

    #[test]
    fn empty_data() -> der::Result<()> {
        let mut in_buf = [0u8; 32];

        let mut encoder = Encoder::new(&mut in_buf);
        encoder.sequence(crate::PKCS_7_DATA_OID.encoded_len()?, |encoder| {
            encoder.oid(crate::PKCS_7_DATA_OID)
        })?;
        let encoded_der = encoder.finish().expect("encoding success");

        let info = ContentInfo::from_der(encoded_der)?;
        match info {
            ContentInfo::Data(None) => (),
            _ => panic!("unexpected case"),
        }

        let mut out_buf = [0u8; 32];
        let encoded_der2 = info.encode_to_slice(&mut out_buf)?;

        assert_eq!(encoded_der, encoded_der2);

        Ok(())
    }

    #[test]
    fn simple_data() -> der::Result<()> {
        let mut in_buf = [0u8; 32];

        let hello = "hello".as_bytes();
        assert_eq!(5, hello.len());

        let hello_len = Length::try_from(hello.len())?.for_tlv()?;
        assert_eq!(Length::new(7), hello_len);

        let tagged_hello_len = hello_len.for_tlv()?;
        assert_eq!(Length::new(9), tagged_hello_len);

        let oid_len = crate::PKCS_7_DATA_OID.encoded_len()?;
        assert_eq!(Length::new(11), oid_len);

        let inner_len = (oid_len + tagged_hello_len)?;
        assert_eq!(Length::new(20), inner_len);

        let mut encoder = Encoder::new(&mut in_buf);
        encoder.sequence(inner_len, |encoder| {
            encoder.oid(crate::PKCS_7_DATA_OID)?;
            encoder.context_specific(
                TagNumber::new(0),
                TagMode::Explicit,
                OctetString::new(hello)?,
            )
        })?;
        let encoded_der = encoder.finish().expect("encoding success");
        assert_eq!(22, encoded_der.len());

        let info = ContentInfo::from_der(encoded_der)?;
        match info {
            ContentInfo::Data(Some(DataContent { content })) => assert_eq!(hello, content),
            _ => panic!("unexpected case"),
        }

        let mut out_buf = [0u8; 32];
        let encoded_der2 = info.encode_to_slice(&mut out_buf)?;

        assert_eq!(encoded_der, encoded_der2);

        Ok(())
    }
}
