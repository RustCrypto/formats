use crate::{data_content::DataContent, encrypted_data_content::EncryptedDataContent, ContentType};

use der::{
    asn1::{ContextSpecific, OctetString},
    Decodable, Decoder, Encodable, Sequence, TagMode, TagNumber,
};

const CONTENT_TAG: TagNumber = TagNumber::new(0);

/// Content exchanged between entities [RFC 5652 § 3](https://datatracker.ietf.org/doc/html/rfc5652#section-3)
///
/// ```text
/// ContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   content
///     [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
/// ```
pub enum ContentInfo<'a> {
    /// Content type `data`
    Data(Option<DataContent<'a>>),

    /// Content type `encrypted-data`
    EncryptedData(Option<EncryptedDataContent<'a>>),

    /// Catch-all case for content types that are not explicitly supported
    ///   - signed-data
    ///   - enveloped-data
    ///   - signed-and-enveloped-data
    ///   - digested-data
    Other((ContentType, Option<OctetString<'a>>)),
}

impl<'a> ContentInfo<'a> {
    /// return content type of content info
    pub fn content_type(&self) -> ContentType {
        match self {
            Self::Data(_) => ContentType::Data,
            Self::EncryptedData(_) => ContentType::EncryptedData,
            Self::Other((content_type, _)) => *content_type,
        }
    }
}

impl<'a> ContentInfo<'a> {
    /// new ContentInfo of `data` content type
    pub fn new_data(content: &'a [u8]) -> Self {
        ContentInfo::Data(Some(content.into()))
    }

    /// new ContentInfo of given content type with empty content
    pub fn new_empty(content_type: ContentType) -> Self {
        match content_type {
            ContentType::Data => ContentInfo::Data(None),
            ContentType::EncryptedData => ContentInfo::EncryptedData(None),
            _ => ContentInfo::Other((content_type, None)),
        }
    }

    /// new Content info of given content type with given raw content
    pub fn new_raw(content_type: ContentType, content: &'a [u8]) -> der::Result<Self> {
        Ok(ContentInfo::Other((
            content_type,
            Some(OctetString::new(content)?),
        )))
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
                ContentType::EncryptedData => Ok(ContentInfo::EncryptedData(
                    ContextSpecific::decode_explicit(decoder, CONTENT_TAG)?
                        .map(|field| field.value),
                )),
                _ => Ok(ContentInfo::Other((
                    content_type,
                    decoder.context_specific::<OctetString<'_>>(CONTENT_TAG, TagMode::Explicit)?,
                ))),
            }
        })
    }
}

impl<'a> Sequence<'a> for ContentInfo<'a> {
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
            Self::EncryptedData(data) => f(&[
                &self.content_type(),
                &data.as_ref().map(|d| ContextSpecific {
                    tag_number: CONTENT_TAG,
                    tag_mode: TagMode::Explicit,
                    value: *d,
                }),
            ]),
            Self::Other((content_type, opt_oct_str)) => f(&[
                content_type,
                &opt_oct_str.as_ref().map(|d| ContextSpecific {
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
    fn empty_encrypted_data() -> der::Result<()> {
        let mut in_buf = [0u8; 32];

        let mut encoder = Encoder::new(&mut in_buf);
        encoder.sequence(crate::PKCS_7_ENCRYPTED_DATA_OID.encoded_len()?, |encoder| {
            encoder.oid(crate::PKCS_7_ENCRYPTED_DATA_OID)
        })?;
        let encoded_der = encoder.finish().expect("encoding success");

        let info = ContentInfo::from_der(encoded_der)?;
        match info {
            ContentInfo::EncryptedData(None) => (),
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
                &OctetString::new(hello)?,
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
