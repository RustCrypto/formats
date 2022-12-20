use crate::{data_content::DataContent, encrypted_data_content::EncryptedDataContent, ContentType, signed_data_content::SignedDataContent};

use der::{
    asn1::{ContextSpecific, OctetStringRef},
    DecodeValue, Encode, Header, Reader, Sequence, TagMode, TagNumber,
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

    /// Content type `signed-data`
    SignedData(Option<SignedDataContent<'a>>),

    /// Catch-all case for content types that are not explicitly supported
    ///   - signed-data
    ///   - enveloped-data
    ///   - signed-and-enveloped-data
    ///   - digested-data
    Other((ContentType, Option<OctetStringRef<'a>>)),
}

impl<'a> ContentInfo<'a> {
    /// return content type of content info
    pub fn content_type(&self) -> ContentType {
        match self {
            Self::Data(_) => ContentType::Data,
            Self::EncryptedData(_) => ContentType::EncryptedData,
            Self::SignedData(_) => ContentType::SignedData,
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
            ContentType::SignedData => ContentInfo::SignedData(None),
            _ => ContentInfo::Other((content_type, None)),
        }
    }

    /// new Content info of given content type with given raw content
    pub fn new_raw(content_type: ContentType, content: &'a [u8]) -> der::Result<Self> {
        Ok(ContentInfo::Other((
            content_type,
            Some(OctetStringRef::new(content)?),
        )))
    }
}

impl<'a> DecodeValue<'a> for ContentInfo<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<ContentInfo<'a>> {
        reader.read_nested(header.length, |reader| {
            let content_type = reader.decode()?;
            match content_type {
                ContentType::Data => Ok(ContentInfo::Data(
                    reader.context_specific::<DataContent<'_>>(CONTENT_TAG, TagMode::Explicit)?,
                )),
                ContentType::EncryptedData => Ok(ContentInfo::EncryptedData(
                    reader.context_specific(CONTENT_TAG, TagMode::Explicit)?,
                )),
                ContentType::SignedData => Ok(ContentInfo::SignedData(
                    reader.context_specific::<SignedDataContent<'_>>(CONTENT_TAG, TagMode::Explicit)?,
                )),
                _ => Ok(ContentInfo::Other((
                    content_type,
                    reader
                        .context_specific::<OctetStringRef<'_>>(CONTENT_TAG, TagMode::Explicit)?,
                ))),
            }
        })
    }
}

impl<'a> Sequence<'a> for ContentInfo<'a> {
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encode]) -> der::Result<T>,
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
            Self::SignedData(data) => f(&[
                &self.content_type(),
                &data.as_ref().map(|d| ContextSpecific {
                    tag_number: CONTENT_TAG,
                    tag_mode: TagMode::Explicit,
                    value: d.clone(),
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
    use der::{asn1::OctetStringRef, Decode, Encode, Length, SliceWriter, TagMode, TagNumber};

    #[test]
    fn empty_data() -> der::Result<()> {
        let mut in_buf = [0u8; 32];

        let mut encoder = SliceWriter::new(&mut in_buf);
        encoder.sequence(crate::PKCS_7_DATA_OID.encoded_len()?, |encoder| {
            crate::PKCS_7_DATA_OID.encode(encoder)
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

        let mut encoder = SliceWriter::new(&mut in_buf);
        encoder.sequence(crate::PKCS_7_ENCRYPTED_DATA_OID.encoded_len()?, |encoder| {
            (crate::PKCS_7_ENCRYPTED_DATA_OID).encode(encoder)
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

        let mut encoder = SliceWriter::new(&mut in_buf);
        encoder.sequence(inner_len, |encoder| {
            crate::PKCS_7_DATA_OID.encode(encoder)?;
            encoder.context_specific(
                TagNumber::new(0),
                TagMode::Explicit,
                &OctetStringRef::new(hello)?,
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
