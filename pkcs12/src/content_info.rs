use der::{
    asn1::OctetStringRef, Decode, DecodeValue, Encode, Header, Reader, Sequence, TagMode, TagNumber,
};
use pkcs7::ContentType;

use crate::authenticated_safe::AuthenticatedSafe;

const CONTENT_TAG: TagNumber = TagNumber::new(0);

/// TODO
#[derive(Clone, Debug)]
pub enum ContentInfo<'a> {
    /// Content type `data`
    Data(Option<AuthenticatedSafe<'a>>),

    /// Content type `encrypted-data`
    SignedData(Option<AuthenticatedSafe<'a>>),
}

impl<'a> ContentInfo<'a> {
    /// return content type of content info
    pub fn content_type(&self) -> ContentType {
        match self {
            Self::Data(_) => ContentType::Data,
            Self::SignedData(_) => ContentType::SignedData,
            // _ => panic!("unsupported"),
        }
    }
}

impl<'a> ContentInfo<'a> {
    /// new ContentInfo of `data` content type
    // TODO
    // pub fn new_data(content: &'a [u8]) -> Self {
    //     ContentInfo::Data(Some(content.into()))
    // }

    /// new ContentInfo of given content type with empty content
    pub fn new_empty(content_type: ContentType) -> Self {
        match content_type {
            ContentType::Data => ContentInfo::Data(None),
            ContentType::SignedData => ContentInfo::SignedData(None),
            _ => panic!("Not supported here"),
        }
    }

    // /// new Content info of given content type with given raw content
    // pub fn new_raw(content_type: ContentType, content: &'a [u8]) -> der::Result<Self> {
    //     Ok(ContentInfo::Other((
    //         content_type,
    //         Some(OctetStringRef::new(content)?),
    //     )))
    // }
}

impl<'a> DecodeValue<'a> for ContentInfo<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<ContentInfo<'a>> {
        reader.read_nested(header.length, |reader| {
            let content_type = reader.decode()?;
            match content_type {
                ContentType::Data => {
                    let inner = reader
                        .context_specific::<OctetStringRef<'a>>(CONTENT_TAG, TagMode::Explicit)?;
                    let content = AuthenticatedSafe::from_der(inner.unwrap().as_bytes())?;
                    Ok(ContentInfo::Data(Some(content)))
                }
                ContentType::SignedData => Ok(ContentInfo::SignedData(
                    reader.context_specific(CONTENT_TAG, TagMode::Explicit)?,
                )),

                _ => panic!("Not supported here"),
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
                // TODO
                // &data.as_ref().map(|d| ContextSpecific {
                //     tag_number: CONTENT_TAG,
                //     tag_mode: TagMode::Explicit,
                //     value: *d,
                // }),
            ]),
            Self::SignedData(data) => f(&[
                &self.content_type(),
                // TODO
                // &data.as_ref().map(|d| ContextSpecific {
                //     tag_number: CONTENT_TAG,
                //     tag_mode: TagMode::Explicit,
                //     value: *d,
                // }),
            ]),
        }
    }
}
