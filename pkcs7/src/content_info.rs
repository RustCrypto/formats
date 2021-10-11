use crate::{ContentType, DataContent};

use der::{Decodable, Decoder, Encodable, ErrorKind, Message, TagMode, TagNumber};

const CONTENT_TAG: TagNumber = TagNumber::new(0);

/// Content exchanged between entities
pub enum ContentInfo<'a> {
    /// Content type `data`
    Data(DataContent<'a>),
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
        ContentInfo::Data(content.into())
    }
}

impl<'a> Decodable<'a> for ContentInfo<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<ContentInfo<'a>> {
        decoder.sequence(|decoder| {
            let content_type = decoder.decode()?;
            match content_type {
                ContentType::Data => decoder
                    .context_specific::<DataContent<'_>>(CONTENT_TAG, TagMode::Explicit)?
                    .map(ContentInfo::Data)
                    .ok_or_else(|| decoder.error(ErrorKind::Failed)),
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
            Self::Data(data) => f(&[&self.content_type(), data]),
        }
    }
}
