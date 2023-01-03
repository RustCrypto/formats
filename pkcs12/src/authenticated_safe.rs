use alloc::vec::Vec;
use der::{
    asn1::{ContextSpecific, OctetStringRef},
    Decode, DecodeValue, Encode, EncodeValue, ErrorKind, FixedTag, Header, Length, Reader,
    Sequence, Tag, TagMode, TagNumber, Writer,
};
use pkcs7::encrypted_data_content::EncryptedDataContent;
use pkcs8::ObjectIdentifier;

use crate::safe_bag::SafeContents;

const CONTENT_TAG: TagNumber = TagNumber::new(0);

/// sequence of AuthenticatedSafeItems
pub type AuthenticatedSafe<'a> = Vec<AuthenticatedSafeItem<'a>>;

/// TODO
#[derive(Clone, Debug)]
pub enum AuthenticatedSafeItem<'a> {
    /// data safe
    Data(Option<SafeContents<'a>>),
    /// encrypted data safe
    EncryptedData(Option<EncryptedDataContent<'a>>),
    /// enveloped data safe
    EnvelopedData(Option<SafeContents<'a>>),
}

impl<'a> AuthenticatedSafeItem<'a> {
    /// return content type of content info
    pub fn content_type(&self) -> AuthenticatedSafeContentType {
        match self {
            Self::Data(_) => AuthenticatedSafeContentType::Data,
            Self::EncryptedData(_) => AuthenticatedSafeContentType::EncryptedData,
            Self::EnvelopedData(_) => AuthenticatedSafeContentType::EnvelopedData,
        }
    }
}

impl<'a> DecodeValue<'a> for AuthenticatedSafeItem<'a> {
    fn decode_value<R: Reader<'a>>(
        reader: &mut R,
        header: Header,
    ) -> der::Result<AuthenticatedSafeItem<'a>> {
        reader.read_nested(header.length, |reader| {
            let bag_type = reader.decode()?;
            match bag_type {
                AuthenticatedSafeContentType::Data => {
                    let inner = reader
                        .context_specific::<OctetStringRef<'a>>(CONTENT_TAG, TagMode::Explicit)?;
                    let contents = SafeContents::from_der(inner.unwrap().as_bytes())?;
                    Ok(AuthenticatedSafeItem::Data(Some(contents)))
                }
                AuthenticatedSafeContentType::EncryptedData => {
                    Ok(AuthenticatedSafeItem::EncryptedData(
                        reader.context_specific::<EncryptedDataContent<'a>>(
                            CONTENT_TAG,
                            TagMode::Explicit,
                        )?,
                    ))
                }
                AuthenticatedSafeContentType::EnvelopedData => {
                    Ok(AuthenticatedSafeItem::EnvelopedData(
                        reader
                            .context_specific::<SafeContents<'a>>(CONTENT_TAG, TagMode::Explicit)?,
                    ))
                }
            }
        })
    }
}

impl<'a> Sequence<'a> for AuthenticatedSafeItem<'a> {
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encode]) -> der::Result<T>,
    {
        match self {
            AuthenticatedSafeItem::Data(data) => f(&[
                &self.content_type(),
                &data.as_ref().map(|d| ContextSpecific {
                    tag_number: CONTENT_TAG,
                    tag_mode: TagMode::Explicit,
                    value: d.clone(),
                }),
            ]),
            AuthenticatedSafeItem::EncryptedData(data) => f(&[
                &self.content_type(),
                &data.as_ref().map(|d| ContextSpecific {
                    tag_number: CONTENT_TAG,
                    tag_mode: TagMode::Explicit,
                    value: d.clone(),
                }),
            ]),
            AuthenticatedSafeItem::EnvelopedData(data) => f(&[
                &self.content_type(),
                &data.as_ref().map(|d| ContextSpecific {
                    tag_number: CONTENT_TAG,
                    tag_mode: TagMode::Explicit,
                    value: d.clone(),
                }),
            ]),
        }
    }
}

/// Indicates the type of content.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum AuthenticatedSafeContentType {
    /// Plain data content type
    Data,

    /// Enveloped-data content type
    EnvelopedData,

    /// Encrypted-data content type
    EncryptedData,
}

impl<'a> DecodeValue<'a> for AuthenticatedSafeContentType {
    fn decode_value<R: Reader<'a>>(
        reader: &mut R,
        header: Header,
    ) -> der::Result<AuthenticatedSafeContentType> {
        ObjectIdentifier::decode_value(reader, header)?.try_into()
    }
}

impl EncodeValue for AuthenticatedSafeContentType {
    fn value_len(&self) -> der::Result<Length> {
        ObjectIdentifier::from(*self).value_len()
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> der::Result<()> {
        ObjectIdentifier::from(*self).encode_value(writer)
    }
}

impl FixedTag for AuthenticatedSafeContentType {
    const TAG: Tag = Tag::ObjectIdentifier;
}

impl From<AuthenticatedSafeContentType> for ObjectIdentifier {
    fn from(content_type: AuthenticatedSafeContentType) -> ObjectIdentifier {
        match content_type {
            AuthenticatedSafeContentType::Data => pkcs7::PKCS_7_DATA_OID,
            AuthenticatedSafeContentType::EnvelopedData => pkcs7::PKCS_7_ENVELOPED_DATA_OID,
            AuthenticatedSafeContentType::EncryptedData => pkcs7::PKCS_7_ENCRYPTED_DATA_OID,
        }
    }
}

impl TryFrom<ObjectIdentifier> for AuthenticatedSafeContentType {
    type Error = der::Error;

    fn try_from(oid: ObjectIdentifier) -> der::Result<Self> {
        match oid {
            pkcs7::PKCS_7_DATA_OID => Ok(Self::Data),
            pkcs7::PKCS_7_ENVELOPED_DATA_OID => Ok(Self::EnvelopedData),
            pkcs7::PKCS_7_ENCRYPTED_DATA_OID => Ok(Self::EncryptedData),
            _ => Err(ErrorKind::OidUnknown { oid }.into()),
        }
    }
}
