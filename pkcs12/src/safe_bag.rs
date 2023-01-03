use alloc::vec::Vec;
use der::{
    asn1::{ContextSpecific, OctetString},
    DecodeValue, Encode, Header, Reader, Sequence, TagMode, TagNumber,
};
use pkcs8::{EncryptedPrivateKeyInfo, PrivateKeyInfo};
use x509_cert::attr::Attributes;

use crate::{bag_type::BagType, cert_bag_content::CertBagContent};

type Placeholder = OctetString;

const CONTENT_TAG: TagNumber = TagNumber::new(0);

/// Sequence of SafeBag
pub type SafeContents<'a> = Vec<SafeBag<'a>>;

///
/// ```text
/// SafeBag ::= SEQUENCE {
///     bagId          BAG-TYPE.&id ({PKCS12BagSet})
///     bagValue       [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
///     bagAttributes  SET OF PKCS12Attribute OPTIONAL
/// }
/// PKCS12BagSet BAG-TYPE ::= {
///     keyBag |
///     pkcs8ShroudedKeyBag |
///     certBag |
///     crlBag |
///     secretBag |
///     safeContentsBag,
///     .. -- For future extensions
/// }
/// PKCS12Attribute ::= SEQUENCE {
///     attrId      ATTRIBUTE.&id ({PKCS12AttrSet}),
///     attrValues  SET OF ATTRIBUTE.&Type ({PKCS12AttrSet}{@attrId})
/// } -- This type is compatible with the X.500 type 'Attribute'
/// ```
#[derive(Clone, Debug)]
pub enum SafeBag<'a> {
    /// key bag
    KeyBag(Option<PrivateKeyInfo<'a>>, Option<Attributes>),
    /// pkcs8 bag
    Pkcs8ShroudedKeyBag(Option<EncryptedPrivateKeyInfo<'a>>, Option<Attributes>),
    /// cert bag
    CertBag(Option<CertBagContent>, Option<Attributes>),
    /// crl bag currently unimplemented
    CrlBag(Option<Placeholder>, Option<Attributes>),
    /// secret bag currently unimplemented
    SecretBag(Option<Placeholder>, Option<Attributes>),
    /// safeContents bag currently unimplemented
    SafeContentsBag(Option<Placeholder>, Option<Attributes>),
}

impl<'a> SafeBag<'a> {
    /// return content type of content info
    pub fn content_type(&self) -> BagType {
        match self {
            Self::KeyBag(_, _) => BagType::Key,
            _ => panic!("content type"),
        }
    }
}

impl<'a> DecodeValue<'a> for SafeBag<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<SafeBag<'a>> {
        reader.read_nested(header.length, |reader| {
            let bag_type = reader.decode()?;
            match bag_type {
                BagType::Key => Ok(SafeBag::KeyBag(
                    reader
                        .context_specific::<PrivateKeyInfo<'a>>(CONTENT_TAG, TagMode::Explicit)?,
                    reader.decode()?,
                )),
                BagType::Pkcs8 => Ok(SafeBag::Pkcs8ShroudedKeyBag(
                    reader.context_specific::<EncryptedPrivateKeyInfo<'a>>(
                        CONTENT_TAG,
                        TagMode::Explicit,
                    )?,
                    reader.decode()?,
                )),
                BagType::Cert => Ok(SafeBag::CertBag(
                    reader.context_specific::<CertBagContent>(CONTENT_TAG, TagMode::Explicit)?,
                    reader.decode()?,
                )),
                _ => todo!("Encoding of other types is currently not supported"),
            }
        })
    }
}

impl<'a> Sequence<'a> for SafeBag<'a> {
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encode]) -> der::Result<T>,
    {
        match self {
            Self::KeyBag(data, attrs) => f(&[
                &self.content_type(),
                &data.as_ref().map(|d| ContextSpecific {
                    tag_number: CONTENT_TAG,
                    tag_mode: TagMode::Explicit,
                    value: d.clone(),
                }),
                &attrs,
            ]),
            Self::Pkcs8ShroudedKeyBag(data, attrs) => f(&[
                &self.content_type(),
                &data.as_ref().map(|d| ContextSpecific {
                    tag_number: CONTENT_TAG,
                    tag_mode: TagMode::Explicit,
                    value: d.clone(),
                }),
                &attrs,
            ]),
            Self::CertBag(data, attrs) => f(&[
                &self.content_type(),
                &data.as_ref().map(|d| ContextSpecific {
                    tag_number: CONTENT_TAG,
                    tag_mode: TagMode::Explicit,
                    value: d.clone(),
                }),
                &attrs,
            ]),
            _ => todo!("Encoding of other types is currently not supported"),
        }
    }
}
