//! SafeBag-related types

use alloc::vec::Vec;
use const_oid::ObjectIdentifier;
use der::{AnyRef, Decode};
use x509_cert::attr::Attributes;

/// The `SafeContents` type is defined in [RFC 7292 Section 4.2].
///
/// ```text
/// SafeContents ::= SEQUENCE OF SafeBag
/// ```
///
/// [RFC 7292 Section 4.2]: https://www.rfc-editor.org/rfc/rfc7292#section-4.2
pub type SafeContents = Vec<SafeBag>;

/// The `SafeBag` type is defined in [RFC 7292 Section 4.2].
///
/// ```text
/// SafeBag ::= SEQUENCE {
///     bagId          BAG-TYPE.&id ({PKCS12BagSet})
///     bagValue       [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
///     bagAttributes  SET OF PKCS12Attribute OPTIONAL
/// }
/// ```
///
/// [RFC 7292 Section 4.2]: https://www.rfc-editor.org/rfc/rfc7292#section-4.2
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct SafeBag {
    pub bag_id: ObjectIdentifier,
    pub bag_value: Vec<u8>,
    pub bag_attributes: Option<Attributes>,
}

impl<'a> ::der::DecodeValue<'a> for SafeBag {
    type Error = der::Error;

    fn decode_value<R: ::der::Reader<'a>>(
        reader: &mut R,
        _header: ::der::Header,
    ) -> ::der::Result<Self> {
        let bag_id = reader.decode()?;
        let bag_value = reader.tlv_bytes()?.to_vec();
        let bag_attributes = reader.decode()?;
        Ok(Self {
            bag_id,
            bag_value,
            bag_attributes,
        })
    }
}
impl ::der::EncodeValue for SafeBag {
    fn value_len(&self) -> ::der::Result<::der::Length> {
        let content = AnyRef::from_der(&self.bag_value)?;
        use ::der::Encode as _;
        [
            self.bag_id.encoded_len()?,
            ::der::asn1::ContextSpecificRef {
                tag_number: ::der::TagNumber(0),
                tag_mode: ::der::TagMode::Explicit,
                value: &content,
            }
            .encoded_len()?,
            self.bag_attributes.encoded_len()?,
        ]
        .into_iter()
        .try_fold(::der::Length::ZERO, |acc, len| acc + len)
    }
    fn encode_value(&self, writer: &mut impl ::der::Writer) -> ::der::Result<()> {
        use ::der::Encode as _;
        self.bag_id.encode(writer)?;
        let content = AnyRef::from_der(&self.bag_value)?;
        ::der::asn1::ContextSpecificRef {
            tag_number: ::der::TagNumber(0),
            tag_mode: ::der::TagMode::Explicit,
            value: &content,
        }
        .encode(writer)?;
        self.bag_attributes.encode(writer)?;
        Ok(())
    }
}
impl ::der::Sequence<'_> for SafeBag {}
