//! SafeBag-related types

use alloc::vec::Vec;
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{AnyRef, Decode, Enumerated, Sequence, Tagged};
use spki::AlgorithmIdentifierOwned;
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
    /// DER encoding of the complete `[0] EXPLICIT` field (tag, length and the bag value).
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
        let bag_value = reader.tlv_bytes()?;
        check_bag_value(bag_value)?;
        let bag_value = bag_value.to_vec();
        let bag_attributes = reader.decode()?;
        Ok(Self {
            bag_id,
            bag_value,
            bag_attributes,
        })
    }
}
/// `bagValue` must be a single `[0] EXPLICIT` (context-specific, constructed) TLV.
fn check_bag_value(bag_value: &[u8]) -> ::der::Result<()> {
    let tag = AnyRef::from_der(bag_value)?.tag();
    let expected = ::der::Tag::ContextSpecific {
        constructed: true,
        number: ::der::TagNumber(0),
    };
    if tag != expected {
        return Err(tag.unexpected_error(Some(expected)).into());
    }
    Ok(())
}

impl ::der::EncodeValue for SafeBag {
    fn value_len(&self) -> ::der::Result<::der::Length> {
        check_bag_value(&self.bag_value)?;
        use ::der::Encode as _;
        [
            self.bag_id.encoded_len()?,
            ::der::Length::try_from(self.bag_value.len())?,
            self.bag_attributes.encoded_len()?,
        ]
        .into_iter()
        .try_fold(::der::Length::ZERO, |acc, len| acc + len)
    }
    fn encode_value(&self, writer: &mut impl ::der::Writer) -> ::der::Result<()> {
        use ::der::Encode as _;
        self.bag_id.encode(writer)?;
        check_bag_value(&self.bag_value)?;
        writer.write(&self.bag_value)?;
        self.bag_attributes.encode(writer)?;
        Ok(())
    }
}
impl ::der::Sequence<'_> for SafeBag {}

/// Version for the PrivateKeyInfo structure as defined in [RFC 5208 Section 5].
///
/// [RFC 5208 Section 5]: https://www.rfc-editor.org/rfc/rfc5208#section-5
#[derive(Clone, Copy, Debug, Enumerated, Eq, PartialEq, PartialOrd, Ord)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Pkcs8Version {
    /// syntax version 3
    V0 = 0,
}

// PrivateKeyInfo is defined in the pkcs8 crate but without Debug, PartialEq, Eq, Sequence
/// The `PrivateKeyInfo` type is defined in [RFC 5208 Section 5].
///
/// ```text
///       PrivateKeyInfo ::= SEQUENCE {
///         version                   Version,
///         privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
///         privateKey                PrivateKey,
///         attributes           [0]  IMPLICIT Attributes OPTIONAL }
/// ```
///
/// [RFC 5208 Section 5]: https://www.rfc-editor.org/rfc/rfc5208#section-5
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct PrivateKeyInfo {
    /// Syntax version number (always 0 for RFC 5208)
    pub version: Pkcs8Version,

    /// X.509 `AlgorithmIdentifier` for the private key type.
    pub algorithm: AlgorithmIdentifierOwned,

    /// Private key data.
    pub private_key: OctetString,

    /// Public key data, optionally available if version is V2.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub attributes: Option<Attributes>,
}
