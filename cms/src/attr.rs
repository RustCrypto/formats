//! Attribute-related types
//!
use alloc::{boxed::Box, vec};
use core::borrow::Borrow;
use der::{
    DecodeValue, EncodeValue, FixedTag, Length, Tag,
    asn1::{OctetString, OctetStringRef},
    oid::db::rfc6268,
};

use x509_cert::{attr::Attribute, time::Time};

use crate::signed_data::SignerInfo;

/// The `MessageDigest` attribute is defined in [RFC 5652 Section 11.2].
///
/// ```text
///   MessageDigest ::= OCTET STRING
/// ```
///
/// [RFC 5652 Section 11.2]: https://www.rfc-editor.org/rfc/rfc5652#section-11.2
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MessageDigest(pub OctetString);

impl MessageDigest {
    /// Borrow the inner byte slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Take ownership of the octet string.
    #[inline]
    pub fn into_bytes(self) -> Box<[u8]> {
        self.0.into_bytes()
    }

    /// Get the length of the inner byte slice.
    #[inline]
    pub fn len(&self) -> Length {
        self.0.len()
    }

    /// Create a [`MessageDigest`] from a [`digest::Digest`]
    #[cfg(feature = "digest")]
    pub fn from_digest<D>(digest: D) -> der::Result<Self>
    where
        D: digest::Digest,
    {
        Ok(MessageDigest(OctetString::new(digest.finalize().to_vec())?))
    }

    /// Return an [`OctetStringRef`] pointing to the underlying data
    #[inline]
    pub fn as_octet_string_ref(&self) -> &OctetStringRef {
        self.0.borrow()
    }
}

impl AsRef<[u8]> for MessageDigest {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<OctetString> for MessageDigest {
    #[inline]
    fn as_ref(&self) -> &OctetString {
        &self.0
    }
}

impl<'a> DecodeValue<'a> for MessageDigest {
    type Error = <OctetString as DecodeValue<'a>>::Error;

    #[inline]
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        OctetString::decode_value(reader, header).map(Self)
    }
}

impl EncodeValue for MessageDigest {
    #[inline]
    fn value_len(&self) -> der::Result<Length> {
        self.0.value_len()
    }

    #[inline]
    fn encode_value(&self, writer: &mut impl der::Writer) -> der::Result<()> {
        self.0.encode_value(writer)
    }
}

impl FixedTag for MessageDigest {
    const TAG: Tag = OctetString::TAG;
}

impl From<MessageDigest> for vec::Vec<u8> {
    #[inline]
    fn from(value: MessageDigest) -> vec::Vec<u8> {
        value.0.into_bytes().into()
    }
}

impl TryFrom<&Attribute> for MessageDigest {
    type Error = der::Error;

    fn try_from(attr: &Attribute) -> Result<Self, Self::Error> {
        if attr.oid != rfc6268::ID_MESSAGE_DIGEST {
            return Err(der::ErrorKind::OidUnknown { oid: attr.oid }.into());
        }

        // A message-digest attribute MUST have a single attribute value, even
        // though the syntax is defined as a SET OF AttributeValue.  There MUST
        // NOT be zero or multiple instances of AttributeValue present.

        if attr.values.len() != 1 {
            return Err(der::ErrorKind::Value { tag: Tag::Set }.into());
        }
        let message_digest = attr
            .values
            .get(0)
            .expect("Invariant violation, only one value is present in the attribute");

        message_digest.decode_as::<OctetString>().map(Self)
    }
}

/// The `SigningTime` attribute is defined in [RFC 5652 Section 11.3].
///
/// ```text
///   SigningTime  ::= Time
/// ```
///
/// [RFC 5652 Section 11.3]: https://www.rfc-editor.org/rfc/rfc5652#section-11.3
pub type SigningTime = Time;

/// The `Countersignature` attribute is defined in [RFC 5652 Section 11.4].
///
/// ```text
///   Countersignature ::= SignerInfo
/// ```
///
/// [RFC 5652 Section 11.4]: https://www.rfc-editor.org/rfc/rfc5652#section-11.4
pub type Countersignature = SignerInfo;
