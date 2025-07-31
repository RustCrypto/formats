//! Attribute-related types
use alloc::{boxed::Box, vec};
use der::{
    DecodeValue, EncodeValue, FixedTag, Length, Tag,
    asn1::{OctetString, OctetStringRef},
    referenced::OwnedToRef,
};

use x509_cert::time::Time;

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
    pub fn as_octet_string_ref<'a>(&'a self) -> OctetStringRef<'a> {
        self.0.owned_to_ref()
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
