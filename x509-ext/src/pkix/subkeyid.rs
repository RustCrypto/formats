use core::ops::Deref;

use const_oid::{ObjectIdentifier, Typed};
use der::{asn1::OctetString, DecodeValue, EncodeValue, FixedTag};

/// Subject key identifier extension as defined in [RFC 5280 Section 4.2.1.2].
///
/// ```text
/// SubjectKeyIdentifier ::= KeyIdentifier
/// KeyIdentifier ::= OCTET STRING
/// ```
///
/// [RFC 5280 Section 4.2.1.2]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectKeyIdentifier<'a>(&'a [u8]);

impl<'a> From<&'a [u8]> for SubjectKeyIdentifier<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for SubjectKeyIdentifier<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl Deref for SubjectKeyIdentifier<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl Typed for SubjectKeyIdentifier<'_> {
    const OID: const_oid::ObjectIdentifier = ObjectIdentifier::new("2.5.29.14");
}

impl<'a> FixedTag for SubjectKeyIdentifier<'a> {
    const TAG: der::Tag = OctetString::TAG;
}

impl<'a> DecodeValue<'a> for SubjectKeyIdentifier<'a> {
    fn decode_value(decoder: &mut der::Decoder<'a>, header: der::Header) -> der::Result<Self> {
        Ok(Self(OctetString::decode_value(decoder, header)?.into()))
    }
}

impl<'a> EncodeValue for SubjectKeyIdentifier<'a> {
    fn value_len(&self) -> der::Result<der::Length> {
        OctetString::new(self.0)?.value_len()
    }

    fn encode_value(&self, encoder: &mut der::Encoder<'_>) -> der::Result<()> {
        OctetString::new(self.0)?.encode_value(encoder)
    }
}
