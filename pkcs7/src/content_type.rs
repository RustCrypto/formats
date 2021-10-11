use der::asn1::ObjectIdentifier;
use der::{DecodeValue, Decoder, EncodeValue, Encoder, ErrorKind, Length, Tag, Tagged};

/// Indicates the type of content.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ContentType {
    /// Plain data content type
    Data,
    /// Signed-data content type
    SignedData,
    /// Enveloped-data content type
    EnvelopedData,
    /// Signed-and-enveloped-data content type
    SignedAndEnvelopedData,
    /// Digested-data content type
    DigestedData,
    /// Encrypted-data content type
    EncryptedData,
}

impl ContentType {
    /// return OID for content type
    pub fn to_oid(&self) -> ObjectIdentifier {
        match self {
            Self::Data => crate::PKCS_7_DATA_OID,
            Self::SignedData => crate::PKCS_7_SIGNED_DATA_OID,
            Self::EnvelopedData => crate::PKCS_7_ENVELOPED_DATA_OID,
            Self::SignedAndEnvelopedData => crate::PKCS_7_SIGNED_AND_ENVELOPED_DATA_OID,
            Self::DigestedData => crate::PKCS_7_DIGESTED_DATA_OID,
            Self::EncryptedData => crate::PKCS_7_ENCRYPTED_DATA_OID,
        }
    }

    /// match content type to given OID
    pub fn from_oid(oid: ObjectIdentifier) -> Option<Self> {
        match oid {
            crate::PKCS_7_DATA_OID => Some(Self::Data),
            crate::PKCS_7_SIGNED_DATA_OID => Some(Self::SignedData),
            crate::PKCS_7_ENVELOPED_DATA_OID => Some(Self::EnvelopedData),
            crate::PKCS_7_SIGNED_AND_ENVELOPED_DATA_OID => Some(Self::SignedAndEnvelopedData),
            crate::PKCS_7_DIGESTED_DATA_OID => Some(Self::DigestedData),
            crate::PKCS_7_ENCRYPTED_DATA_OID => Some(Self::EncryptedData),
            _ => None,
        }
    }
}

impl<'a> DecodeValue<'a> for ContentType {
    fn decode_value(decoder: &mut Decoder<'a>, length: Length) -> der::Result<ContentType> {
        let oid = ObjectIdentifier::decode_value(decoder, length)?;
        ContentType::from_oid(oid).ok_or_else(|| decoder.error(ErrorKind::UnknownOid { oid: oid }))
    }
}

impl EncodeValue for ContentType {
    fn value_len(&self) -> der::Result<Length> {
        self.to_oid().value_len()
    }

    fn encode_value(&self, encoder: &mut Encoder<'_>) -> der::Result<()> {
        self.to_oid().encode_value(encoder)
    }
}

impl Tagged for ContentType {
    const TAG: Tag = Tag::ObjectIdentifier;
}
