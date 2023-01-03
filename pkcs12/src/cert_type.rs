use core::cmp::Ordering;

use der::asn1::ObjectIdentifier;
use der::{
    DecodeValue, EncodeValue, ErrorKind, FixedTag, Header, Length, Reader, Tag, ValueOrd, Writer,
};

/// Indicates the type of content.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum CertType {
    /// Plain data content type
    X509,

    /// Signed-data content type
    Sdsi,
}

impl<'a> DecodeValue<'a> for CertType {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<CertType> {
        ObjectIdentifier::decode_value(reader, header)?.try_into()
    }
}

impl EncodeValue for CertType {
    fn value_len(&self) -> der::Result<Length> {
        ObjectIdentifier::from(*self).value_len()
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> der::Result<()> {
        ObjectIdentifier::from(*self).encode_value(writer)
    }
}

impl FixedTag for CertType {
    const TAG: Tag = Tag::ObjectIdentifier;
}

impl From<CertType> for ObjectIdentifier {
    fn from(content_type: CertType) -> ObjectIdentifier {
        match content_type {
            CertType::X509 => crate::PKCS_12_X509_CERT_OID,
            CertType::Sdsi => crate::PKCS_12_SDSI_CERT_OID,
        }
    }
}

impl TryFrom<ObjectIdentifier> for CertType {
    type Error = der::Error;

    fn try_from(oid: ObjectIdentifier) -> der::Result<Self> {
        match oid {
            crate::PKCS_12_X509_CERT_OID => Ok(Self::X509),
            crate::PKCS_12_SDSI_CERT_OID => Ok(Self::Sdsi),
            _ => Err(ErrorKind::OidUnknown { oid }.into()),
        }
    }
}

impl ValueOrd for CertType {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        Ok(self.cmp(other))
    }
}
