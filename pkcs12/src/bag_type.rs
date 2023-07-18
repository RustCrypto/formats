//! BagType-related types

use der::asn1::ObjectIdentifier;
use der::{ErrorKind, FixedTag, Tag};

/// Indicates the type of content.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum BagType {
    /// Plain data content type
    Key,

    /// Signed-data content type
    Pkcs8,

    /// Enveloped-data content type
    Cert,

    /// Signed-and-enveloped-data content type
    Crl,

    /// Digested-data content type
    Secret,

    /// Encrypted-data content type
    SafeContents,
}


impl FixedTag for BagType {
    const TAG: Tag = Tag::ObjectIdentifier;
}

impl From<BagType> for ObjectIdentifier {
    fn from(content_type: BagType) -> ObjectIdentifier {
        match content_type {
            BagType::Key => crate::PKCS_12_KEY_BAG_OID,
            BagType::Pkcs8 => crate::PKCS_12_PKCS8_KEY_BAG_OID,
            BagType::Cert => crate::PKCS_12_CERT_BAG_OID,
            BagType::Crl => crate::PKCS_12_CRL_BAG_OID,
            BagType::Secret => crate::PKCS_12_SECRET_BAG_OID,
            BagType::SafeContents => crate::PKCS_12_SAFE_CONTENTS_BAG_OID,
        }
    }
}

impl TryFrom<ObjectIdentifier> for BagType {
    type Error = der::Error;

    fn try_from(oid: ObjectIdentifier) -> der::Result<Self> {
        match oid {
            crate::PKCS_12_KEY_BAG_OID => Ok(Self::Key),
            crate::PKCS_12_PKCS8_KEY_BAG_OID => Ok(Self::Pkcs8),
            crate::PKCS_12_CERT_BAG_OID => Ok(Self::Cert),
            crate::PKCS_12_CRL_BAG_OID => Ok(Self::Crl),
            crate::PKCS_12_SECRET_BAG_OID => Ok(Self::Secret),
            crate::PKCS_12_SAFE_CONTENTS_BAG_OID => Ok(Self::SafeContents),
            _ => Err(ErrorKind::OidUnknown { oid }.into()),
        }
    }
}
