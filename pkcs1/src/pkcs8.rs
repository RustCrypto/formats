//! Blanket impl of PKCS#1 support for types with PKCS#8 support.

pub use pkcs8::*;

use crate::{DecodeRsaPrivateKey, DecodeRsaPublicKey, Result};
use der::asn1::{Any, Null};

#[cfg(feature = "alloc")]
use {
    crate::{EncodeRsaPrivateKey, EncodeRsaPublicKey, RsaPrivateKeyDocument, RsaPublicKeyDocument},
    der::Document,
};

/// `rsaEncryption` Object Identifier (OID)
pub const ALGORITHM_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.1");

/// `AlgorithmIdentifier` for RSA.
pub const ALGORITHM_ID: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
    oid: ALGORITHM_OID,
    parameters: Some(Any::NULL),
};

impl<T: DecodePrivateKey> DecodeRsaPrivateKey for T {
    fn from_pkcs1_der(private_key: &[u8]) -> Result<Self> {
        let algorithm = AlgorithmIdentifier {
            oid: ALGORITHM_OID,
            parameters: Some(Null.into()),
        };

        Ok(Self::try_from(PrivateKeyInfo {
            algorithm,
            private_key,
            public_key: None,
        })?)
    }
}

impl<T: DecodePublicKey> DecodeRsaPublicKey for T {
    fn from_pkcs1_der(public_key: &[u8]) -> Result<Self> {
        Ok(Self::from_spki(SubjectPublicKeyInfo {
            algorithm: ALGORITHM_ID,
            subject_public_key: public_key,
        })?)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<T: EncodePrivateKey> EncodeRsaPrivateKey for T {
    fn to_pkcs1_der(&self) -> Result<RsaPrivateKeyDocument> {
        let doc = self.to_pkcs8_der()?;
        Ok(RsaPrivateKeyDocument::from_der(doc.decode().private_key)?)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<T: EncodePublicKey> EncodeRsaPublicKey for T {
    fn to_pkcs1_der(&self) -> Result<RsaPublicKeyDocument> {
        let doc = self.to_public_key_der()?;
        Ok(RsaPublicKeyDocument::from_der(
            doc.decode().subject_public_key,
        )?)
    }
}
