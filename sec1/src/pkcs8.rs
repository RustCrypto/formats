//! Blanket impl of SEC1 support for types with PKCS#8 support.

pub use pkcs8::*;

use crate::{DecodeEcPrivateKey, EcPrivateKey, Result};
use der::Decodable;

#[cfg(feature = "alloc")]
use {
    crate::{EcPrivateKeyDocument, EncodeEcPrivateKey},
    der::Document,
};

/// Algorithm [`ObjectIdentifier`] for elliptic curve public key cryptography
/// (`id-ecPublicKey`).
///
/// <http://oid-info.com/get/1.2.840.10045.2.1>
pub const ALGORITHM_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");

impl<T: DecodePrivateKey> DecodeEcPrivateKey for T {
    fn from_sec1_der(private_key: &[u8]) -> Result<Self> {
        let params_oid = EcPrivateKey::from_der(private_key)?
            .parameters
            .and_then(|params| params.named_curve());

        let algorithm = AlgorithmIdentifier {
            oid: ALGORITHM_OID,
            parameters: params_oid.as_ref().map(Into::into),
        };

        Ok(Self::from_pkcs8_private_key_info(PrivateKeyInfo {
            algorithm,
            private_key,
            public_key: None,
        })?)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<T: EncodePrivateKey> EncodeEcPrivateKey for T {
    fn to_sec1_der(&self) -> Result<EcPrivateKeyDocument> {
        let doc = self.to_pkcs8_der()?;
        let pkcs8_key = PrivateKeyInfo::from_der(doc.as_der())?;
        let mut pkcs1_key = EcPrivateKey::from_der(pkcs8_key.private_key)?;
        pkcs1_key.parameters = Some(pkcs8_key.algorithm.parameters_oid()?.into());
        pkcs1_key.try_into()
    }
}
