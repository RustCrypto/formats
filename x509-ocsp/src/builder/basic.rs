//! OCSP basic builder

use crate::{builder::Error, CertId};
use const_oid::AssociatedOid;
use der::{
    asn1::{Null, OctetString},
    Encode,
};
use digest::Digest;
use spki::AlgorithmIdentifierOwned;
use x509_cert::{serial_number::SerialNumber, Certificate};

impl CertId {
    /// Generates a `CertID` by running the issuer's subject and key through the specified
    /// [`Digest`].
    ///
    /// [RFC 6960 Section 4.1.1]
    ///
    /// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
    pub fn from_issuer<D>(issuer: &Certificate, serial_number: SerialNumber) -> Result<Self, Error>
    where
        D: Digest + AssociatedOid,
    {
        Ok(Self {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: D::OID,
                parameters: Some(Null.into()),
            },
            issuer_name_hash: OctetString::new(
                D::digest(issuer.tbs_certificate.subject.to_der()?).to_vec(),
            )?,
            issuer_key_hash: OctetString::new(
                D::digest(
                    issuer
                        .tbs_certificate
                        .subject_public_key_info
                        .subject_public_key
                        .raw_bytes(),
                )
                .to_vec(),
            )?,
            serial_number,
        })
    }

    /// Generates a `CertID` by running the issuer's subject and key through the specified
    /// [`Digest`] and pulls the serial from `cert`. This does not ensure that `cert` is actually
    /// issued by `issuer`.
    ///
    /// [RFC 6960 Section 4.1.1]
    ///
    /// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
    pub fn from_cert<D>(issuer: &Certificate, cert: &Certificate) -> Result<Self, Error>
    where
        D: Digest + AssociatedOid,
    {
        Self::from_issuer::<D>(issuer, cert.tbs_certificate.serial_number.clone())
    }
}
