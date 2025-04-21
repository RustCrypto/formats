//! OOB-related types

use der::Sequence;
use der::asn1::BitString;

use crmf::controls::CertId;
use spki::AlgorithmIdentifierOwned;
use x509_cert::certificate::{Profile, Rfc5280};

#[cfg(feature = "digest")]
use {
    der::{asn1::Null, oid::AssociatedOid},
    x509_cert::{certificate::CertificateInner, ext::pkix::name::GeneralName},
};

use crate::header::CmpCertificate;

/// The `OOBCert` type is defined in [RFC 4210 Section 5.2.5].
///
/// ```text
///  OOBCert ::= CMPCertificate
/// ```
///
/// [RFC 4210 Section 5.2.5]: https://www.rfc-editor.org/rfc/rfc4210#section-5.2.5
pub type OobCert = CmpCertificate;

/// The `OOBCertHash` type is defined in [RFC 4210 Section 5.2.5].
///
/// ```text
///  OOBCertHash ::= SEQUENCE {
///      hashAlg     [0] AlgorithmIdentifier{DIGEST-ALGORITHM, {...}}
///                          OPTIONAL,
///      certId      [1] CertId                  OPTIONAL,
///      hashVal         BIT STRING
///  }
/// ```
///
/// [RFC 4210 Section 5.2.5]: https://www.rfc-editor.org/rfc/rfc4210#section-5.2.5
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct OobCertHash<P: Profile = Rfc5280> {
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub hash_alg: Option<AlgorithmIdentifierOwned>,
    #[asn1(
        context_specific = "1",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub cert_id: Option<CertId<P>>,
    pub hash_val: BitString,
}

#[cfg(feature = "digest")]
impl<P> OobCertHash<P>
where
    P: Profile,
{
    /// Create an [`OobCertHash`] from a given certificate
    pub fn from_certificate<D>(cert: &CertificateInner<P>) -> der::Result<Self>
    where
        D: digest::Digest + AssociatedOid,
    {
        Ok(Self {
            hash_alg: Some(AlgorithmIdentifierOwned {
                oid: D::OID,
                parameters: Some(Null.into()),
            }),
            cert_id: Some(CertId {
                issuer: GeneralName::DirectoryName(cert.tbs_certificate().issuer().clone()),
                serial_number: cert.tbs_certificate().serial_number().clone(),
            }),
            hash_val: BitString::from_bytes(&cert.hash::<D>()?)?,
        })
    }
}
