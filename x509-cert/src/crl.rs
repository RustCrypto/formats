//! Certificate Revocation List types

use crate::{
    AlgorithmIdentifier, Version,
    certificate::{Profile, Rfc5280},
    ext::Extensions,
    name::Name,
    serial_number::SerialNumber,
    time::Time,
};

use alloc::vec::Vec;

use der::asn1::BitString;
use der::{Sequence, ValueOrd};

#[cfg(feature = "pem")]
use der::pem::PemLabel;

/// `CertificateList` as defined in [RFC 5280 Section 5.1].
///
/// ```text
/// CertificateList  ::=  SEQUENCE  {
///     tbsCertList          TBSCertList,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING
/// }
/// ```
///
/// [RFC 5280 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct CertificateList<P: Profile = Rfc5280> {
    pub tbs_cert_list: TbsCertList<P>,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: BitString,
}

#[cfg(feature = "pem")]
impl<P: Profile> PemLabel for CertificateList<P> {
    const PEM_LABEL: &'static str = "X509 CRL";
}

/// Implicit intermediate structure from the ASN.1 definition of `TBSCertList`.
///
/// This type is used for the `revoked_certificates` field of `TbsCertList`.
/// See [RFC 5280 Section 5.1].
///
/// ```text
/// RevokedCert ::= SEQUENCE {
///     userCertificate         CertificateSerialNumber,
///     revocationDate          Time,
///     crlEntryExtensions      Extensions OPTIONAL
/// }
/// ```
///
/// [RFC 5280 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct RevokedCert<P: Profile = Rfc5280> {
    pub serial_number: SerialNumber<P>,
    pub revocation_date: Time,
    pub crl_entry_extensions: Option<Extensions>,
}

/// `TbsCertList` as defined in [RFC 5280 Section 5.1].
///
/// ```text
/// TBSCertList  ::=  SEQUENCE  {
///      version                 Version OPTIONAL, -- if present, MUST be v2
///      signature               AlgorithmIdentifier,
///      issuer                  Name,
///      thisUpdate              Time,
///      nextUpdate              Time OPTIONAL,
///      revokedCertificates     SEQUENCE OF SEQUENCE  {
///           userCertificate         CertificateSerialNumber,
///           revocationDate          Time,
///           crlEntryExtensions      Extensions OPTIONAL -- if present, version MUST be v2
///      }  OPTIONAL,
///      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL -- if present, version MUST be v2
/// }
/// ```
///
/// [RFC 5280 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct TbsCertList<P: Profile = Rfc5280> {
    pub version: Version,
    pub signature: AlgorithmIdentifier,
    pub issuer: Name,
    pub this_update: Time,
    pub next_update: Option<Time>,
    pub revoked_certificates: Option<Vec<RevokedCert<P>>>,

    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub crl_extensions: Option<Extensions>,
}
