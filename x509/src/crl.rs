//! CertificateList [`CertificateList`] and TBSCertList [`TbsCertList`] as defined in RFC 5280

use crate::ext::Extensions;
use crate::name::Name;
use crate::time::Time;
use crate::Version;
use der::asn1::{BitString, UIntBytes};
use der::Sequence;
use spki::AlgorithmIdentifier;

///```text
/// CertificateList  ::=  SEQUENCE  {
///      tbsCertList          TBSCertList,
///      signatureAlgorithm   AlgorithmIdentifier,
///      signatureValue       BIT STRING  }
/// ```
/// [RFC 5280 Section 5.1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-5.1>
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CertificateList<'a> {
    /// tbsCertList       TBSCertList,
    pub tbs_cert_list: TbsCertList<'a>,
    /// signatureAlgorithm   AlgorithmIdentifier,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    /// signature            BIT STRING
    pub signature: BitString<'a>,
}

/// Structure fabricated from the revokedCertificates definition in TBSCertList
///
///```text
/// RevokedCert ::= SEQUENCE {
///           userCertificate         CertificateSerialNumber,
///           revocationDate          Time,
///           crlEntryExtensions      Extensions OPTIONAL
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct RevokedCert<'a> {
    /// userCertificate         CertificateSerialNumber,
    pub serial_number: UIntBytes<'a>,
    /// revocationDate          Time,
    pub revocation_date: Time,
    /// crlEntryExtensions      Extensions OPTIONAL
    pub crl_entry_extensions: Extensions<'a>,
}

/// Structure fabricated from the revokedCertificates definition in TBSCertList
/// ```text
/// RevokedCerts ::= SEQUENCE OF RevokedCert;
/// ```
pub type RevokedCerts<'a> = alloc::vec::Vec<RevokedCert<'a>>;

///```text
/// TBSCertList  ::=  SEQUENCE  {
///      version                 Version OPTIONAL,
///                                   -- if present, MUST be v2
///      signature               AlgorithmIdentifier,
///      issuer                  Name,
///      thisUpdate              Time,
///      nextUpdate              Time OPTIONAL,
///      revokedCertificates     SEQUENCE OF SEQUENCE  {
///           userCertificate         CertificateSerialNumber,
///           revocationDate          Time,
///           crlEntryExtensions      Extensions OPTIONAL
///                                    -- if present, version MUST be v2
///                                }  OPTIONAL,
///      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
///                                    -- if present, version MUST be v2
///                                }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TbsCertList<'a> {
    ///      version                 Version OPTIONAL,
    ///                                   -- if present, MUST be v2
    pub version: Version,
    ///      signature               AlgorithmIdentifier,
    pub signature: AlgorithmIdentifier<'a>,
    ///      issuer                  Name,
    pub issuer: Name<'a>,
    ///      thisUpdate              Time,
    pub this_update: Time,
    ///      nextUpdate              Time OPTIONAL,
    pub next_update: Option<Time>,
    ///      revokedCertificates     RevokedCerts
    pub revoked_certificates: Option<RevokedCerts<'a>>,
    ///      crlExtensions           \[0\]  EXPLICIT Extensions OPTIONAL
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub crl_extensions: Option<Extensions<'a>>,
}
