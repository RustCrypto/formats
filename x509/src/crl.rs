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
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CertificateList<'a> {
    pub tbs_cert_list: TbsCertList<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
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
#[allow(missing_docs)]
pub struct RevokedCert<'a> {
    pub serial_number: UIntBytes<'a>,
    pub revocation_date: Time,
    pub crl_entry_extensions: Option<Extensions<'a>>,
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
#[allow(missing_docs)]
pub struct TbsCertList<'a> {
    pub version: Version,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: Name<'a>,
    pub this_update: Time,
    pub next_update: Option<Time>,
    pub revoked_certificates: Option<RevokedCerts<'a>>,

    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub crl_extensions: Option<Extensions<'a>>,
}
