//! Certificate key pair-related types

use alloc::vec::Vec;
use der::{Choice, Sequence};

use crmf::controls::{EncryptedValue, PkiPublicationInfo};

use crate::header::CMPCertificate;
use crate::status::PkiStatusInfo;

/// The `CertifiedKeyPair` type is defined in [RFC 4210 Section 5.3.4]
///
/// ```text
///  CertifiedKeyPair ::= SEQUENCE {
///      certOrEncCert       CertOrEncCert,
///      privateKey      [0] EncryptedValue      OPTIONAL,
///      publicationInfo [1] PKIPublicationInfo  OPTIONAL }
/// ```
///
/// [RFC 4210 Section 5.3.4]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CertifiedKeyPair {
    pub cert_or_enc_cert: CertOrEncCert,
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub priv_key: Option<EncryptedValue>,
    #[asn1(
        context_specific = "1",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub publication_info: Option<PkiPublicationInfo>,
}

/// The `CertOrEncCert` type is defined in [RFC 4210 Section 5.3.4]
///
/// ```text
///  CertOrEncCert ::= CHOICE {
///      certificate     [0] CMPCertificate,
///      encryptedCert   [1] EncryptedValue }
/// ```
///
/// [RFC 4210 Section 5.3.4]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.4
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
#[allow(clippy::large_enum_variant)]
pub enum CertOrEncCert {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", constructed = "true")]
    Certificate(CMPCertificate),

    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    EncryptedCert(EncryptedValue),
}

/// The `KeyRecRepContent` type is defined in [RFC 4210 Section 5.3.8]
///
/// ```text
///  KeyRecRepContent ::= SEQUENCE {
///      status                  PKIStatusInfo,
///      newSigCert          [0] CMPCertificate OPTIONAL,
///      caCerts             [1] SEQUENCE SIZE (1..MAX) OF
///                                       CMPCertificate OPTIONAL,
///      keyPairHist         [2] SEQUENCE SIZE (1..MAX) OF
///                                       CertifiedKeyPair OPTIONAL }
/// ```
///
/// [RFC 4210 Section 5.3.8]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.8
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct KeyRecRepContent<'a> {
    pub status: PkiStatusInfo<'a>,
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub new_sig_cert: Option<CMPCertificate>,
    #[asn1(
        context_specific = "1",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub ca_certs: Option<Vec<CMPCertificate>>,
    #[asn1(
        context_specific = "2",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub key_pair_hist: Option<Vec<CertifiedKeyPair>>,
}
