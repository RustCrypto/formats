//! X.509 OCSP CertStatus

use crate::OcspGeneralizedTime;
use const_oid::AssociatedOid;
use core::option::Option;
use der::{Choice, Decode, Sequence, asn1::Null};
use x509_cert::{crl::RevokedCert, ext::pkix::CrlReason};

/// CertStatus structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// CertStatus ::= CHOICE {
///    good                [0] IMPLICIT NULL,
///    revoked             [1] IMPLICIT RevokedInfo,
///    unknown             [2] IMPLICIT UnknownInfo }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Copy, Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum CertStatus {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Good(Null),

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Revoked(RevokedInfo),

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    Unknown(UnknownInfo),
}

impl CertStatus {
    /// Returns `CertStatus` set to `good` as defined in [RFC 6960 Section 4.2.1]
    ///
    /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
    pub fn good() -> Self {
        Self::Good(Null)
    }

    /// Returns `CertStatus` set to `revoked` as defined in [RFC 6960 Section 4.2.1]
    ///
    /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
    pub fn revoked(info: impl Into<RevokedInfo>) -> Self {
        Self::Revoked(info.into())
    }

    /// Returns `CertStatus` set to `unknown` as defined in [RFC 6960 Section 4.2.1]
    ///
    /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
    pub fn unknown() -> Self {
        Self::Unknown(Null)
    }
}

/// RevokedInfo structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// RevokedInfo ::= SEQUENCE {
///    revocationTime          GeneralizedTime,
///    revocationReason        [0] EXPLICIT CRLReason OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct RevokedInfo {
    pub revocation_time: OcspGeneralizedTime,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub revocation_reason: Option<CrlReason>,
}

/// RevokedInfo structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// UnknownInfo ::= NULL
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
pub type UnknownInfo = Null;

impl From<&RevokedInfo> for RevokedInfo {
    fn from(info: &RevokedInfo) -> Self {
        *info
    }
}

impl From<&RevokedCert> for RevokedInfo {
    /// Converts [`RevokedCert`] to [`RevokedInfo`].
    ///
    /// Attempts to extract the [`CrlReason`]. If it fails, the `CrlReason` is set to `None`.
    fn from(rc: &RevokedCert) -> Self {
        Self {
            revocation_time: rc.revocation_date.into(),
            revocation_reason: match &rc.crl_entry_extensions {
                Some(extns) => {
                    let mut filter = extns.iter().filter(|extn| extn.extn_id == CrlReason::OID);
                    match filter.next() {
                        Some(extn) => CrlReason::from_der(extn.extn_value.as_bytes()).ok(),
                        None => None,
                    }
                }
                None => None,
            },
        }
    }
}

impl From<RevokedCert> for RevokedInfo {
    /// Converts [`RevokedCert`] to [`RevokedInfo`].
    ///
    /// Attempts to extract the [`CrlReason`]. If it fails, the `CrlReason` is set to `None`.
    fn from(rc: RevokedCert) -> Self {
        Self::from(&rc)
    }
}
