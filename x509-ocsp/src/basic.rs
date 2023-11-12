//! Basic OCSP Response

use crate::AsResponseBytes;
use alloc::vec::Vec;
use const_oid::{db::rfc6960::ID_PKIX_OCSP_BASIC, AssociatedOid};
use core::{default::Default, option::Option};
use der::{
    asn1::{BitString, GeneralizedTime, Null, ObjectIdentifier, OctetString, UtcTime},
    Choice, DateTime, Decode, Enumerated, Sequence,
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    certificate::Certificate,
    crl::RevokedCert,
    ext::{pkix::CrlReason, Extensions},
    impl_newtype,
    name::Name,
    serial_number::SerialNumber,
    time::Time,
};

/// OCSP `Version` as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// Version ::= INTEGER { v1(0) }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Default, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Version {
    /// Version 1 (default)
    #[default]
    V1 = 0,
}

/// [`GeneralizedTime`] wrapper for easy conversion from legacy `UTC Time`
///
/// OCSP does not support legacy UTC Time while many other X.509 structures do.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OcspGeneralizedTime(pub GeneralizedTime);

impl_newtype!(OcspGeneralizedTime, GeneralizedTime);

#[cfg(feature = "std")]
impl TryFrom<std::time::SystemTime> for OcspGeneralizedTime {
    type Error = der::Error;

    fn try_from(other: std::time::SystemTime) -> Result<Self, Self::Error> {
        Ok(Self(GeneralizedTime::from_system_time(other)?))
    }
}

#[cfg(feature = "std")]
impl TryFrom<&std::time::SystemTime> for OcspGeneralizedTime {
    type Error = der::Error;

    fn try_from(other: &std::time::SystemTime) -> Result<Self, Self::Error> {
        Self::try_from(*other)
    }
}

impl From<DateTime> for OcspGeneralizedTime {
    fn from(other: DateTime) -> Self {
        Self(GeneralizedTime::from_date_time(other))
    }
}

impl From<&DateTime> for OcspGeneralizedTime {
    fn from(other: &DateTime) -> Self {
        Self::from(*other)
    }
}

impl From<UtcTime> for OcspGeneralizedTime {
    fn from(other: UtcTime) -> Self {
        Self(GeneralizedTime::from_date_time(other.to_date_time()))
    }
}

impl From<&UtcTime> for OcspGeneralizedTime {
    fn from(other: &UtcTime) -> Self {
        Self::from(*other)
    }
}

impl From<Time> for OcspGeneralizedTime {
    fn from(other: Time) -> Self {
        match other {
            Time::UtcTime(t) => t.into(),
            Time::GeneralTime(t) => t.into(),
        }
    }
}

impl From<&Time> for OcspGeneralizedTime {
    fn from(other: &Time) -> Self {
        Self::from(*other)
    }
}

/// BasicOcspResponse structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// BasicOCSPResponse ::= SEQUENCE {
///   tbsResponseData          ResponseData,
///   signatureAlgorithm       AlgorithmIdentifier,
///   signature                BIT STRING,
///   certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct BasicOcspResponse {
    pub tbs_response_data: ResponseData,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub certs: Option<Vec<Certificate>>,
}

impl AssociatedOid for BasicOcspResponse {
    const OID: ObjectIdentifier = ID_PKIX_OCSP_BASIC;
}

impl AsResponseBytes for BasicOcspResponse {}

/// ResponseData structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// ResponseData ::= SEQUENCE {
///    version              [0] EXPLICIT Version DEFAULT v1,
///    responderID             ResponderID,
///    producedAt              GeneralizedTime,
///    responses               SEQUENCE OF SingleResponse,
///    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ResponseData {
    #[asn1(
        context_specific = "0",
        default = "Default::default",
        tag_mode = "EXPLICIT"
    )]
    pub version: Version,
    pub responder_id: ResponderId,
    pub produced_at: OcspGeneralizedTime,
    pub responses: Vec<SingleResponse>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub response_extensions: Option<Extensions>,
}

/// ResponderID structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// ResponderID ::= CHOICE {
///    byName              [1] Name,
///    byKey               [2] KeyHash }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum ResponderId {
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    ByName(Name),

    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    ByKey(KeyHash),
}

impl From<Name> for ResponderId {
    fn from(other: Name) -> Self {
        Self::ByName(other)
    }
}

impl From<KeyHash> for ResponderId {
    fn from(other: KeyHash) -> Self {
        Self::ByKey(other)
    }
}

/// KeyHash structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
///                          -- (i.e., the SHA-1 hash of the value of the
///                          -- BIT STRING subjectPublicKey [excluding
///                          -- the tag, length, and number of unused
///                          -- bits] in the responder's certificate)
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
pub type KeyHash = OctetString;

/// SingleResponse structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// SingleResponse ::= SEQUENCE {
///    certID                  CertID,
///    certStatus              CertStatus,
///    thisUpdate              GeneralizedTime,
///    nextUpdate              [0] EXPLICIT GeneralizedTime OPTIONAL,
///    singleExtensions        [1] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct SingleResponse {
    pub cert_id: CertId,
    pub cert_status: CertStatus,
    pub this_update: OcspGeneralizedTime,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub next_update: Option<OcspGeneralizedTime>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub single_extensions: Option<Extensions>,
}

/// CertID structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// CertID ::= SEQUENCE {
///    hashAlgorithm           AlgorithmIdentifier,
///    issuerNameHash          OCTET STRING, -- Hash of issuer's DN
///    issuerKeyHash           OCTET STRING, -- Hash of issuer's public key
///    serialNumber            CertificateSerialNumber }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CertId {
    pub hash_algorithm: AlgorithmIdentifierOwned,
    pub issuer_name_hash: OctetString,
    pub issuer_key_hash: OctetString,
    pub serial_number: SerialNumber,
}

impl From<&CertId> for CertId {
    /// Clones the referenced `CertID`
    fn from(other: &CertId) -> Self {
        other.clone()
    }
}

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
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
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
    /// Returns `CertStatus` set to `Good` as defined in [RFC 6960 Section 4.2.1]
    ///
    /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
    pub fn good() -> Self {
        Self::Good(Null)
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
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
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

impl From<&RevokedCert> for RevokedInfo {
    /// Converts [`RevokedCert`] to [`RevokedInfo`].
    ///
    /// Attempts to extract the [`CrlReason`]. If it fails, the `CrlReason` is set to `None`.
    fn from(rc: &RevokedCert) -> Self {
        Self {
            revocation_time: rc.revocation_date.into(),
            revocation_reason: if let Some(extensions) = &rc.crl_entry_extensions {
                let mut filter = extensions
                    .iter()
                    .filter(|ext| ext.extn_id == CrlReason::OID);
                match filter.next() {
                    None => None,
                    Some(ext) => match CrlReason::from_der(ext.extn_value.as_bytes()) {
                        Ok(reason) => Some(reason),
                        Err(_) => None,
                    },
                }
            } else {
                None
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
