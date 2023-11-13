//! Basic OCSP Response

use crate::{ext::Nonce, AsResponseBytes, OcspGeneralizedTime};
use alloc::vec::Vec;
use const_oid::{
    db::rfc6960::{ID_PKIX_OCSP_BASIC, ID_PKIX_OCSP_NONCE},
    AssociatedOid,
};
use core::{default::Default, option::Option};
use der::{
    asn1::{BitString, Null, ObjectIdentifier, OctetString},
    Choice, Decode, Enumerated, Sequence,
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    certificate::Certificate,
    crl::RevokedCert,
    ext::{pkix::CrlReason, Extensions},
    name::Name,
    serial_number::SerialNumber,
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

impl BasicOcspResponse {
    /// Returns the response's nonce value, if any. This method will return `None` if the response
    /// has no `Nonce` extension or decoding of the `Nonce` extension fails.
    pub fn nonce(&self) -> Option<Nonce> {
        self.tbs_response_data.nonce()
    }
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

impl ResponseData {
    /// Returns the response's nonce value, if any. This method will return `None` if the response
    /// has no `Nonce` extension or decoding of the `Nonce` extension fails.
    pub fn nonce(&self) -> Option<Nonce> {
        match &self.response_extensions {
            Some(extns) => {
                let mut filter = extns.iter().filter(|e| e.extn_id == ID_PKIX_OCSP_NONCE);
                match filter.next() {
                    Some(extn) => Nonce::from_der(extn.extn_value.as_bytes()).ok(),
                    None => None,
                }
            }
            None => None,
        }
    }
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
