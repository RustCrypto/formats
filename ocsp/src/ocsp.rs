use der::asn1::{BitString, Ia5String, ObjectIdentifier, OctetString, UIntBytes};
use der::asn1::{GeneralizedTime, Null};
use der::{Any, Choice, Enumerated, Sequence};
use spki::AlgorithmIdentifier;
use x509::ext::pkix::name::GeneralName;
use x509::ext::pkix::{AuthorityInfoAccessSyntax, CrlReason};
use x509::ext::Extensions;
use x509::name::Name;
use x509::Certificate;

/// ```text
/// OCSPRequest ::= SEQUENCE {
///    tbsRequest              TBSRequest,
///    optionalSignature   [0] EXPLICIT Signature OPTIONAL }
/// ```
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct OcspRequest<'a> {
    pub tbs_request: TbsRequest<'a>,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub optional_signature: Option<Signature<'a>>,
}

/// ```text
/// TBSRequest ::= SEQUENCE {
///    version             [0] EXPLICIT Version DEFAULT v1,
///    requestorName       [1] EXPLICIT GeneralName OPTIONAL,
///    requestList             SEQUENCE OF Request,
///    requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
/// ```
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TbsRequest<'a> {
    ///    version             \[0\] EXPLICIT Version DEFAULT v1,
    #[asn1(
        context_specific = "0",
        default = "Default::default",
        tag_mode = "EXPLICIT"
    )]
    pub version: Version,

    ///    requestorName       \[1\] EXPLICIT GeneralName OPTIONAL,
    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub requestor_name: Option<GeneralName<'a>>,

    ///    requestList             SEQUENCE OF Request,
    pub request_list: alloc::vec::Vec<Request<'a>>,

    ///    requestExtensions   \[2\] EXPLICIT Extensions OPTIONAL }
    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    pub request_extensions: Option<Extensions<'a>>,
}

/// ```text
/// Signature ::= SEQUENCE {
///    signatureAlgorithm      AlgorithmIdentifier,
///    signature               BIT STRING,
///    certs                  [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ```
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Signature<'a> {
    ///    signatureAlgorithm      AlgorithmIdentifier,
    pub signature_algorithm: AlgorithmIdentifier<'a>,

    ///    signature               BIT STRING,
    pub signature: BitString<'a>,

    ///    certs               \[0\] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub certs: Option<Vec<Certificate<'a>>>,
}

/// OCSP `Version` as defined in [RFC 6960 Section 4.1].
///
/// ```text
/// Version ::= INTEGER { v1(0) }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Version {
    /// Version 1 (default)
    V1 = 0,
}

impl Default for Version {
    fn default() -> Self {
        Self::V1
    }
}

/// ```text
/// Request ::= SEQUENCE {
///    reqCert                     CertID,
///    singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
/// ```
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Request<'a> {
    ///    reqCert                     CertID,
    pub req_cert: CertId<'a>,

    ///    singleRequestExtensions \[0\] EXPLICIT Extensions OPTIONAL }
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub single_request_extensions: Option<Extensions<'a>>,
}

/// ```text
/// CertID ::= SEQUENCE {
///    hashAlgorithm           AlgorithmIdentifier,
///    issuerNameHash          OCTET STRING, -- Hash of issuer's DN
///    issuerKeyHash           OCTET STRING, -- Hash of issuer's public key
///    serialNumber            CertificateSerialNumber }
/// ```
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CertId<'a> {
    ///    hashAlgorithm           AlgorithmIdentifier,
    pub hash_algorithm: AlgorithmIdentifier<'a>,

    ///    issuerNameHash          OCTET STRING, -- Hash of issuer's DN
    pub issuer_name_hash: OctetString<'a>,

    ///    issuerKeyHash           OCTET STRING, -- Hash of issuer's public key
    pub issuer_key_hash: OctetString<'a>,

    ///    serialNumber            CertificateSerialNumber }
    pub serial_number: UIntBytes<'a>,
}

/// ```text
/// OCSPResponse ::= SEQUENCE {
///    responseStatus          OCSPResponseStatus,
///    responseBytes           [0] EXPLICIT ResponseBytes OPTIONAL }
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct OcspResponse<'a> {
    pub response_status: OcspResponseStatus,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub response_bytes: Option<ResponseBytes<'a>>,
}

/// ```text
/// OCSPResponseStatus ::= ENUMERATED {
///    successful          (0),  -- Response has valid confirmations
///    malformedRequest    (1),  -- Illegal confirmation request
///    internalError       (2),  -- Internal error in issuer
///    tryLater            (3),  -- Try again later
///                              -- (4) is not used
///    sigRequired         (5),  -- Must sign the request
///    unauthorized        (6)   -- Request unauthorized
/// }
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Enumerated, Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum OcspResponseStatus {
    ///    successful          (0),  -- Response has valid confirmations
    Successful = 0,

    ///    malformedRequest    (1),  -- Illegal confirmation request
    MalformedRequest = 1,

    ///    internalError       (2),  -- Internal error in issuer
    InternalError = 2,

    ///    tryLater            (3),  -- Try again later
    TryLater = 3,

    //                              -- (4) is not used
    ///    sigRequired         (5),  -- Must sign the request
    SigRequired = 5,

    ///    unauthorized        (6)   -- Request unauthorized
    Unauthorized = 6,
}

/// ```text
/// ResponseBytes ::= SEQUENCE {
///    responseType            OBJECT IDENTIFIER,
///    response                OCTET STRING }
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ResponseBytes<'a> {
    ///    responseType            OBJECT IDENTIFIER,
    pub response_type: ObjectIdentifier,

    ///    response                OCTET STRING }
    pub response: OctetString<'a>,
}

/// ```text
/// BasicOCSPResponse ::= SEQUENCE {
///   tbsResponseData          ResponseData,
///   signatureAlgorithm       AlgorithmIdentifier,
///   signature                BIT STRING,
///   certs                \[0\] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct BasicOcspResponse<'a> {
    ///   tbsResponseData          ResponseData,
    pub tbs_response_data: ResponseData<'a>,

    ///   signatureAlgorithm       AlgorithmIdentifier,
    pub signature_algorithm: AlgorithmIdentifier<'a>,

    ///   signature                BIT STRING,
    pub signature: BitString<'a>,

    ///    certs               \[0\] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub certs: Option<alloc::vec::Vec<Any<'a>>>,
}

/// ```text
// ResponseData ::= SEQUENCE {
///    version              [0] EXPLICIT Version DEFAULT v1,
///    responderID             ResponderID,
///    producedAt              GeneralizedTime,
///    responses               SEQUENCE OF SingleResponse,
///    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ResponseData<'a> {
    ///    version             \[0\] EXPLICIT Version DEFAULT v1,
    #[asn1(
        context_specific = "0",
        default = "Default::default",
        tag_mode = "EXPLICIT"
    )]
    pub version: Version,

    ///    responderID             ResponderID,
    pub responder_id: ResponderId<'a>,

    ///    producedAt              GeneralizedTime,
    pub produced_at: GeneralizedTime,

    ///    responses               SEQUENCE OF SingleResponse,
    pub responses: Vec<SingleResponse<'a>>,

    ///    responseExtensions  \[1\] EXPLICIT Extensions OPTIONAL }
    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub response_extensions: Option<Extensions<'a>>,
}

/// ```text
// ResponderID ::= CHOICE {
///    byName              [1] Name,
///    byKey               [2] KeyHash }
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum ResponderId<'a> {
    ///    byName              \[1\] Name,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    ByName(Name<'a>),

    ///    byKey               \[2\] KeyHash }
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    ByKey(KeyHash<'a>),
}

/// ```text
/// KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
///                          -- (i.e., the SHA-1 hash of the value of the
///                          -- BIT STRING subjectPublicKey [excluding
///                          -- the tag, length, and number of unused
///                          -- bits] in the responder's certificate)
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
pub type KeyHash<'a> = OctetString<'a>;

/// ```text
// SingleResponse ::= SEQUENCE {
///    certID                  CertID,
///    certStatus              CertStatus,
///    thisUpdate              GeneralizedTime,
///    nextUpdate              [0] EXPLICIT GeneralizedTime OPTIONAL,
///    singleExtensions        [1] EXPLICIT Extensions OPTIONAL }
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SingleResponse<'a> {
    ///    certID                  CertID,
    pub cert_id: CertId<'a>,

    ///    certStatus              CertStatus,
    pub cert_status: CertStatus,

    ///    thisUpdate              GeneralizedTime,
    pub this_update: GeneralizedTime,

    ///    nextUpdate          \[0\] EXPLICIT GeneralizedTime OPTIONAL,
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub next_update: Option<GeneralizedTime>,

    ///    singleExtensions    \[1\] EXPLICIT Extensions OPTIONAL }
    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub single_request_extensions: Option<Extensions<'a>>,
}

/// ```text
/// CertStatus ::= CHOICE {
///    good                [0] IMPLICIT NULL,
///    revoked             [1] IMPLICIT RevokedInfo,
///    unknown             [2] IMPLICIT UnknownInfo }
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum CertStatus {
    ///    good                \[0\] IMPLICIT NULL,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Good(Null),

    ///    revoked             \[1\] IMPLICIT RevokedInfo,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Revoked(RevokedInfo),

    ///    unknown             \[2\] IMPLICIT UnknownInfo }
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    Unknown(UnknownInfo),
}

/// ```text
// RevokedInfo ::= SEQUENCE {
///    revocationTime          GeneralizedTime,
///    revocationReason        [0] EXPLICIT CRLReason OPTIONAL }
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct RevokedInfo {
    ///    revocationTime          GeneralizedTime,
    pub revocation_time: GeneralizedTime,

    ///    revocationReason    \[0\] EXPLICIT CRLReason OPTIONAL }
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub revocation_reason: Option<CrlReason>,
}

/// ```text
/// UnknownInfo ::= NULL
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
pub type UnknownInfo = Null;

/// ```text
// ArchiveCutoff ::= GeneralizedTime
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
pub type ArchiveCutoff = GeneralizedTime;

/// ```text
// AcceptableResponses ::= SEQUENCE OF OBJECT IDENTIFIER
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
pub type AcceptableResponses = Vec<ObjectIdentifier>;

/// ```text
/// ServiceLocator ::= SEQUENCE {
///    issuer                  Name,
///    locator                 AuthorityInfoAccessSyntax }
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ServiceLocator<'a> {
    ///    issuer                  Name,
    pub issuer: Name<'a>,

    ///    locator                 AuthorityInfoAccessSyntax }
    pub locator: AuthorityInfoAccessSyntax<'a>,
}

/// ```text
/// CrlID ::= SEQUENCE {
///     crlUrl               [0] EXPLICIT IA5String OPTIONAL,
///     crlNum               [1] EXPLICIT INTEGER OPTIONAL,
///     crlTime              [2] EXPLICIT GeneralizedTime OPTIONAL }
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CrlId<'a> {
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub crl_url: Option<Ia5String<'a>>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub crl_num: Option<UIntBytes<'a>>,

    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    pub crl_time: Option<GeneralizedTime>,
}

/// ```text
/// PreferredSignatureAlgorithms ::= SEQUENCE OF PreferredSignatureAlgorithm
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
pub type PreferredSignatureAlgorithms<'a> = Vec<PreferredSignatureAlgorithm<'a>>;

/// ```text
/// PreferredSignatureAlgorithm ::= SEQUENCE {
///    sigIdentifier   AlgorithmIdentifier,
///    certIdentifier  AlgorithmIdentifier OPTIONAL }
/// ```
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PreferredSignatureAlgorithm<'a> {
    pub sig_identifier: AlgorithmIdentifier<'a>,
    pub cert_identifier: Option<AlgorithmIdentifier<'a>>,
}

// Object Identifiers
//       id-pkix  OBJECT IDENTIFIER  ::=
//                { iso(1) identified-organization(3) dod(6) internet(1)
//                        security(5) mechanisms(5) pkix(7) }
// id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }

/// id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
pub const KP_OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");

// id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
// id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }

/// id-pkix-ocsp                 OBJECT IDENTIFIER ::= { id-ad-ocsp }
pub const OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");

/// id-pkix-ocsp-basic           OBJECT IDENTIFIER ::= { id-pkix-ocsp 1 }
pub const OCSP_BASIC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");

/// id-pkix-ocsp-nonce           OBJECT IDENTIFIER ::= { id-pkix-ocsp 2 }
pub const OCSP_NONCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");

/// id-pkix-ocsp-crl             OBJECT IDENTIFIER ::= { id-pkix-ocsp 3 }
pub const OCSP_CRL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.3");

/// id-pkix-ocsp-response        OBJECT IDENTIFIER ::= { id-pkix-ocsp 4 }
pub const OCSP_RESPONSE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.4");

/// id-pkix-ocsp-nocheck         OBJECT IDENTIFIER ::= { id-pkix-ocsp 5 }
pub const OCSP_NOCHECK: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.5");

/// id-pkix-ocsp-archive-cutoff  OBJECT IDENTIFIER ::= { id-pkix-ocsp 6 }
pub const KP_OCSP_ARCHIVE_CUTOFF: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.6");

/// id-pkix-ocsp-service-locator OBJECT IDENTIFIER ::= { id-pkix-ocsp 7 }
pub const OCSP_SERVICE_LOCATOR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.7");

/// id-pkix-ocsp-pref-sig-algs   OBJECT IDENTIFIER ::= { id-pkix-ocsp 8 }
pub const OCSP_PREF_SIG_ALGS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.8");

/// id-pkix-ocsp-extended-revoke OBJECT IDENTIFIER ::= { id-pkix-ocsp 9 }
pub const OCSP_EXTENDED_REVOKE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.9");
