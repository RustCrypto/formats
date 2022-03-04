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
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
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
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct TbsRequest<'a> {
    #[asn1(
        context_specific = "0",
        default = "Default::default",
        tag_mode = "EXPLICIT"
    )]
    pub version: Version,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub requestor_name: Option<GeneralName<'a>>,

    pub request_list: alloc::vec::Vec<Request<'a>>,

    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    pub request_extensions: Option<Extensions<'a>>,
}

/// ```text
/// Signature ::= SEQUENCE {
///    signatureAlgorithm      AlgorithmIdentifier,
///    signature               BIT STRING,
///    certs                  [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct Signature<'a> {
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature: BitString<'a>,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub certs: Option<Vec<Certificate<'a>>>,
}

/// OCSP `Version` as defined in [RFC 6960 Section 4.1].
///
/// ```text
/// Version ::= INTEGER { v1(0) }
/// ```
///
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum Version {
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
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct Request<'a> {
    pub req_cert: CertId<'a>,

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
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CertId<'a> {
    pub hash_algorithm: AlgorithmIdentifier<'a>,
    pub issuer_name_hash: OctetString<'a>,
    pub issuer_key_hash: OctetString<'a>,
    pub serial_number: UIntBytes<'a>,
}

/// ```text
/// OCSPResponse ::= SEQUENCE {
///    responseStatus          OCSPResponseStatus,
///    responseBytes           [0] EXPLICIT ResponseBytes OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
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
#[derive(Enumerated, Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
#[allow(missing_docs)]
pub enum OcspResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}

/// ```text
/// ResponseBytes ::= SEQUENCE {
///    responseType            OBJECT IDENTIFIER,
///    response                OCTET STRING }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ResponseBytes<'a> {
    pub response_type: ObjectIdentifier,
    pub response: OctetString<'a>,
}

/// ```text
/// BasicOCSPResponse ::= SEQUENCE {
///   tbsResponseData          ResponseData,
///   signatureAlgorithm       AlgorithmIdentifier,
///   signature                BIT STRING,
///   certs                \[0\] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct BasicOcspResponse<'a> {
    pub tbs_response_data: ResponseData<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature: BitString<'a>,

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
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ResponseData<'a> {
    #[asn1(
        context_specific = "0",
        default = "Default::default",
        tag_mode = "EXPLICIT"
    )]
    pub version: Version,
    pub responder_id: ResponderId<'a>,
    pub produced_at: GeneralizedTime,
    pub responses: Vec<SingleResponse<'a>>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub response_extensions: Option<Extensions<'a>>,
}

/// ```text
// ResponderID ::= CHOICE {
///    byName              [1] Name,
///    byKey               [2] KeyHash }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum ResponderId<'a> {
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    ByName(Name<'a>),

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
pub type KeyHash<'a> = OctetString<'a>;

/// ```text
// SingleResponse ::= SEQUENCE {
///    certID                  CertID,
///    certStatus              CertStatus,
///    thisUpdate              GeneralizedTime,
///    nextUpdate              [0] EXPLICIT GeneralizedTime OPTIONAL,
///    singleExtensions        [1] EXPLICIT Extensions OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct SingleResponse<'a> {
    pub cert_id: CertId<'a>,
    pub cert_status: CertStatus,
    pub this_update: GeneralizedTime,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub next_update: Option<GeneralizedTime>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub single_request_extensions: Option<Extensions<'a>>,
}

/// ```text
/// CertStatus ::= CHOICE {
///    good                [0] IMPLICIT NULL,
///    revoked             [1] IMPLICIT RevokedInfo,
///    unknown             [2] IMPLICIT UnknownInfo }
/// ```
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

/// ```text
// RevokedInfo ::= SEQUENCE {
///    revocationTime          GeneralizedTime,
///    revocationReason        [0] EXPLICIT CRLReason OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct RevokedInfo {
    pub revocation_time: GeneralizedTime,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub revocation_reason: Option<CrlReason>,
}

/// ```text
/// UnknownInfo ::= NULL
/// ```
pub type UnknownInfo = Null;

/// ```text
// ArchiveCutoff ::= GeneralizedTime
/// ```
pub type ArchiveCutoff = GeneralizedTime;

/// ```text
// AcceptableResponses ::= SEQUENCE OF OBJECT IDENTIFIER
/// ```
pub type AcceptableResponses = Vec<ObjectIdentifier>;

/// ```text
/// ServiceLocator ::= SEQUENCE {
///    issuer                  Name,
///    locator                 AuthorityInfoAccessSyntax }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ServiceLocator<'a> {
    pub issuer: Name<'a>,
    pub locator: AuthorityInfoAccessSyntax<'a>,
}

/// ```text
/// CrlID ::= SEQUENCE {
///     crlUrl               [0] EXPLICIT IA5String OPTIONAL,
///     crlNum               [1] EXPLICIT INTEGER OPTIONAL,
///     crlTime              [2] EXPLICIT GeneralizedTime OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
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
/// ```
pub type PreferredSignatureAlgorithms<'a> = Vec<PreferredSignatureAlgorithm<'a>>;

/// ```text
/// PreferredSignatureAlgorithm ::= SEQUENCE {
///    sigIdentifier   AlgorithmIdentifier,
///    certIdentifier  AlgorithmIdentifier OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
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
