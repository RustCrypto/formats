//! OCSP Response

use const_oid::AssociatedOid;
use core::option::Option;
use der::{
    Enumerated, Sequence,
    asn1::{Null, ObjectIdentifier, OctetString},
};

/// OcspNoCheck as defined in [RFC 6960 Section 4.2.2.2.1].
///
/// This extension is identified by the ID_PKIX_OCSP_NOCHECK OID.
///
/// ```text
/// OcspNoCheck ::= NULL
/// ```
///
/// [RFC 6960 Section 4.2.2.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.2.2.1
pub type OcspNoCheck = Null;

/// OCSPResponse structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// OCSPResponse ::= SEQUENCE {
///    responseStatus          OCSPResponseStatus,
///    responseBytes           [0] EXPLICIT ResponseBytes OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct OcspResponse {
    pub response_status: OcspResponseStatus,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub response_bytes: Option<ResponseBytes>,
}

impl OcspResponse {
    /// Encodes an `OcspResponse` with the status set to `Successful`
    ///
    /// [RFC 6960 Section 4.2.1]
    ///
    /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
    pub fn successful(res: impl AsResponseBytes) -> Result<Self, der::Error> {
        Ok(OcspResponse {
            response_status: OcspResponseStatus::Successful,
            response_bytes: Some(res.to_response_bytes()?),
        })
    }

    /// Encodes an `OcspResponse` with the status set to `MalformedRequest`
    ///
    /// [RFC 6960 Section 4.2.1]
    ///
    /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
    pub fn malformed_request() -> Self {
        OcspResponse {
            response_status: OcspResponseStatus::MalformedRequest,
            response_bytes: None,
        }
    }

    /// Encodes an `OcspResponse` with the status set to `InternalError`
    ///
    /// [RFC 6960 Section 4.2.1]
    ///
    /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
    pub fn internal_error() -> Self {
        OcspResponse {
            response_status: OcspResponseStatus::InternalError,
            response_bytes: None,
        }
    }

    /// Encodes an `OcspResponse` with the status set to `TryLater`
    ///
    /// [RFC 6960 Section 4.2.1]
    ///
    /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
    pub fn try_later() -> Self {
        OcspResponse {
            response_status: OcspResponseStatus::TryLater,
            response_bytes: None,
        }
    }

    /// Encodes an `OcspResponse` with the status set to `SigRequired`
    ///
    /// [RFC 6960 Section 4.2.1]
    ///
    /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
    pub fn sig_required() -> Self {
        OcspResponse {
            response_status: OcspResponseStatus::SigRequired,
            response_bytes: None,
        }
    }

    /// Encodes an `OcspResponse` with the status set to `Unauthorized`
    ///
    /// [RFC 6960 Section 4.2.1]
    ///
    /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
    pub fn unauthorized() -> Self {
        OcspResponse {
            response_status: OcspResponseStatus::Unauthorized,
            response_bytes: None,
        }
    }
}

/// OCSPResponseStatus structure as defined in [RFC 6960 Section 4.2.1].
///
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
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
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

/// ResponseBytes structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// ResponseBytes ::= SEQUENCE {
///    responseType            OBJECT IDENTIFIER,
///    response                OCTET STRING }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ResponseBytes {
    pub response_type: ObjectIdentifier,
    pub response: OctetString,
}

/// Trait for encoding [`ResponseBytes`]
pub trait AsResponseBytes: AssociatedOid + der::Encode {
    /// Encodes the response bytes of successful OCSP responses
    fn to_response_bytes(&self) -> Result<ResponseBytes, der::Error> {
        Ok(ResponseBytes {
            response_type: <Self as AssociatedOid>::OID,
            response: OctetString::new(self.to_der()?)?,
        })
    }
}
