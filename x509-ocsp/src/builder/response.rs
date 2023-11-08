//! OCSP response builder

use crate::{
    builder::Error, BasicOcspResponse, OcspResponse, OcspResponseStatus, ResponderId,
    ResponseBytes, ResponseData, SingleResponse, Version,
};
use alloc::vec::Vec;
use const_oid::db::rfc6960::ID_PKIX_OCSP_BASIC;
use der::{
    asn1::{BitString, GeneralizedTime, OctetString},
    Encode,
};
use signature::{SignatureEncoding, Signer};
use spki::DynSignatureAlgorithmIdentifier;
use x509_cert::{ext::AsExtension, name::Name, Certificate};

impl OcspResponse {
    /// Encodes an `OcspResponse` with the status set to `Successful`
    ///
    /// [RFC 6960 Section 4.2.1]
    ///
    /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
    pub fn successful(basic: BasicOcspResponse) -> Result<Self, der::Error> {
        Ok(OcspResponse {
            response_status: OcspResponseStatus::Successful,
            response_bytes: Some(ResponseBytes {
                response_type: ID_PKIX_OCSP_BASIC,
                response: OctetString::new(basic.to_der()?)?,
            }),
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

/// X509 Basic OCSP Response builder
pub struct BasicOcspResponseBuilder {
    tbs_response_data: ResponseData,
}

impl BasicOcspResponseBuilder {
    /// Returns a `BasicOcspResponseBuilder` with the specified [`Version`], [`ResponderId`], and
    pub fn new(
        version: Version,
        responder_id: impl Into<ResponderId>,
        produced_at: GeneralizedTime,
    ) -> Self {
        let responder_id = responder_id.into();
        Self {
            tbs_response_data: ResponseData {
                version,
                responder_id,
                produced_at,
                responses: Vec::new(),
                response_extensions: None,
            },
        }
    }

    /// Adds a [`SingleResponse`] to the builder as defined in [RFC 6960 Section 4.2.1].
    ///
    /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
    pub fn with_single_response(mut self, single_response: SingleResponse) -> Self {
        self.tbs_response_data.responses.push(single_response);
        self
    }

    /// Adds a response extension as specified in [RFC 6960 Section 4.4]. Errors when the
    /// extension encoding fails.
    ///
    /// [RFC 6960 Section 4.4]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4
    pub fn with_extension(mut self, ext: impl AsExtension) -> Result<Self, Error> {
        let ext = ext.to_extension(&Name::default(), &[])?;
        match self.tbs_response_data.response_extensions {
            Some(ref mut exts) => exts.push(ext),
            None => self.tbs_response_data.response_extensions = Some(alloc::vec![ext]),
        }
        Ok(self)
    }

    /// Consumes the builder and returns a signed [`BasicOcspResponse`]. Errors when the algorithm
    /// identifier encoding, message encoding, or signature generation fails.
    pub fn sign<S, Sig>(
        self,
        signer: &mut S,
        certificate_chain: Option<Vec<Certificate>>,
    ) -> Result<BasicOcspResponse, Error>
    where
        S: Signer<Sig> + DynSignatureAlgorithmIdentifier,
        Sig: SignatureEncoding,
    {
        let signature_algorithm = signer.signature_algorithm_identifier()?;
        let signature = signer.try_sign(&self.tbs_response_data.to_der()?)?;
        let signature = BitString::from_bytes(signature.to_bytes().as_ref())?;
        Ok(BasicOcspResponse {
            tbs_response_data: self.tbs_response_data,
            signature_algorithm,
            signature,
            certs: certificate_chain,
        })
    }
}
