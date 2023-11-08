//! OCSP response builder

use crate::{
    builder::Error, BasicOcspResponse, CertId, CertStatus, OcspResponse, OcspResponseStatus,
    ResponderId, ResponseBytes, ResponseData, SingleResponse, Version,
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
///
/// ```
/// use der::{
///     asn1::{GeneralizedTime, ObjectIdentifier},
///     DateTime, Decode,
/// };
/// use std::time::SystemTime;
/// use x509_cert::Certificate;
/// use x509_ocsp::builder::BasicOcspResponseBuilder;
/// use x509_ocsp::{ext::Nonce, CertStatus, OcspRequest, OcspResponse, SingleResponse, Version};
///
/// const NONCE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");
///
/// # const OCSP_REQ_DER: &[u8] = include_bytes!(
/// #     "../../tests/examples/ocsp-multiple-requests-nonce-req.der"
/// # );
/// # const CA_DER: &[u8] = include_bytes!("../../tests/examples/rsa-2048-sha256-ca.der");
/// # const CA_KEY_DER: &[u8] = include_bytes!("../../tests/examples/rsa-2048-sha256-ca-key.der");
/// # use rsa::{pkcs1v15::SigningKey, pkcs8::DecodePrivateKey};
/// # use sha2::Sha256;
/// # fn rsa_signer() -> SigningKey<Sha256> {
/// #     let private_key = rsa::RsaPrivateKey::from_pkcs8_der(CA_KEY_DER).unwrap();
/// #     let signing_key = SigningKey::<Sha256>::new(private_key);
/// #     signing_key
/// # }
/// let req = OcspRequest::from_der(OCSP_REQ_DER).unwrap();
/// let ca = Certificate::from_der(CA_DER).unwrap();
///
/// let mut builder = BasicOcspResponseBuilder::new(
///     Version::V1,
///     ca.tbs_certificate.subject.clone(),
///     GeneralizedTime::from_system_time(SystemTime::now()).unwrap(),
/// )
/// .with_single_response(SingleResponse::new(
///     req.tbs_request.request_list[0].req_cert.clone(),
///     CertStatus::good(),
///     GeneralizedTime::from_date_time(DateTime::new(2023, 10, 31, 0, 0, 0).unwrap()),
/// ));
///
/// if let Some(extns) = req.tbs_request.request_extensions {
///     let mut filter = extns.iter().filter(|e| e.extn_id == NONCE_OID);
///     if let Some(extn) = filter.next() {
///         builder = builder
///             .with_extension(Nonce::from_der(extn.extn_value.as_bytes()).unwrap())
///             .unwrap();
///     }
/// }
///
/// let mut signer = rsa_signer();
/// let signer_cert_chain = vec![ca.clone()];
/// let resp =
///     OcspResponse::successful(builder.sign(&mut signer, Some(signer_cert_chain)).unwrap())
///         .unwrap();
/// ```
pub struct BasicOcspResponseBuilder {
    tbs_response_data: ResponseData,
}

impl BasicOcspResponseBuilder {
    /// Returns a `BasicOcspResponseBuilder` given the [`Version`], [`ResponderId`], and `Produced
    /// At` values.
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

impl SingleResponse {
    /// Returns a `SingleResponse` given the `CertID`, `CertStatus`, and `This Update`. `Next
    /// Update` is set to `None`.
    pub fn new(cert_id: CertId, cert_status: CertStatus, this_update: GeneralizedTime) -> Self {
        Self {
            cert_id,
            cert_status,
            this_update,
            next_update: None,
            single_extensions: None,
        }
    }

    /// Adds a `Next Update` to the builder as defined in [RFC 6960 Section 4.2.1].
    ///
    /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
    pub fn with_next_update(mut self, next_update: GeneralizedTime) -> Self {
        self.next_update = Some(next_update);
        self
    }

    /// Adds a single response extension as specified in [RFC 6960 Section 4.4]. Errors when the
    /// extension encoding fails.
    ///
    /// [RFC 6960 Section 4.4]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4
    pub fn with_extension(mut self, ext: impl AsExtension) -> Result<Self, Error> {
        let ext = ext.to_extension(&Name::default(), &[])?;
        match self.single_extensions {
            Some(ref mut exts) => exts.push(ext),
            None => self.single_extensions = Some(alloc::vec![ext]),
        }
        Ok(self)
    }
}
