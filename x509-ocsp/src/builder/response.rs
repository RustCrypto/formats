//! OCSP response builder

use crate::{
    builder::Error, BasicOcspResponse, OcspGeneralizedTime, ResponderId, ResponseData,
    SingleResponse, Version,
};
use alloc::vec::Vec;
use der::{asn1::BitString, Encode};
use signature::{SignatureEncoding, Signer};
use spki::DynSignatureAlgorithmIdentifier;
use x509_cert::{
    ext::{AsExtension, Extensions},
    name::Name,
    Certificate,
};

/// X509 Basic OCSP Response builder
///
/// ```
/// use der::{asn1::ObjectIdentifier, DateTime, Decode};
/// use x509_cert::Certificate;
/// use x509_ocsp::builder::BasicOcspResponseBuilder;
/// use x509_ocsp::{ext::Nonce, CertStatus, OcspGeneralizedTime, OcspRequest, OcspResponse,
///     SingleResponse, Version,
/// };
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
/// )
/// .with_single_response(
///     SingleResponse::new(
///         req.tbs_request.request_list[0].req_cert.clone(),
///         CertStatus::good(),
///         OcspGeneralizedTime::from(DateTime::new(2023, 10, 31, 0, 0, 0).unwrap()),
///     )
///     .with_next_update(OcspGeneralizedTime::from(
///         DateTime::new(2024, 1, 1, 0, 0, 0).unwrap()
///     )),
/// );
///
/// if let Some(nonce) = req.nonce() {
///     builder = builder.with_extension(nonce).unwrap();
/// }
///
/// #[cfg(feature = "std")]
/// let now = OcspGeneralizedTime::try_from(std::time::SystemTime::now()).unwrap();
///
/// #[cfg(not(feature = "std"))]
/// let now = OcspGeneralizedTime::from(
///     DateTime::new(2023, 11, 1, 0, 0, 0).unwrap()
/// );
///
/// let mut signer = rsa_signer();
/// let signer_cert_chain = vec![ca.clone()];
/// let resp = OcspResponse::successful(
///     builder
///         .sign(&mut signer, Some(signer_cert_chain), now)
///         .unwrap(),
/// )
/// .unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct BasicOcspResponseBuilder {
    version: Version,
    responder_id: ResponderId,
    responses: Vec<SingleResponse>,
    response_extensions: Option<Extensions>,
}

impl BasicOcspResponseBuilder {
    /// Returns a `BasicOcspResponseBuilder` given the [`Version`], [`ResponderId`], and `Produced
    /// At` values.
    pub fn new(version: Version, responder_id: impl Into<ResponderId>) -> Self {
        let responder_id = responder_id.into();
        Self {
            version,
            responder_id,
            responses: Vec::new(),
            response_extensions: None,
        }
    }

    /// Adds a [`SingleResponse`] to the builder as defined in [RFC 6960 Section 4.2.1].
    ///
    /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
    pub fn with_single_response(mut self, single_response: SingleResponse) -> Self {
        self.responses.push(single_response);
        self
    }

    /// Adds a response extension as specified in [RFC 6960 Section 4.4]. Errors when the
    /// extension encoding fails.
    ///
    /// [RFC 6960 Section 4.4]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4
    pub fn with_extension(mut self, ext: impl AsExtension) -> Result<Self, Error> {
        let ext = ext.to_extension(&Name::default(), &[])?;
        match self.response_extensions {
            Some(ref mut exts) => exts.push(ext),
            None => self.response_extensions = Some(alloc::vec![ext]),
        }
        Ok(self)
    }

    /// Consumes the builder and returns a signed [`BasicOcspResponse`]. Errors when the algorithm
    /// identifier encoding, message encoding, or signature generation fails.
    ///
    /// Per [RFC 6960 Section 2.4], the `producedAt` value must be the time the request was
    /// signed.
    ///
    /// [RFC 6960 Section 2.4]: https://datatracker.ietf.org/doc/html/rfc6960#section-2.4
    pub fn sign<S, Sig>(
        self,
        signer: &mut S,
        certificate_chain: Option<Vec<Certificate>>,
        produced_at: OcspGeneralizedTime,
    ) -> Result<BasicOcspResponse, Error>
    where
        S: Signer<Sig> + DynSignatureAlgorithmIdentifier,
        Sig: SignatureEncoding,
    {
        let tbs_response_data = ResponseData {
            version: self.version,
            responder_id: self.responder_id,
            produced_at,
            responses: self.responses,
            response_extensions: self.response_extensions,
        };
        let signature_algorithm = signer.signature_algorithm_identifier()?;
        let signature = signer.try_sign(&tbs_response_data.to_der()?)?;
        let signature = BitString::from_bytes(signature.to_bytes().as_ref())?;
        Ok(BasicOcspResponse {
            tbs_response_data,
            signature_algorithm,
            signature,
            certs: certificate_chain,
        })
    }
}
