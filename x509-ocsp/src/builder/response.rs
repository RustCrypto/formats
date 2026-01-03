//! OCSP response builder

use crate::{
    BasicOcspResponse, OcspGeneralizedTime, OcspResponse, ResponderId, ResponseData,
    SingleResponse, Version, builder::Error,
};
use alloc::vec::Vec;
use der::Encode;
use rand_core::CryptoRng;
use signature::{RandomizedSigner, Signer};
use spki::{DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding};
use x509_cert::{
    Certificate,
    ext::{Extensions, ToExtension},
    name::Name,
};

/// X509 OCSP Response builder
///
/// ```
/// use der::{asn1::ObjectIdentifier, DateTime, Decode};
/// use x509_cert::Certificate;
/// use x509_ocsp::builder::OcspResponseBuilder;
/// use x509_ocsp::{ext::Nonce, CertStatus, OcspGeneralizedTime, OcspRequest, OcspResponse,
///     SingleResponse,
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
/// let mut builder = OcspResponseBuilder::new(ca.tbs_certificate().subject().clone())
///     .with_single_response(
///         SingleResponse::new(
///             req.tbs_request.request_list[0].req_cert.clone(),
///             CertStatus::good(),
///             OcspGeneralizedTime::from(DateTime::new(2023, 10, 31, 0, 0, 0).unwrap()),
///         )
///         .with_next_update(OcspGeneralizedTime::from(
///             DateTime::new(2024, 1, 1, 0, 0, 0).unwrap()
///         )),
///     );
///
/// if let Some(nonce) = req.nonce() {
///     builder = builder.with_extension(&nonce).unwrap();
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
/// let resp = builder
///     .sign(&mut signer, Some(signer_cert_chain), now)
///     .unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct OcspResponseBuilder {
    responder_id: ResponderId,
    responses: Vec<SingleResponse>,
    response_extensions: Option<Extensions>,
}

impl OcspResponseBuilder {
    /// Returns a `OcspResponseBuilder` given the [`Version`], [`ResponderId`], and `Produced
    /// At` values.
    pub fn new(responder_id: impl Into<ResponderId>) -> Self {
        let responder_id = responder_id.into();
        Self {
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
    pub fn with_extension<E: ToExtension>(mut self, ext: E) -> Result<Self, E::Error> {
        let ext = ext.to_extension(&Name::default(), &[])?;
        match self.response_extensions {
            Some(ref mut exts) => exts.push(ext),
            None => self.response_extensions = Some(alloc::vec![ext]),
        }
        Ok(self)
    }

    /// Consume the builder and returns [`ResponseData`]
    fn into_response_data(self, produced_at: OcspGeneralizedTime) -> ResponseData {
        ResponseData {
            version: Version::default(),
            responder_id: self.responder_id,
            produced_at,
            responses: self.responses,
            response_extensions: self.response_extensions,
        }
    }

    /// Consumes the builder and returns a signed [`OcspResponse`]. Errors when the algorithm
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
    ) -> Result<OcspResponse, Error>
    where
        S: Signer<Sig> + DynSignatureAlgorithmIdentifier,
        Sig: SignatureBitStringEncoding,
    {
        let tbs_response_data = self.into_response_data(produced_at);
        let signature_algorithm = signer.signature_algorithm_identifier()?;
        let signature = signer
            .try_sign(&tbs_response_data.to_der()?)?
            .to_bitstring()?;
        Ok(OcspResponse::successful(BasicOcspResponse {
            tbs_response_data,
            signature_algorithm,
            signature,
            certs: certificate_chain,
        })?)
    }

    /// Consumes the builder and returns a signed [`OcspResponse`]. Errors when the algorithm
    /// identifier encoding, message encoding, or signature generation fails.
    ///
    /// Per [RFC 6960 Section 2.4], the `producedAt` value must be the time the request was
    /// signed.
    ///
    /// [RFC 6960 Section 2.4]: https://datatracker.ietf.org/doc/html/rfc6960#section-2.4
    pub fn sign_with_rng<S, Sig, R>(
        self,
        signer: &mut S,
        rng: &mut R,
        certificate_chain: Option<Vec<Certificate>>,
        produced_at: OcspGeneralizedTime,
    ) -> Result<OcspResponse, Error>
    where
        S: RandomizedSigner<Sig> + DynSignatureAlgorithmIdentifier,
        Sig: SignatureBitStringEncoding,
        R: CryptoRng + ?Sized,
    {
        let tbs_response_data = self.into_response_data(produced_at);
        let signature_algorithm = signer.signature_algorithm_identifier()?;
        let signature = signer
            .try_sign_with_rng(rng, &tbs_response_data.to_der()?)?
            .to_bitstring()?;
        Ok(OcspResponse::successful(BasicOcspResponse {
            tbs_response_data,
            signature_algorithm,
            signature,
            certs: certificate_chain,
        })?)
    }
}
