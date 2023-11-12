//! OCSP response builder

use crate::{
    builder::Error, AsResponseBytes, BasicOcspResponse, CertId, CertStatus, OcspGeneralizedTime,
    OcspResponse, OcspResponseStatus, ResponderId, ResponseData, SingleResponse, Version,
};
use alloc::vec::Vec;
use const_oid::AssociatedOid;
use der::{asn1::BitString, Encode};
use digest::Digest;
use signature::{SignatureEncoding, Signer};
use spki::DynSignatureAlgorithmIdentifier;
use x509_cert::{
    crl::CertificateList,
    ext::{AsExtension, Extensions},
    name::Name,
    serial_number::SerialNumber,
    Certificate,
};

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

/// X509 Basic OCSP Response builder
///
/// ```
/// use der::{asn1::ObjectIdentifier, DateTime, Decode};
/// use x509_cert::Certificate;
/// use x509_ocsp::builder::BasicOcspResponseBuilder;
/// use x509_ocsp::{ext::Nonce, CertStatus, OcspGeneralizedTime, OcspRequest, OcspResponse, SingleResponse,
///     Version
/// };
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
/// if let Some(extns) = req.tbs_request.request_extensions {
///     let mut filter = extns.iter().filter(|e| e.extn_id == NONCE_OID);
///     if let Some(extn) = filter.next() {
///         builder = builder
///             .with_extension(Nonce::from_der(extn.extn_value.as_bytes()).unwrap())
///             .unwrap();
///     }
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
            produced_at: produced_at,
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

impl SingleResponse {
    /// Returns a `SingleResponse` given the `CertID`, `CertStatus`, and `This Update`. `Next
    /// Update` is set to `None`.
    pub fn new(cert_id: CertId, cert_status: CertStatus, this_update: OcspGeneralizedTime) -> Self {
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
    pub fn with_next_update(mut self, next_update: OcspGeneralizedTime) -> Self {
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

    /// Returns a `SingleResponse` by searching through the CRL to see if `serial` is revoked. If
    /// not, the `CertStatus` is set to good. The `CertID` is built from the issuer and serial
    /// number. This method does not ensure the CRL is issued by the issuer and only asserts that
    /// the serial is not revoked in the provided CRL.
    pub fn from_crl<D>(
        issuer: &Certificate,
        crl: &CertificateList,
        serial_number: SerialNumber,
    ) -> Result<Self, Error>
    where
        D: Digest + AssociatedOid,
    {
        let cert_status = match &crl.tbs_cert_list.revoked_certificates {
            Some(revoked_certs) => {
                let mut filter = revoked_certs
                    .iter()
                    .filter(|rc| rc.serial_number == serial_number);
                match filter.next() {
                    None => CertStatus::good(),
                    Some(rc) => CertStatus::Revoked(rc.into()),
                }
            }
            None => CertStatus::good(),
        };
        let cert_id = CertId::from_issuer::<D>(issuer, serial_number)?;
        let this_update = crl.tbs_cert_list.this_update.into();
        let next_update = match crl.tbs_cert_list.next_update {
            Some(t) => Some(t.into()),
            None => None,
        };
        Ok(Self {
            cert_id,
            cert_status,
            this_update,
            next_update,
            single_extensions: None,
        })
    }
}
