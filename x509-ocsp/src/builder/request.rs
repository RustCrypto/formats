//! OCSP request builder

use crate::{OcspRequest, Request, Signature, TbsRequest, Version, builder::Error};
use alloc::vec::Vec;
use der::Encode;
use rand_core::CryptoRng;
use signature::{RandomizedSigner, Signer};
use spki::{DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding};
use x509_cert::{
    Certificate,
    certificate::Rfc5280,
    ext::{ToExtension, pkix::name::GeneralName},
    name::Name,
};

/// X509 OCSP Request builder
///
/// ```
/// use der::Decode;
/// use sha1::Sha1;
/// use x509_cert::{serial_number::SerialNumber, Certificate};
/// use x509_ocsp::builder::OcspRequestBuilder;
/// use x509_ocsp::{ext::Nonce, Request};
///
/// # const ISSUER_DER: &[u8] = include_bytes!("../../tests/examples/rsa-2048-sha256-ca.der");
/// # const CERT_DER: &[u8] = include_bytes!("../../tests/examples/rsa-2048-sha256-crt.der");
/// # const KEY_DER: &[u8] = include_bytes!("../../tests/examples/rsa-2048-sha256-crt-key.der");
/// # use rsa::{pkcs1v15::SigningKey, pkcs8::DecodePrivateKey};
/// # use sha2::Sha256;
/// # fn rsa_signer() -> SigningKey<Sha256> {
/// #     let private_key = rsa::RsaPrivateKey::from_pkcs8_der(KEY_DER).unwrap();
/// #     let signing_key = SigningKey::<Sha256>::new(private_key);
/// #     signing_key
/// # }
/// let issuer = Certificate::from_der(ISSUER_DER).unwrap();
/// let cert = Certificate::from_der(CERT_DER).unwrap();
///
/// let req = OcspRequestBuilder::default()
///     .with_request(Request::from_cert::<Sha1>(&issuer, &cert).unwrap())
///     .build();
///
/// let mut rng = rand::rng();
///
/// let req = OcspRequestBuilder::default()
///     .with_request(Request::from_issuer::<Sha1>(&issuer, SerialNumber::from(2usize)).unwrap())
///     .with_request(Request::from_issuer::<Sha1>(&issuer, SerialNumber::from(3usize)).unwrap())
///     .with_request(Request::from_issuer::<Sha1>(&issuer, SerialNumber::from(4usize)).unwrap())
///     .with_extension(&Nonce::generate(&mut rng, 32).unwrap())
///     .unwrap()
///     .build();
///
/// let mut signer = rsa_signer();
/// let signer_cert_chain = vec![cert.clone()];
/// let req = OcspRequestBuilder::default()
///     .with_request(Request::from_cert::<Sha1>(&issuer, &cert).unwrap())
///     .with_extension(&Nonce::generate(&mut rng, 32).unwrap())
///     .unwrap()
///     .sign(&mut signer, Some(signer_cert_chain))
///     .unwrap();
/// ```
#[derive(Clone, Debug, Default)]
pub struct OcspRequestBuilder {
    tbs: TbsRequest<Rfc5280>,
}

impl OcspRequestBuilder {
    /// Returns an `OcspRequestBuilder` with the specified [`Version`]
    pub fn new(version: Version) -> Self {
        Self {
            tbs: TbsRequest {
                version,
                requestor_name: None,
                request_list: Vec::new(),
                request_extensions: None,
            },
        }
    }

    /// Sets the requestor name as specified in [RFC 6960 Section 4.1.1]
    ///
    /// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
    pub fn with_requestor_name(mut self, requestor_name: GeneralName) -> Self {
        self.tbs.requestor_name = Some(requestor_name);
        self
    }

    /// Adds a [`Request`] to the builder as defined in [RFC 6960 Section 4.1.1].
    ///
    /// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
    pub fn with_request(mut self, request: Request) -> Self {
        self.tbs.request_list.push(request);
        self
    }

    /// Adds a request extension as specified in [RFC 6960 Section 4.4]. Errors when the
    /// extension encoding fails.
    ///
    /// [RFC 6960 Section 4.4]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4
    pub fn with_extension<E: ToExtension>(mut self, ext: E) -> Result<Self, E::Error> {
        let ext = ext.to_extension(&Name::default(), &[])?;
        match self.tbs.request_extensions {
            Some(ref mut exts) => exts.push(ext),
            None => self.tbs.request_extensions = Some(alloc::vec![ext]),
        }
        Ok(self)
    }

    /// Consumes the builder and returns an [`OcspRequest`]
    pub fn build(self) -> OcspRequest {
        OcspRequest {
            tbs_request: self.tbs,
            optional_signature: None,
        }
    }

    /// Consumes the builder and returns a signed [`OcspRequest`]. Errors when the algorithm
    /// identifier encoding, message encoding, or signature generation fails.
    pub fn sign<S, Sig>(
        self,
        signer: &mut S,
        certificate_chain: Option<Vec<Certificate>>,
    ) -> Result<OcspRequest, Error>
    where
        S: Signer<Sig> + DynSignatureAlgorithmIdentifier,
        Sig: SignatureBitStringEncoding,
    {
        let signature_algorithm = signer.signature_algorithm_identifier()?;
        let signature = signer.try_sign(&self.tbs.to_der()?)?.to_bitstring()?;
        let optional_signature = Some(Signature {
            signature_algorithm,
            signature,
            certs: certificate_chain,
        });
        Ok(OcspRequest {
            tbs_request: self.tbs,
            optional_signature,
        })
    }

    /// Consumes the builder and returns a signed [`OcspRequest`]. Errors when the algorithm
    /// identifier encoding, message encoding, or signature generation fails.
    pub fn sign_with_rng<S, Sig, R>(
        self,
        signer: &mut S,
        rng: &mut R,
        certificate_chain: Option<Vec<Certificate>>,
    ) -> Result<OcspRequest, Error>
    where
        S: RandomizedSigner<Sig> + DynSignatureAlgorithmIdentifier,
        Sig: SignatureBitStringEncoding,
        R: CryptoRng + ?Sized,
    {
        let signature_algorithm = signer.signature_algorithm_identifier()?;
        let signature = signer
            .try_sign_with_rng(rng, &self.tbs.to_der()?)?
            .to_bitstring()?;
        let optional_signature = Some(Signature {
            signature_algorithm,
            signature,
            certs: certificate_chain,
        });
        Ok(OcspRequest {
            tbs_request: self.tbs,
            optional_signature,
        })
    }
}
