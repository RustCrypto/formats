//! OCSP request builder

use crate::{builder::Error, CertId, OcspRequest, Request, Signature, TbsRequest, Version};
use alloc::vec::Vec;
use const_oid::AssociatedOid;
use der::{asn1::BitString, Encode};
use digest::Digest;
use signature::{SignatureEncoding, Signer};
use spki::DynSignatureAlgorithmIdentifier;
use x509_cert::{
    ext::{pkix::name::GeneralName, AsExtension},
    name::Name,
    serial_number::SerialNumber,
    Certificate,
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
/// # use rand_core::SeedableRng;
/// # fn seed_rng() -> rand_chacha::ChaChaRng {
/// #     rand_chacha::ChaChaRng::from_seed([5; 32])
/// # }
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
/// let mut rng = seed_rng();
///
/// let req = OcspRequestBuilder::default()
///     .with_request(Request::from_cert::<Sha1>(&issuer, &cert).unwrap())
///     .with_extension(Nonce::generate(&mut rng, 32).unwrap())
///     .unwrap()
///     .build();
///
/// let req = OcspRequestBuilder::default()
///     .with_request(Request::from_issuer::<Sha1>(&issuer, SerialNumber::from(2usize)).unwrap())
///     .with_request(Request::from_issuer::<Sha1>(&issuer, SerialNumber::from(3usize)).unwrap())
///     .with_request(Request::from_issuer::<Sha1>(&issuer, SerialNumber::from(4usize)).unwrap())
///     .with_extension(Nonce::generate(&mut rng, 32).unwrap())
///     .unwrap()
///     .build();
///
/// let mut signer = rsa_signer();
/// let signer_cert_chain = vec![cert.clone()];
/// let req = OcspRequestBuilder::default()
///     .with_request(Request::from_cert::<Sha1>(&issuer, &cert).unwrap())
///     .with_extension(Nonce::generate(&mut rng, 32).unwrap())
///     .unwrap()
///     .sign(&mut signer, Some(signer_cert_chain))
///     .unwrap();
/// ```
pub struct OcspRequestBuilder {
    tbs_request: TbsRequest,
    optional_signature: Option<Signature>,
}

impl Default for OcspRequestBuilder {
    fn default() -> Self {
        OcspRequestBuilder::new(Version::V1)
    }
}

impl OcspRequestBuilder {
    /// Returns an `OcspRequestBuilder` with the specified [`Version`]
    pub fn new(version: Version) -> Self {
        Self {
            tbs_request: TbsRequest {
                version,
                requestor_name: None,
                request_list: Vec::new(),
                request_extensions: None,
            },
            optional_signature: None,
        }
    }

    /// Sets the requestor name as specified in [RFC 6960 Section 4.1.1]
    ///
    /// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
    pub fn with_requestor_name(mut self, requestor_name: GeneralName) -> Self {
        self.tbs_request.requestor_name = Some(requestor_name);
        self
    }

    /// Adds a [`Request`] to the builder as defined in [RFC 6960 Section 4.1.1].
    ///
    /// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
    pub fn with_request(mut self, request: Request) -> Self {
        self.tbs_request.request_list.push(request);
        self
    }

    /// Adds a request extension as specified in [RFC 6960 Section 4.4]. Errors when the
    /// extension encoding fails.
    ///
    /// [RFC 6960 Section 4.4]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4
    pub fn with_extension(mut self, ext: impl AsExtension) -> Result<Self, Error> {
        let ext = ext.to_extension(&Name::default(), &[])?;
        match self.tbs_request.request_extensions {
            Some(ref mut exts) => exts.push(ext),
            None => self.tbs_request.request_extensions = Some(alloc::vec![ext]),
        }
        Ok(self)
    }

    /// Consumes the builder and returns an [`OcspRequest`]
    pub fn build(self) -> OcspRequest {
        self.into()
    }

    /// Consumes the builder and returns a signed [`OcspRequest`]. Errors when the algorithm
    /// identifier encoding, message encoding, or signature generation fails.
    pub fn sign<S, Sig>(
        mut self,
        signer: &mut S,
        certificate_chain: Option<Vec<Certificate>>,
    ) -> Result<OcspRequest, Error>
    where
        S: Signer<Sig> + DynSignatureAlgorithmIdentifier,
        Sig: SignatureEncoding,
    {
        let signature_algorithm = signer.signature_algorithm_identifier()?;
        let signature = signer.try_sign(&self.tbs_request.to_der()?)?;
        let signature = BitString::from_bytes(signature.to_bytes().as_ref())?;
        self.optional_signature = Some(Signature {
            signature_algorithm,
            signature,
            certs: certificate_chain,
        });
        Ok(self.into())
    }
}

// There is no point going backwards from OcspRequest
#[allow(clippy::from_over_into)]
impl Into<OcspRequest> for OcspRequestBuilder {
    fn into(self) -> OcspRequest {
        OcspRequest {
            tbs_request: self.tbs_request,
            optional_signature: self.optional_signature,
        }
    }
}

impl Request {
    /// Returns a new `Request` with the specified `CertID`
    pub fn new(req_cert: CertId) -> Self {
        Self {
            req_cert,
            single_request_extensions: None,
        }
    }

    /// Generates a `CertID` by running the issuer's subject and key through the specified
    /// [`Digest`].
    /// 
    /// [RFC 6960 Section 4.1.1]
    ///
    /// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
    pub fn from_issuer<D>(issuer: &Certificate, serial_number: SerialNumber) -> Result<Self, Error>
    where
        D: Digest + AssociatedOid,
    {
        Ok(Self::new(CertId::from_issuer::<D>(issuer, serial_number)?))
    }

    /// Generates a `CertID` by running the issuer's subject and key through the specified
    /// [`Digest`] and pulls the serial from `cert`. This does not ensure that `cert` is actually
    /// issued by `issuer`.
    /// 
    /// [RFC 6960 Section 4.1.1]
    ///
    /// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
    pub fn from_cert<D>(issuer: &Certificate, cert: &Certificate) -> Result<Self, Error>
    where
        D: Digest + AssociatedOid,
    {
        Ok(Self::new(CertId::from_cert::<D>(issuer, cert)?))
    }

    /// Adds a single request extension as specified in [RFC 6960 Section 4.4]. Errors when the
    /// extension encoding fails.
    ///
    /// [RFC 6960 Section 4.4]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4
    pub fn with_extension(mut self, ext: impl AsExtension) -> Result<Self, Error> {
        let ext = ext.to_extension(&Name::default(), &[])?;
        match self.single_request_extensions {
            Some(ref mut exts) => exts.push(ext),
            None => self.single_request_extensions = Some(alloc::vec![ext]),
        }
        Ok(self)
    }
}
