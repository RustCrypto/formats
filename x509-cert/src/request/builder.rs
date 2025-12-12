use alloc::vec;

use der::{Encode, asn1::BitString};
use signature::Keypair;
use spki::{
    AlgorithmIdentifier, DynSignatureAlgorithmIdentifier, EncodePublicKey, SubjectPublicKeyInfo,
};

use crate::{
    builder::{Builder, Error, NULL_OID, Result},
    ext::ToExtension,
    name::Name,
    request::{CertReq, CertReqInfo, ExtensionReq, attributes::AsAttribute},
};

/// Builder for X509 Certificate Requests (CSR)
///
/// ```
/// # use p256::{pkcs8::DecodePrivateKey, NistP256, ecdsa::DerSignature};
/// # const PKCS8_PRIVATE_KEY_DER: &[u8] = include_bytes!("../../tests/examples/p256-priv.der");
/// # fn ecdsa_signer() -> ecdsa::SigningKey<NistP256> {
/// #     let secret_key = p256::SecretKey::from_pkcs8_der(PKCS8_PRIVATE_KEY_DER).unwrap();
/// #     ecdsa::SigningKey::from(secret_key)
/// # }
/// use x509_cert::{
///     builder::{Builder, RequestBuilder},
///     ext::pkix::{name::GeneralName, SubjectAltName},
///     name::Name,
/// };
/// use std::str::FromStr;
///
/// use std::net::{IpAddr, Ipv4Addr};
/// let subject = Name::from_str("CN=service.domination.world").unwrap();
///
/// let signer = ecdsa_signer();
/// let mut builder = RequestBuilder::new(subject).expect("Create certificate request");
/// builder
///     .add_extension(&SubjectAltName(vec![GeneralName::from(IpAddr::V4(
///         Ipv4Addr::new(192, 0, 2, 0),
///     ))]))
///     .unwrap();
///
/// let cert_req = builder.build::<_, DerSignature>(&signer).unwrap();
/// ```
pub struct RequestBuilder {
    info: CertReqInfo,
    extension_req: ExtensionReq,
}

impl RequestBuilder {
    /// Creates a new certificate request builder
    pub fn new(subject: Name) -> Result<Self> {
        let version = Default::default();

        let algorithm = AlgorithmIdentifier {
            oid: NULL_OID,
            parameters: None,
        };
        let public_key = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key: BitString::from_bytes(&[]).expect("unable to parse empty object"),
        };

        let attributes = Default::default();
        let extension_req = Default::default();

        Ok(Self {
            info: CertReqInfo {
                version,
                subject,
                public_key,
                attributes,
            },
            extension_req,
        })
    }

    /// Add an extension to this certificate request
    ///
    /// Extensions need to implement [`ToExtension`], examples may be found in
    /// in [`ToExtension` documentation](../ext/trait.ToExtension.html#examples) or
    /// [the implementors](../ext/trait.ToExtension.html#implementors).
    pub fn add_extension<E: ToExtension>(
        &mut self,
        extension: E,
    ) -> core::result::Result<(), E::Error> {
        let ext = extension.to_extension(&self.info.subject, &self.extension_req.0)?;

        self.extension_req.0.push(ext);

        Ok(())
    }

    /// Add an attribute to this certificate request
    pub fn add_attribute<A: AsAttribute>(&mut self, attribute: &A) -> Result<()> {
        let attr = attribute.to_attribute()?;

        self.info.attributes.insert(attr)?;
        Ok(())
    }
}

impl Builder for RequestBuilder {
    type Output = CertReq;

    fn finalize<S>(&mut self, signer: &S) -> Result<vec::Vec<u8>>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        let verifying_key = signer.verifying_key();
        let public_key = SubjectPublicKeyInfo::from_key(&verifying_key)?;
        self.info.public_key = public_key;

        self.info
            .attributes
            .insert(self.extension_req.clone().try_into()?)?;

        self.info.to_der().map_err(Error::from)
    }

    fn assemble<S>(self, signature: BitString, signer: &S) -> Result<Self::Output>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        let algorithm = signer.signature_algorithm_identifier()?;

        Ok(CertReq {
            info: self.info,
            algorithm,
            signature,
        })
    }
}
