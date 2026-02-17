//! X509 Certificate builder

use alloc::vec;
use core::fmt;
use der::{Encode, asn1::BitString, referenced::OwnedToRef};
use signature::{
    AsyncRandomizedSigner, AsyncSigner, Keypair, RandomizedSigner, Signer, rand_core::CryptoRng,
};
use spki::{
    DynSignatureAlgorithmIdentifier, EncodePublicKey, ObjectIdentifier, SignatureBitStringEncoding,
};

use crate::{
    AlgorithmIdentifier, SubjectPublicKeyInfo,
    certificate::{self, Certificate, TbsCertificate, Version},
    crl::{CertificateList, RevokedCert, TbsCertList},
    ext::{
        Extensions, ToExtension,
        pkix::{AuthorityKeyIdentifier, CrlNumber, SubjectKeyIdentifier},
    },
    serial_number::SerialNumber,
    time::{Time, Validity},
};

pub mod profile;

use self::profile::BuilderProfile;

#[deprecated(
    since = "0.3.0",
    note = "please use `x509_cert::builder::profile::BuilderProfile` instead"
)]
pub use self::profile::BuilderProfile as Profile;

#[deprecated(
    since = "0.3.0",
    note = "please use `x509_cert::request::RequestBuilder` instead"
)]
pub use crate::request::RequestBuilder;

pub(crate) const NULL_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.0.0");

/// Error type
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// ASN.1 DER-related errors.
    Asn1(der::Error),

    /// Public key errors propagated from the [`spki::Error`] type.
    PublicKey(spki::Error),

    /// Signing error propagated for the [`signature::Error`] type.
    Signature(signature::Error),

    /// Each RelativeDistinguishedName MUST contain exactly one AttributeTypeAndValue.
    NonUniqueRdn,

    /// Each Name MUST NOT contain more than one instance of a given
    /// AttributeTypeAndValue across all RelativeDistinguishedNames unless explicitly
    /// allowed in these Requirements
    NonUniqueATV,

    /// Non-ordered attribute or invalid attribute
    InvalidAttribute {
        /// Offending [`ObjectIdentifier`]
        oid: ObjectIdentifier,
    },

    /// Not all required elements were specified
    MissingAttributes,
}

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Asn1(err) => write!(f, "ASN.1 error: {err}"),
            Error::PublicKey(err) => write!(f, "public key error: {err}"),
            Error::Signature(err) => write!(f, "signature error: {err}"),
            Error::NonUniqueRdn => write!(
                f,
                "Each RelativeDistinguishedName MUST contain exactly one AttributeTypeAndValue."
            ),
            Error::NonUniqueATV => write!(
                f,
                "Each Name MUST NOT contain more than one instance of a given AttributeTypeAndValue"
            ),
            Error::InvalidAttribute { oid } => write!(
                f,
                "Non-ordered attribute or invalid attribute found (oid={oid})"
            ),
            Error::MissingAttributes => write!(f, "Not all required elements were specified"),
        }
    }
}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
    }
}

impl From<spki::Error> for Error {
    fn from(err: spki::Error) -> Error {
        Error::PublicKey(err)
    }
}

impl From<signature::Error> for Error {
    fn from(err: signature::Error) -> Error {
        Error::Signature(err)
    }
}

/// Result type
pub type Result<T> = core::result::Result<T, Error>;

/// X509 Certificate builder
///
#[cfg_attr(feature = "std", doc = "```")]
#[cfg_attr(not(feature = "std"), doc = "```ignore")]
/// use der::Decode;
/// use x509_cert::spki::SubjectPublicKeyInfo;
/// use x509_cert::builder::{CertificateBuilder, Builder, profile};
/// use x509_cert::name::Name;
/// use x509_cert::serial_number::SerialNumber;
/// use x509_cert::time::Validity;
/// use std::str::FromStr;
///
/// # const RSA_2048_DER: &[u8] = include_bytes!("../tests/examples/rsa2048-pub.der");
/// # const RSA_2048_PRIV_DER: &[u8] = include_bytes!("../tests/examples/rsa2048-priv.der");
/// # use rsa::{pkcs1v15::SigningKey, pkcs1::DecodeRsaPrivateKey};
/// # use sha2::Sha256;
/// # use std::time::Duration;
/// # use der::referenced::RefToOwned;
/// # fn rsa_signer() -> SigningKey<Sha256> {
/// #     let private_key = rsa::RsaPrivateKey::from_pkcs1_der(RSA_2048_PRIV_DER).unwrap();
/// #     let signing_key = SigningKey::<Sha256>::new(private_key);
/// #     signing_key
/// # }
///
/// let serial_number = SerialNumber::from(42u32);
/// let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
/// let subject = Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
/// let profile = profile::cabf::Root::new(false,subject).expect("Create root profile");
///
/// let pub_key = SubjectPublicKeyInfo::try_from(RSA_2048_DER).expect("get rsa pub key");
///
/// let mut signer = rsa_signer();
/// let mut builder = CertificateBuilder::new(
///     profile,
///     serial_number,
///     validity,
///     pub_key,
/// )
/// .expect("Create certificate builder");
///
/// let cert = builder.build(&signer).expect("Create certificate");
/// ```
pub struct CertificateBuilder<P> {
    tbs: TbsCertificate,
    extensions: Extensions,
    profile: P,
}

impl<P> CertificateBuilder<P>
where
    P: BuilderProfile,
{
    /// Creates a new certificate builder
    pub fn new(
        profile: P,
        serial_number: SerialNumber,
        mut validity: Validity,
        subject_public_key_info: SubjectPublicKeyInfo,
    ) -> Result<Self> {
        let signature_alg = AlgorithmIdentifier {
            oid: NULL_OID,
            parameters: None,
        };

        let subject = profile.get_subject();
        let issuer = profile.get_issuer(&subject);

        validity.not_before.rfc5280_adjust_utc_time()?;
        validity.not_after.rfc5280_adjust_utc_time()?;

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number,
            signature: signature_alg,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            extensions: None,

            // We will not generate unique identifier because as per RFC5280 Section 4.1.2.8:
            //   CAs conforming to this profile MUST NOT generate
            //   certificates with unique identifiers.
            //
            // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.8
            issuer_unique_id: None,
            subject_unique_id: None,
        };

        let extensions = Extensions::default();
        Ok(Self {
            tbs,
            extensions,
            profile,
        })
    }

    /// Add an extension to this certificate
    ///
    /// Extensions need to implement [`ToExtension`], examples may be found in
    /// in [`ToExtension` documentation](../ext/trait.ToExtension.html#examples) or
    /// [the implementors](../ext/trait.ToExtension.html#implementors).
    pub fn add_extension<E: ToExtension>(
        &mut self,
        extension: E,
    ) -> core::result::Result<(), E::Error> {
        let ext = extension.to_extension(&self.tbs.subject, &self.extensions)?;
        self.extensions.push(ext);
        Ok(())
    }
}

/// Trait for X509 builders
///
/// This trait defines the interface between builder and the signers.
pub trait Builder: Sized {
    /// Type built by this builder
    type Output: Sized;

    /// Assemble the final object from signature.
    fn assemble<S>(self, signature: BitString, signer: &S) -> Result<Self::Output>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey;

    /// Finalize and return a serialization of the object for signature.
    fn finalize<S>(&mut self, signer: &S) -> Result<vec::Vec<u8>>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey;

    /// Run the object through the signer and build it.
    ///
    /// # Notes
    ///
    /// When using ECDSA signers, the `Signature` parameter will need to be explicit
    /// as multiple implementation of [`signature::Signer`] with various signature
    /// are available.
    ///
    /// This would look like:
    #[cfg_attr(feature = "std", doc = "```no_run")]
    #[cfg_attr(not(feature = "std"), doc = "```ignore")]
    /// # use p256::elliptic_curve::Generate;
    /// # use rand::rng;
    /// # use std::{
    /// #     str::FromStr,
    /// #     time::Duration
    /// # };
    /// # use x509_cert::{
    /// #     builder::{self, CertificateBuilder, Builder},
    /// #     name::Name,
    /// #     serial_number::SerialNumber,
    /// #     spki::SubjectPublicKeyInfo,
    /// #     time::Validity
    /// # };
    /// #
    /// # let mut rng = rng();
    /// # let signer = p256::ecdsa::SigningKey::generate_from_rng(&mut rng);
    /// # let builder = CertificateBuilder::new(
    /// #     builder::profile::cabf::Root::new(
    /// #         false,
    /// #         Name::from_str("CN=World domination corporation").unwrap()
    /// #     ).unwrap(),
    /// #     SerialNumber::from(42u32),
    /// #     Validity::from_now(Duration::new(5, 0)).unwrap(),
    /// #     SubjectPublicKeyInfo::from_key(signer.verifying_key()).unwrap()
    /// # ).unwrap();
    /// let certificate = builder.build::<_, ecdsa::der::Signature<_>>(&signer).unwrap();
    /// ```
    fn build<S, Signature>(mut self, signer: &S) -> Result<Self::Output>
    where
        S: Signer<Signature>,
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
        Signature: SignatureBitStringEncoding,
    {
        let blob = self.finalize(signer)?;

        let signature = signer.try_sign(&blob)?.to_bitstring()?;

        self.assemble(signature, signer)
    }

    /// Run the object through the signer and build it.
    ///
    /// # Notes
    ///
    /// When using ECDSA signers, the `Signature` parameter will need to be explicit
    /// as multiple implementation of [`signature::Signer`] with various signature
    /// are available.
    ///
    /// This would look like:
    #[cfg_attr(feature = "std", doc = "```no_run")]
    #[cfg_attr(not(feature = "std"), doc = "```ignore")]
    /// # use p256::elliptic_curve::Generate;
    /// # use rand::rng;
    /// # use std::{
    /// #     str::FromStr,
    /// #     time::Duration
    /// # };
    /// # use x509_cert::{
    /// #     builder::{self, CertificateBuilder, Builder},
    /// #     name::Name,
    /// #     serial_number::SerialNumber,
    /// #     spki::SubjectPublicKeyInfo,
    /// #     time::Validity
    /// # };
    /// #
    /// # let mut rng = rng();
    /// # let signer = p256::ecdsa::SigningKey::generate_from_rng(&mut rng);
    /// # let builder = CertificateBuilder::new(
    /// #     builder::profile::cabf::Root::new(
    /// #         false,
    /// #         Name::from_str("CN=World domination corporation").unwrap()
    /// #     ).unwrap(),
    /// #     SerialNumber::from(42u32),
    /// #     Validity::from_now(Duration::new(5, 0)).unwrap(),
    /// #     SubjectPublicKeyInfo::from_key(signer.verifying_key()).unwrap()
    /// # ).unwrap();
    /// let certificate = builder.build_with_rng::<_, ecdsa::der::Signature<_>, _>(
    ///     &signer,
    ///     &mut rng
    /// ).unwrap();
    /// ```
    fn build_with_rng<S, Signature, R>(mut self, signer: &S, rng: &mut R) -> Result<Self::Output>
    where
        S: RandomizedSigner<Signature>,
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
        Signature: SignatureBitStringEncoding,
        R: CryptoRng + ?Sized,
    {
        let blob = self.finalize(signer)?;

        let signature = signer.try_sign_with_rng(rng, &blob)?.to_bitstring()?;

        self.assemble(signature, signer)
    }
}

impl<P> Builder for CertificateBuilder<P>
where
    P: BuilderProfile,
{
    type Output = Certificate;

    fn finalize<S>(&mut self, cert_signer: &S) -> Result<vec::Vec<u8>>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        let verifying_key = cert_signer.verifying_key();
        let signer_pub = SubjectPublicKeyInfo::from_key(&verifying_key)?;

        self.tbs.signature = cert_signer.signature_algorithm_identifier()?;

        let mut default_extensions = self.profile.build_extensions(
            self.tbs.subject_public_key_info.owned_to_ref(),
            signer_pub.owned_to_ref(),
            &self.tbs,
        )?;

        self.extensions.append(&mut default_extensions);

        if !self.extensions.is_empty() {
            self.tbs.extensions = Some(self.extensions.clone());
        }

        if self.tbs.extensions.is_none() {
            if self.tbs.issuer_unique_id.is_some() || self.tbs.subject_unique_id.is_some() {
                self.tbs.version = Version::V2;
            } else {
                self.tbs.version = Version::V1;
            }
        }

        self.tbs.to_der().map_err(Error::from)
    }

    fn assemble<S>(self, signature: BitString, _signer: &S) -> Result<Self::Output>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        let signature_algorithm = self.tbs.signature.clone();

        Ok(Certificate {
            tbs_certificate: self.tbs,
            signature_algorithm,
            signature,
        })
    }
}

/// Trait for async X509 builders
///
/// This trait defines the interface between builder and the signers.
///
/// This is the async counterpart of [`Builder`].
#[allow(async_fn_in_trait)]
pub trait AsyncBuilder: Sized {
    /// Type built by this builder
    type Output: Sized;

    /// Assemble the final object from signature.
    fn assemble<S>(self, signature: BitString, signer: &S) -> Result<Self::Output>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey;

    /// Finalize and return a serialization of the object for signature.
    fn finalize<S>(&mut self, signer: &S) -> Result<vec::Vec<u8>>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey;

    /// Run the object through the signer and build it.
    ///
    /// # Notes
    ///
    /// When using ECDSA signers, the `Signature` parameter will need to be explicit
    /// as multiple implementation of [`signature::AsyncSigner`] with various signature
    /// are available.
    ///
    /// This would look like:
    #[cfg_attr(feature = "std", doc = "```no_run")]
    #[cfg_attr(not(feature = "std"), doc = "```ignore")]
    /// # use p256::elliptic_curve::Generate;
    /// # use rand::rng;
    /// # use std::{
    /// #     str::FromStr,
    /// #     time::Duration
    /// # };
    /// # use x509_cert::{
    /// #     builder::{self, CertificateBuilder, AsyncBuilder},
    /// #     name::Name,
    /// #     serial_number::SerialNumber,
    /// #     spki::SubjectPublicKeyInfo,
    /// #     time::Validity
    /// # };
    /// #
    /// # async fn build() -> builder::Result<()> {
    /// # let mut rng = rng();
    /// # let signer = p256::ecdsa::SigningKey::generate_from_rng(&mut rng);
    /// # let builder = CertificateBuilder::new(
    /// #     builder::profile::cabf::Root::new(
    /// #         false,
    /// #         Name::from_str("CN=World domination corporation").unwrap()
    /// #     ).unwrap(),
    /// #     SerialNumber::from(42u32),
    /// #     Validity::from_now(Duration::new(5, 0)).unwrap(),
    /// #     SubjectPublicKeyInfo::from_key(signer.verifying_key()).unwrap()
    /// # ).unwrap();
    /// let certificate = builder.build_async::<_, ecdsa::der::Signature<_>>(&signer).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn build_async<S, Signature>(mut self, signer: &S) -> Result<Self::Output>
    where
        S: AsyncSigner<Signature>,
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
        Signature: SignatureBitStringEncoding,
    {
        let blob = self.finalize(signer)?;

        let signature = signer.sign_async(&blob).await?.to_bitstring()?;

        self.assemble(signature, signer)
    }

    /// Run the object through the signer and build it.
    ///
    /// # Notes
    ///
    /// When using ECDSA signers, the `Signature` parameter will need to be explicit
    /// as multiple implementation of [`signature::AsyncSigner`] with various signature
    /// are available.
    ///
    /// This would look like:
    #[cfg_attr(feature = "std", doc = "```no_run")]
    #[cfg_attr(not(feature = "std"), doc = "```ignore")]
    /// # use p256::elliptic_curve::Generate;
    /// # use rand::rng;
    /// # use std::{
    /// #     str::FromStr,
    /// #     time::Duration
    /// # };
    /// # use x509_cert::{
    /// #     builder::{self, CertificateBuilder, AsyncBuilder},
    /// #     name::Name,
    /// #     serial_number::SerialNumber,
    /// #     spki::SubjectPublicKeyInfo,
    /// #     time::Validity
    /// # };
    /// #
    /// # async fn build() -> builder::Result<()> {
    /// # let mut rng = rng();
    /// # let signer = p256::ecdsa::SigningKey::generate_from_rng(&mut rng);
    /// # let builder = CertificateBuilder::new(
    /// #     builder::profile::cabf::Root::new(
    /// #         false,
    /// #         Name::from_str("CN=World domination corporation").unwrap()
    /// #     ).unwrap(),
    /// #     SerialNumber::from(42u32),
    /// #     Validity::from_now(Duration::new(5, 0)).unwrap(),
    /// #     SubjectPublicKeyInfo::from_key(signer.verifying_key()).unwrap()
    /// # ).unwrap();
    /// let certificate = builder.build_with_rng_async::<_, ecdsa::der::Signature<_>, _>(&signer, &mut rng).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn build_with_rng_async<S, Signature, R>(
        mut self,
        signer: &S,
        rng: &mut R,
    ) -> Result<Self::Output>
    where
        S: AsyncRandomizedSigner<Signature>,
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
        Signature: SignatureBitStringEncoding,
        R: CryptoRng + ?Sized,
    {
        let blob = self.finalize(signer)?;

        let signature = signer
            .try_sign_with_rng_async(rng, &blob)
            .await?
            .to_bitstring()?;

        self.assemble(signature, signer)
    }
}

impl<T> AsyncBuilder for T
where
    T: Builder,
{
    type Output = <T as Builder>::Output;

    fn assemble<S>(self, signature: BitString, signer: &S) -> Result<Self::Output>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        <T as Builder>::assemble(self, signature, signer)
    }

    fn finalize<S>(&mut self, signer: &S) -> Result<vec::Vec<u8>>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        <T as Builder>::finalize(self, signer)
    }
}

/// X.509 CRL builder
pub struct CrlBuilder<P = certificate::Rfc5280>
where
    P: certificate::Profile,
{
    tbs: TbsCertList<P>,
}

impl<P> CrlBuilder<P>
where
    P: certificate::Profile,
{
    /// Create a `CrlBuilder` with the given issuer and the given monotonic [`CrlNumber`]
    #[cfg(feature = "std")]
    pub fn new(issuer: &Certificate, crl_number: CrlNumber) -> der::Result<Self> {
        let this_update = Time::now()?;
        Self::new_with_this_update(issuer, crl_number, this_update)
    }

    /// Create a `CrlBuilder` with the given issuer, a given monotonic [`CrlNumber`], and valid
    /// from the given `this_update` start validity date.
    pub fn new_with_this_update(
        issuer: &Certificate,
        crl_number: CrlNumber,
        this_update: Time,
    ) -> der::Result<Self> {
        // Replaced later when the finalize is called
        let signature_alg = AlgorithmIdentifier {
            oid: NULL_OID,
            parameters: None,
        };

        let issuer_name = issuer.tbs_certificate.subject().clone();

        let mut crl_extensions = Extensions::new();
        crl_extensions.push(crl_number.to_extension(&issuer_name, &crl_extensions)?);
        let aki = match issuer
            .tbs_certificate
            .get_extension::<AuthorityKeyIdentifier>()?
        {
            Some((_, aki)) => aki,
            None => {
                let ski = SubjectKeyIdentifier::try_from(
                    issuer
                        .tbs_certificate
                        .subject_public_key_info()
                        .owned_to_ref(),
                )?;
                AuthorityKeyIdentifier {
                    // KeyIdentifier must be the same as subjectKeyIdentifier
                    key_identifier: Some(ski.0.clone()),
                    // other fields must not be present.
                    ..Default::default()
                }
            }
        };
        crl_extensions.push(aki.to_extension(&issuer_name, &crl_extensions)?);

        let tbs = TbsCertList {
            version: Version::V2,
            signature: signature_alg,
            issuer: issuer_name,
            this_update,
            next_update: None,
            revoked_certificates: None,
            crl_extensions: Some(crl_extensions),
        };

        Ok(Self { tbs })
    }

    /// Make the CRL valid until the given `next_update`
    pub fn with_next_update(mut self, next_update: Option<Time>) -> Self {
        self.tbs.next_update = next_update;
        self
    }

    /// Add certificates to the revocation list
    pub fn with_certificates<I>(mut self, revoked: I) -> Self
    where
        I: Iterator<Item = RevokedCert<P>>,
    {
        let certificates = self
            .tbs
            .revoked_certificates
            .get_or_insert_with(vec::Vec::new);

        let mut revoked: vec::Vec<RevokedCert<P>> = revoked.collect();
        certificates.append(&mut revoked);

        self
    }
}

impl<P> Builder for CrlBuilder<P>
where
    P: certificate::Profile,
{
    type Output = CertificateList<P>;

    fn finalize<S>(&mut self, cert_signer: &S) -> Result<vec::Vec<u8>>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        self.tbs.signature = cert_signer.signature_algorithm_identifier()?;

        self.tbs.to_der().map_err(Error::from)
    }

    fn assemble<S>(self, signature: BitString, _signer: &S) -> Result<Self::Output>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        let signature_algorithm = self.tbs.signature.clone();

        Ok(CertificateList {
            tbs_cert_list: self.tbs,
            signature_algorithm,
            signature,
        })
    }
}
