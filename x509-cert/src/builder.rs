//! X509 Certificate builder

use alloc::vec;
use core::fmt;
use der::{
    asn1::{BitString, OctetString},
    Encode,
};
use sha1::{Digest, Sha1};
use signature::{Keypair, SignatureEncoding, Signer};
use spki::{DynSignatureAlgorithmIdentifier, EncodePublicKey, SubjectPublicKeyInfoOwned};

use crate::{
    certificate::{Certificate, TbsCertificate, Version},
    ext::{
        pkix::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
        },
        AsExtension, Extension,
    },
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

/// Error type
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// ASN.1 DER-related errors.
    Asn1(der::Error),

    /// Public key errors propagated from the [`spki::Error`] type.
    PublicKey(spki::Error),

    /// Signing error propagated for the [`signature::Signer`] type.
    Signature(signature::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Asn1(err) => write!(f, "ASN.1 error: {}", err),
            Error::PublicKey(err) => write!(f, "public key error: {}", err),
            Error::Signature(err) => write!(f, "signature error: {}", err),
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

type Result<T> = core::result::Result<T, Error>;

/// UniqueIds holds the optional attributes `issuerUniqueID` and `subjectUniqueID`
/// to be filled in the TBSCertificate if version v2 or v3.
///
/// See X.509 `TbsCertificate` as defined in [RFC 5280 Section 4.1]
pub struct UniqueIds {
    /// ```text
    /// issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    ///                      -- If present, version MUST be v2 or v3
    /// ```
    pub issuer_unique_id: Option<BitString>,
    /// ```text
    /// subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    ///                      -- If present, version MUST be v2 or v3
    /// ```
    pub subject_unique_id: Option<BitString>,
}

impl UniqueIds {
    fn get_unique_ids(&self) -> (Option<BitString>, Option<BitString>) {
        (
            self.issuer_unique_id.clone(),
            self.subject_unique_id.clone(),
        )
    }
}

/// The type of certificate to build
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Build a root CA certificate
    Root,
    /// Build an intermediate sub CA certificate
    SubCA {
        /// issuer   Name,
        /// represents the name signing the certificate
        issuer: Name,
        /// pathLenConstraint       INTEGER (0..MAX) OPTIONAL
        /// BasicConstraints as defined in [RFC 5280 Section 4.2.1.9].
        path_len_constraint: Option<u8>,
    },
    /// Build an end certificate
    Leaf {
        /// issuer   Name,
        /// represents the name signing the certificate
        issuer: Name,
        /// should the key agreement flag of KeyUsage be enabled
        enable_key_agreement: bool,
    },
    #[cfg(feature = "hazmat")]
    /// Opt-out of the default extensions
    Manual {
        /// issuer   Name,
        /// represents the name signing the certificate
        /// A `None` will make it a self-signed certificate
        issuer: Option<Name>,
    },
}

impl Profile {
    fn get_issuer(&self, subject: &Name) -> Name {
        match self {
            Profile::Root => subject.clone(),
            Profile::SubCA { issuer, .. } => issuer.clone(),
            Profile::Leaf { issuer, .. } => issuer.clone(),
            #[cfg(feature = "hazmat")]
            Profile::Manual { issuer, .. } => issuer.as_ref().unwrap_or(subject).clone(),
        }
    }

    fn build_extensions(
        &self,
        spk: &SubjectPublicKeyInfoOwned,
        issuer_spk: &SubjectPublicKeyInfoOwned,
        tbs: &TbsCertificate,
    ) -> Result<vec::Vec<Extension>> {
        #[cfg(feature = "hazmat")]
        // User opted out of default extensions set.
        if let Profile::Manual { .. } = self {
            return Ok(vec::Vec::default());
        }

        let mut extensions: vec::Vec<Extension> = vec::Vec::new();

        extensions.push({
            let result = Sha1::digest(spk.subject_public_key.raw_bytes());
            SubjectKeyIdentifier(OctetString::new(result.to_vec())?).to_extension(tbs)?
        });

        // Build Authority Key Identifier
        match self {
            Profile::Root => {}
            _ => {
                let mut hasher = Sha1::new();
                hasher.update(issuer_spk.subject_public_key.raw_bytes());
                let result = hasher.finalize();

                extensions.push(
                    AuthorityKeyIdentifier {
                        key_identifier: Some(OctetString::new(result.to_vec())?),
                        authority_cert_issuer: None,
                        authority_cert_serial_number: None,
                    }
                    .to_extension(tbs)?,
                );
            }
        }

        // Build Basic Contraints extensions
        extensions.push(match self {
            Profile::Root => BasicConstraints {
                ca: true,
                path_len_constraint: None,
            }
            .to_extension(tbs)?,
            Profile::SubCA {
                path_len_constraint,
                ..
            } => BasicConstraints {
                ca: true,
                path_len_constraint: *path_len_constraint,
            }
            .to_extension(tbs)?,
            Profile::Leaf { .. } => BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
            .to_extension(tbs)?,
            #[cfg(feature = "hazmat")]
            Profile::Manual { .. } => unreachable!(),
        });

        // Build Key Usage extension
        match self {
            Profile::Root | Profile::SubCA { .. } => {
                extensions.push(
                    KeyUsage(
                        KeyUsages::DigitalSignature | KeyUsages::KeyCertSign | KeyUsages::CRLSign,
                    )
                    .to_extension(tbs)?,
                );
            }
            Profile::Leaf {
                enable_key_agreement,
                ..
            } => {
                let mut key_usage = KeyUsages::DigitalSignature
                    | KeyUsages::NonRepudiation
                    | KeyUsages::KeyEncipherment;
                if *enable_key_agreement {
                    key_usage |= KeyUsages::KeyAgreement;
                }

                extensions.push(KeyUsage(key_usage).to_extension(tbs)?);
            }
            #[cfg(feature = "hazmat")]
            Profile::Manual { .. } => unreachable!(),
        }

        Ok(extensions)
    }
}

/// The version of the Certificate to build.
/// All newly built certificate should use `CertificateVersion::V3`
pub enum CertificateVersion {
    /// Generate a X509 version 1
    V1,
    /// Generate a X509 version 2
    V2(UniqueIds),
    /// Generate a X509 version 3
    V3(UniqueIds),
}

impl From<CertificateVersion> for Version {
    fn from(cv: CertificateVersion) -> Version {
        use CertificateVersion::*;
        match cv {
            V1 => Version::V1,
            V2(_) => Version::V2,
            V3(_) => Version::V3,
        }
    }
}

/// X509 Certificate builder
///
/// ```
/// use der::Decode;
/// use x509_cert::spki::SubjectPublicKeyInfoOwned;
/// use x509_cert::builder::{CertificateBuilder, CertificateVersion, Profile, UniqueIds};
/// use x509_cert::name::Name;
/// use x509_cert::serial_number::SerialNumber;
/// use x509_cert::time::Validity;
///
/// # const RSA_2048_DER: &[u8] = include_bytes!("../tests/examples/rsa2048-pub.der");
/// # const RSA_2048_PRIV_DER: &[u8] = include_bytes!("../tests/examples/rsa2048-priv.der");
/// # use rsa::{pkcs1v15::SigningKey, pkcs1::DecodeRsaPrivateKey};
/// # use sha2::Sha256;
/// # use std::time::Duration;
/// # use der::referenced::RefToOwned;
/// # fn rsa_signer() -> SigningKey<Sha256> {
/// #     let private_key = rsa::RsaPrivateKey::from_pkcs1_der(RSA_2048_PRIV_DER).unwrap();
/// #     let signing_key = SigningKey::<Sha256>::new_with_prefix(private_key);
/// #     signing_key
/// # }
///
/// let uids = UniqueIds {
///     issuer_unique_id: None,
///     subject_unique_id: None,
/// };
///
/// let serial_number = SerialNumber::from(42u32);
/// let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
/// let profile = Profile::Root;
/// let subject =
///     Name::encode_from_string("CN=World domination corporation,O=World domination Inc,C=US")
///         .unwrap();
/// let subject = Name::from_der(&subject).unwrap();
/// let pub_key = SubjectPublicKeyInfoOwned::try_from(RSA_2048_DER).expect("get rsa pub key");
///
/// let mut signer = rsa_signer();
/// let mut builder = CertificateBuilder::new(
///     profile,
///     CertificateVersion::V3(uids),
///     serial_number,
///     validity,
///     subject,
///     pub_key,
///     &mut signer,
/// )
/// .expect("Create certificate");
/// ```
pub struct CertificateBuilder<'s, S> {
    tbs: TbsCertificate,
    signer: &'s mut S,
}

impl<'s, S> CertificateBuilder<'s, S>
where
    S: Keypair,
    S::VerifyingKey: EncodePublicKey,
    S::VerifyingKey: DynSignatureAlgorithmIdentifier,
{
    /// Creates a new certificate builder
    pub fn new<Signature>(
        profile: Profile,
        version: CertificateVersion,
        serial_number: SerialNumber,
        mut validity: Validity,
        subject: Name,
        subject_public_key_info: SubjectPublicKeyInfoOwned,
        signer: &'s mut S,
    ) -> Result<Self>
    where
        S: Signer<Signature>,
    {
        let verifying_key = signer.verifying_key();
        let signer_pub = verifying_key
            .to_public_key_der()?
            .decode_msg::<SubjectPublicKeyInfoOwned>()?;

        let signature_alg = verifying_key.signature_algorithm_identifier()?;
        let issuer = profile.get_issuer(&subject);

        validity.not_before.rfc5280_adjust_utc_time()?;
        validity.not_after.rfc5280_adjust_utc_time()?;

        let (version, (issuer_unique_id, subject_unique_id)) = match version {
            CertificateVersion::V1 => (Version::V1, (None, None)),
            CertificateVersion::V2(uids) => (Version::V2, uids.get_unique_ids()),
            CertificateVersion::V3(uids) => (Version::V3, uids.get_unique_ids()),
        };

        let mut tbs = TbsCertificate {
            version,
            serial_number,
            signature: signature_alg,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id,
            subject_unique_id,
            extensions: None,
        };

        if tbs.version == Version::V3 {
            let extensions =
                profile.build_extensions(&tbs.subject_public_key_info, &signer_pub, &tbs)?;
            if !extensions.is_empty() {
                tbs.extensions = Some(extensions);
            }
        }

        Ok(Self { tbs, signer })
    }

    /// Add an extension to this certificate
    pub fn add_extension<E: AsExtension>(&mut self, extension: &E) -> Result<()> {
        if self.tbs.version == Version::V3 {
            let ext = extension.to_extension(&self.tbs)?;

            if let Some(extensions) = self.tbs.extensions.as_mut() {
                extensions.push(ext);
            } else {
                let extensions = vec![ext];
                self.tbs.extensions = Some(extensions);
            }
        }

        Ok(())
    }

    /// Run the certificate through the signer and build the end certificate.
    pub fn build<Signature>(&mut self) -> Result<Certificate>
    where
        S: Signer<Signature>,
        Signature: SignatureEncoding,
    {
        let signature = self.signer.try_sign(&self.tbs.to_der()?)?;
        let signature = BitString::from_bytes(signature.to_bytes().as_ref())?;

        let cert = Certificate {
            tbs_certificate: self.tbs.clone(),
            signature_algorithm: self.tbs.signature.clone(),
            signature,
        };

        Ok(cert)
    }
}
