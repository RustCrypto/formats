//! Builder for simple PKCS #12 structures

use crate::pbe_params::{Pbes2Params, Pbkdf2Params};
use crate::pfx::Pfx;
use crate::safe_bag::PrivateKeyInfo;
use alloc::vec;
use alloc::vec::Vec;
use const_oid::db::rfc5912::ID_SHA_256;
use const_oid::db::rfc6268::ID_HMAC_WITH_SHA_256;
use const_oid::ObjectIdentifier;
use core::fmt;
use der::asn1::OctetString;
use der::{Any, Decode, Encode};
use pkcs5::pbes2::{AES_256_CBC_OID, PBES2_OID, PBKDF2_OID};
use pkcs8::rand_core::{CryptoRng, RngCore};
use spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned};
use x509_cert::Certificate;

/// Error type
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// ASN.1 DER-related errors.
    Asn1(der::Error),

    /// Signing error propagated for the [`signature::Error`] type.
    Pkcs5(pkcs5::Error),

    /// Missing AlgorithmIdentifier parameters
    MissingParameters,

    /// Failed to prepare EncryptionScheme instance
    EncryptionScheme,

    /// Missing expected content
    MissingContent,

    /// Error verifying MacData
    MacError,

    /// Missing expected content
    UnexpectedAlgorithm(ObjectIdentifier),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Asn1(err) => write!(f, "ASN.1 error: {}", err),
            Error::Pkcs5(err) => write!(f, "PKCS5 crate error: {}", err),
            Error::MissingParameters => write!(f, "Missing parameters"),
            Error::EncryptionScheme => write!(f, "Error preparing EncryptionScheme"),
            Error::MissingContent => write!(f, "Missing content"),
            Error::MacError => write!(f, "Error verifying message authentication code"),
            Error::UnexpectedAlgorithm(oid) => write!(f, "Unexpected algorithm: {}", oid),
        }
    }
}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
    }
}

impl From<pkcs5::Error> for Error {
    fn from(err: pkcs5::Error) -> Error {
        Error::Pkcs5(err)
    }
}

type Result<T> = core::result::Result<T, Error>;

/// Builder object for simple PKCS #12 objects
pub struct Pkcs12Builder {
    private_key: PrivateKeyInfo,
    certificates: Vec<Certificate>,
    key_pbe: Option<AlgorithmIdentifierOwned>,
    cert_pbe: Option<AlgorithmIdentifierOwned>,
    mac_alg: Option<AlgorithmIdentifierOwned>,
    iterations: Option<i32>,
}

impl Pkcs12Builder {
    /// Instantiate a new Pkcs12Builder object given a key and a certificate
    pub fn new(
        private_key: PrivateKeyInfo,
        certificate: Certificate,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self> {
        let mut kdf_salt = [0x00u8; 8];
        rng.fill_bytes(&mut kdf_salt);
        let kdf_params = Pbkdf2Params {
            salt: OctetString::new(kdf_salt)?,
            iteration_count: 2048,
            key_length: None,
            prf: AlgorithmIdentifier {
                oid: ID_HMAC_WITH_SHA_256,
                parameters: None,
            },
        };
        let enc_kdf_params = kdf_params.to_der()?;
        let kdf_key = AlgorithmIdentifierOwned {
            oid: PBKDF2_OID,
            parameters: Some(Any::from_der(&enc_kdf_params)?),
        };
        let encryption_key = AlgorithmIdentifierOwned {
            oid: AES_256_CBC_OID,
            parameters: None,
        };
        let params_key = Pbes2Params {
            kdf: kdf_key,
            encryption: encryption_key,
        };
        let enc_params = params_key.to_der()?;
        Ok(Pkcs12Builder {
            private_key,
            certificates: vec![certificate],
            key_pbe: Some(AlgorithmIdentifierOwned {
                oid: PBES2_OID,
                parameters: Some(Any::from_der(&enc_params)?),
            }),
            cert_pbe: None,
            mac_alg: Some(AlgorithmIdentifierOwned {
                oid: ID_SHA_256,
                parameters: None,
            }),
            iterations: Some(2048),
        })
    }
    /// Add a certificate
    pub fn add_certificate(&mut self, certificate: Certificate) -> Result<&mut Self> {
        self.certificates.push(certificate);
        Ok(self)
    }
    /// Set the password-based encryption algorithm to use when preparing a KeyBag
    pub fn key_pbe(&mut self, key_pbe: AlgorithmIdentifierOwned) -> Result<&mut Self> {
        self.key_pbe = Some(key_pbe);
        Ok(self)
    }
    /// Set the password-based encryption algorithm to use when preparing a CertBag
    pub fn cert_pbe(&mut self, cert_pbe: AlgorithmIdentifierOwned) -> Result<&mut Self> {
        self.cert_pbe = Some(cert_pbe);
        Ok(self)
    }
    /// Set the algorithm to use when preparing a MacData structure
    pub fn mac_alg(&mut self, mac_alg: AlgorithmIdentifierOwned) -> Result<&mut Self> {
        self.mac_alg = Some(mac_alg);
        Ok(self)
    }
    /// Number of iterations for Mac and PBE KDF
    pub fn iterations(&mut self, iterations: i32) -> Result<&mut Self> {
        self.iterations = Some(iterations);
        Ok(self)
    }

    /// Geenerate a Pfx structure from builder contents
    pub fn build(&mut self) -> Result<Pfx> {
        todo!();
    }
}
