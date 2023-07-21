//! Builder for simple PKCS #12 structures

use alloc::string::{String, ToString};
use subtle_encoding::hex;
pub fn buffer_to_hex(buffer: &[u8]) -> String {
    let hex = hex::encode_upper(buffer);
    let r = core::str::from_utf8(hex.as_slice());
    if let Ok(s) = r {
        s.to_string()
    } else {
        "".to_string()
    }
}

use crate::cert_type::CertBag;
use crate::mac_data::MacData;
use crate::pbe_params::{EncryptedPrivateKeyInfo, Pbes2Params, Pbkdf2Params};
use crate::pfx::{Pfx, Version};
use crate::safe_bag::{PrivateKeyInfo, SafeBag, SafeContents};
use crate::{
    PKCS_12_CERT_BAG_OID, PKCS_12_KEY_BAG_OID, PKCS_12_PKCS8_KEY_BAG_OID, PKCS_12_X509_CERT_OID,
};
use alloc::vec::Vec;
use alloc::{format, vec};
use cms::content_info::ContentInfo;
use const_oid::db::rfc5911::ID_DATA;
use const_oid::db::rfc5912::ID_SHA_256;
use const_oid::db::rfc6268::ID_HMAC_WITH_SHA_256;
use const_oid::ObjectIdentifier;
use core::fmt;
use der::asn1::OctetString;
use der::{Any, AnyRef, Decode, Encode};
use pkcs5::pbes2::{AES_256_CBC_OID, PBES2_OID, PBKDF2_OID};
use pkcs5::EncryptionScheme;
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
                parameters: Some(Any::from(der::asn1::AnyRef::NULL)),
            },
        };
        let enc_kdf_params = kdf_params.to_der()?;
        let content_enc_kdf_params = AnyRef::try_from(enc_kdf_params.as_slice())?;

        let kdf_key = AlgorithmIdentifierOwned {
            oid: PBKDF2_OID,
            parameters: Some(Any::from(content_enc_kdf_params)),
        };

        let mut iv = [0x00u8; 16];
        rng.fill_bytes(&mut iv);
        let iv_os = OctetString::new(iv)?;
        let enc_iv_os = iv_os.to_der()?;
        let content_iv = AnyRef::try_from(enc_iv_os.as_slice())?;

        let encryption_key = AlgorithmIdentifierOwned {
            oid: AES_256_CBC_OID,
            parameters: Some(Any::from(content_iv)),
        };
        let params_key = Pbes2Params {
            kdf: kdf_key,
            encryption: encryption_key,
        };
        let enc_params = params_key.to_der()?;
        let content_enc_params = AnyRef::try_from(enc_params.as_slice())?;

        Ok(Pkcs12Builder {
            private_key,
            certificates: vec![certificate],
            key_pbe: Some(AlgorithmIdentifierOwned {
                oid: PBES2_OID,
                parameters: Some(Any::from(content_enc_params)),
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
    pub fn key_pbe(&mut self, key_pbe: Option<AlgorithmIdentifierOwned>) -> Result<&mut Self> {
        self.key_pbe = key_pbe;
        Ok(self)
    }
    /// Set the password-based encryption algorithm to use when preparing a CertBag
    pub fn cert_pbe(&mut self, cert_pbe: Option<AlgorithmIdentifierOwned>) -> Result<&mut Self> {
        self.cert_pbe = cert_pbe;
        Ok(self)
    }
    /// Set the algorithm to use when preparing a MacData structure
    pub fn mac_alg(&mut self, mac_alg: Option<AlgorithmIdentifierOwned>) -> Result<&mut Self> {
        self.mac_alg = mac_alg;
        Ok(self)
    }
    /// Number of iterations for Mac and PBE KDF
    pub fn iterations(&mut self, iterations: i32) -> Result<&mut Self> {
        self.iterations = Some(iterations);
        Ok(self)
    }

    /// Geenerate a Pfx structure from builder contents
    pub fn build(&mut self, password: Option<&[u8]>) -> Result<Pfx> {
        let mut auth_safes = vec![];
        auth_safes.push(self.prepare_cert_bag(&self.certificates, password)?);
        auth_safes.push(self.prepare_key_bag(&self.private_key, password)?);
        let der_auth_safes = auth_safes.to_der()?;
        let mac_data = if let Some(mac_alg) = &self.mac_alg {
            Some(self.prepare_mac_data(&der_auth_safes, &mac_alg)?)
        } else {
            None
        };
        let os = OctetString::new(der_auth_safes)?;
        let os_der = os.to_der()?;
        let content = AnyRef::try_from(os_der.as_slice())?;
        Ok(Pfx {
            version: Version::V3,
            auth_safe: ContentInfo {
                content_type: ID_DATA,
                content: Any::from(content),
            },
            mac_data,
        })
    }

    fn prepare_key_bag(
        &self,
        private_key: &PrivateKeyInfo,
        password: Option<&[u8]>,
    ) -> Result<ContentInfo> {
        let mut der_private_key = private_key.to_der()?;
        let x = buffer_to_hex(der_private_key.as_slice());
        let len = der_private_key.len();
        if password.is_some() && self.key_pbe.is_some() {
            let password = password.unwrap();
            if let Some(alg) = &self.key_pbe {
                let enc_alg = alg.to_der()?;
                der_private_key.resize(len + 16, 0x00);
                let enc_data = if let Ok(es) = EncryptionScheme::from_der(&enc_alg) {
                    es.encrypt_in_place(password, der_private_key.as_mut_slice(), len)?
                } else {
                    todo!();
                };
                let epki = EncryptedPrivateKeyInfo {
                    encryption_algorithm: alg.clone(),
                    encrypted_data: OctetString::new(enc_data)?,
                };

                let safe_bag = SafeBag {
                    bag_id: PKCS_12_PKCS8_KEY_BAG_OID,
                    bag_value: epki.to_der()?,
                    bag_attributes: None,
                };
                let mut safe_contents: SafeContents = vec![];
                safe_contents.push(safe_bag);

                let mut safe_contents_der = safe_contents.to_der()?;
                let os = OctetString::new(safe_contents_der)?;
                let os_der = os.to_der()?;
                let content = AnyRef::try_from(os_der.as_slice())?;
                Ok(ContentInfo {
                    content_type: ID_DATA,
                    content: Any::from(content),
                })
            } else {
                Err(Error::MissingParameters)
            }
        } else {
            let safe_bag = SafeBag {
                bag_id: PKCS_12_KEY_BAG_OID,
                bag_value: der_private_key,
                bag_attributes: None,
            };
            let mut safe_contents: SafeContents = vec![];
            safe_contents.push(safe_bag);

            let mut safe_contents_der = safe_contents.to_der()?;
            let os = OctetString::new(safe_contents_der)?;
            let os_der = os.to_der()?;
            let content = AnyRef::try_from(os_der.as_slice())?;
            Ok(ContentInfo {
                content_type: ID_DATA,
                content: Any::from(content),
            })
        }
    }

    fn prepare_cert_bag(
        &self,
        certificates: &Vec<Certificate>,
        password: Option<&[u8]>,
    ) -> Result<ContentInfo> {
        let mut safe_contents: SafeContents = vec![];
        for certificate in certificates {
            let der_cert = certificate.to_der()?;
            let cert_bag = CertBag {
                cert_id: PKCS_12_X509_CERT_OID,
                cert_value: OctetString::new(der_cert)?,
            };
            let der_cer_bag = cert_bag.to_der()?;
            let safe_bag = SafeBag {
                bag_id: PKCS_12_CERT_BAG_OID,
                bag_value: der_cer_bag,
                bag_attributes: None,
            };
            safe_contents.push(safe_bag);
        }
        let safe_contents_der = safe_contents.to_der()?;
        if password.is_some() && self.cert_pbe.is_some() {
            todo!()
        } else {
            let os = OctetString::new(safe_contents_der)?;
            let os_der = os.to_der()?;
            let content = AnyRef::try_from(os_der.as_slice())?;
            Ok(ContentInfo {
                content_type: ID_DATA,
                content: Any::from(content),
            })
        }
    }

    fn prepare_mac_data(
        &self,
        _der_auth_safes: &[u8],
        _mac_alg: &AlgorithmIdentifierOwned,
    ) -> Result<MacData> {
        todo!()
    }
}
