//! Builder for simple PKCS #12 structures

use crate::cert_type::CertBag;
use crate::pbe_params::{EncryptedPrivateKeyInfo, Pbes2Params, Pbkdf2Params};
use crate::pfx::{Pfx, Version};
use crate::safe_bag::{PrivateKeyInfo, SafeBag, SafeContents};
use crate::{
    PKCS_12_CERT_BAG_OID, PKCS_12_KEY_BAG_OID, PKCS_12_PKCS8_KEY_BAG_OID, PKCS_12_X509_CERT_OID,
};
use alloc::vec;
use alloc::vec::Vec;
use cms::content_info::{CmsVersion, ContentInfo};
use cms::encrypted_data::EncryptedData;
use cms::enveloped_data::EncryptedContentInfo;
use const_oid::db::rfc5911::{ID_DATA, ID_ENCRYPTED_DATA};
use const_oid::db::rfc5912::ID_SHA_256;
use const_oid::db::rfc6268::ID_HMAC_WITH_SHA_256;
use const_oid::ObjectIdentifier;
use core::fmt;
use core::str::Utf8Error;
use der::asn1::OctetString;
use der::{Any, AnyRef, Decode, Encode};
use pkcs5::pbes2::{AES_256_CBC_OID, PBES2_OID, PBKDF2_OID};
use pkcs5::EncryptionScheme;
use pkcs8::rand_core::{CryptoRng, RngCore};
use spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned};
use x509_cert::Certificate;

#[cfg(feature = "kdf")]
use crate::mac_data::MacData;

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

    /// String conversion error
    Utf8Error(Utf8Error),
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
            Error::Utf8Error(err) => write!(f, "Utf8Error: {}", err),
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

fn kdf_alg(rng: &mut (impl CryptoRng + RngCore)) -> Result<Vec<u8>> {
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
    Ok(params_key.to_der()?)
}

impl Pkcs12Builder {
    /// Instantiate a new Pkcs12Builder object given a key and a certificate
    pub fn new(
        private_key: PrivateKeyInfo,
        certificate: Certificate,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self> {
        let key_params = kdf_alg(rng)?;
        let content_key_params = AnyRef::try_from(key_params.as_slice())?;

        let cert_params = kdf_alg(rng)?;
        let content_cert_params = AnyRef::try_from(cert_params.as_slice())?;

        Ok(Pkcs12Builder {
            private_key,
            certificates: vec![certificate],
            key_pbe: Some(AlgorithmIdentifierOwned {
                oid: PBES2_OID,
                parameters: Some(Any::from(content_key_params)),
            }),
            cert_pbe: Some(AlgorithmIdentifierOwned {
                oid: PBES2_OID,
                parameters: Some(Any::from(content_cert_params)),
            }),
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
    pub fn build(
        &mut self,
        password: Option<&[u8]>,
        #[cfg(feature = "kdf")] rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Pfx> {
        let mut auth_safes = vec![];
        auth_safes.push(self.prepare_cert_bag(&self.certificates, password)?);
        auth_safes.push(self.prepare_key_bag(&self.private_key, password)?);
        let der_auth_safes = auth_safes.to_der()?;

        #[cfg(not(feature = "kdf"))]
        let mac_data = None;

        #[cfg(feature = "kdf")]
        let mac_data = if let Some(mac_alg) = &self.mac_alg {
            if let Some(password) = password {
                Some(self.prepare_mac_data(&der_auth_safes, &mac_alg, password, rng)?)
            } else {
                None
            }
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
        if password.is_some() && self.key_pbe.is_some() {
            let password = password.unwrap();
            if let Some(alg) = &self.key_pbe {
                let enc_alg = alg.to_der()?;
                let len = der_private_key.len();
                der_private_key.resize(len + 16, 0x00);
                let enc_data = if let Ok(es) = EncryptionScheme::from_der(&enc_alg) {
                    es.encrypt_in_place(password, der_private_key.as_mut_slice(), len)?
                } else {
                    return Err(Error::EncryptionScheme);
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

                let safe_contents_der = safe_contents.to_der()?;
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

            let safe_contents_der = safe_contents.to_der()?;
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
        let mut safe_contents_der = safe_contents.to_der()?;
        if password.is_some() && self.cert_pbe.is_some() {
            let password = password.unwrap();
            if let Some(alg) = &self.key_pbe {
                let enc_alg = alg.to_der()?;
                let len = safe_contents_der.len();
                safe_contents_der.resize(len + 16, 0x00);
                let enc_data = if let Ok(es) = EncryptionScheme::from_der(&enc_alg) {
                    es.encrypt_in_place(password, safe_contents_der.as_mut_slice(), len)?
                } else {
                    todo!();
                };
                let epki = EncryptedData {
                    version: CmsVersion::V0,
                    enc_content_info: EncryptedContentInfo {
                        content_type: ID_DATA,
                        content_enc_alg: alg.clone(),
                        encrypted_content: Some(OctetString::new(enc_data)?),
                    },
                    unprotected_attrs: None,
                };

                let epki_der = epki.to_der()?;
                let content = AnyRef::try_from(epki_der.as_slice())?;
                Ok(ContentInfo {
                    content_type: ID_ENCRYPTED_DATA,
                    content: Any::from(content),
                })
            } else {
                Err(Error::MissingParameters)
            }
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

    #[cfg(feature = "kdf")]
    fn prepare_mac_data(
        &self,
        der_auth_safes: &[u8],
        mac_alg: &AlgorithmIdentifierOwned,
        password: &[u8],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<MacData> {
        use crate::digest_info::DigestInfo;
        use crate::kdf::*;
        use const_oid::db::rfc5912;
        use digest::FixedOutput;
        use digest::OutputSizeUser;
        use hmac::{Hmac, Mac};

        let mut kdf_salt = [0x00u8; 8];
        rng.fill_bytes(&mut kdf_salt);

        #[cfg(feature = "insecure")]
        const OID_SHA_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

        let s = core::str::from_utf8(password).map_err(|e| Error::Utf8Error(e))?;

        let digest = match mac_alg.oid {
            #[cfg(feature = "insecure")]
            OID_SHA_1 => {
                use sha1::Sha1;
                type HmacSha1 = Hmac<Sha1>;

                let mac_key = derive_key::<Sha1>(
                    &s,
                    kdf_salt.as_slice(),
                    Pkcs12KeyType::Mac,
                    2048,
                    Sha1::output_size(),
                );

                let mut mac = HmacSha1::new_from_slice(&mac_key).map_err(|_e| Error::MacError)?;
                mac.update(der_auth_safes);
                let output = mac.finalize_fixed();
                output.as_slice().to_vec()
            }
            ID_SHA_256 => {
                use sha2::Sha256;
                type HmacSha256 = Hmac<Sha256>;
                let mac_key = derive_key::<Sha256>(
                    &s,
                    kdf_salt.as_slice(),
                    Pkcs12KeyType::Mac,
                    2048,
                    Sha256::output_size(),
                );

                let mut mac = HmacSha256::new_from_slice(&mac_key).map_err(|_e| Error::MacError)?;
                mac.update(der_auth_safes);
                let output = mac.finalize_fixed();
                output.as_slice().to_vec()
            }
            rfc5912::ID_SHA_384 => {
                use sha2::Sha384;
                type HmacSha384 = Hmac<Sha384>;
                let mac_key = derive_key::<Sha384>(
                    &s,
                    kdf_salt.as_slice(),
                    Pkcs12KeyType::Mac,
                    2048,
                    Sha384::output_size(),
                );

                let mut mac = HmacSha384::new_from_slice(&mac_key).map_err(|_e| Error::MacError)?;
                mac.update(der_auth_safes);
                let output = mac.finalize_fixed();
                output.as_slice().to_vec()
            }
            rfc5912::ID_SHA_512 => {
                use sha2::Sha512;
                type HmacSha512 = Hmac<Sha512>;
                let mac_key = derive_key::<Sha512>(
                    &s,
                    kdf_salt.as_slice(),
                    Pkcs12KeyType::Mac,
                    2048,
                    Sha512::output_size(),
                );

                let mut mac = HmacSha512::new_from_slice(&mac_key).map_err(|_e| Error::MacError)?;
                mac.update(der_auth_safes);
                let output = mac.finalize_fixed();
                output.as_slice().to_vec()
            }
            _ => return Err(Error::UnexpectedAlgorithm(mac_alg.oid)),
        };
        Ok(MacData {
            mac: DigestInfo {
                algorithm: mac_alg.clone(),
                digest: OctetString::new(digest.as_slice())?,
            },
            mac_salt: OctetString::new(kdf_salt)?,
            iterations: 2048,
        })
    }
}
