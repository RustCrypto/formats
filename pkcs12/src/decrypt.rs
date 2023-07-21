//! Convenience functions for working with some common PKCS #12 use cases

use crate::authenticated_safe::AuthenticatedSafe;
use crate::cert_type::CertBag;
use crate::pbe_params::EncryptedPrivateKeyInfo as OtherEncryptedPrivateKeyInfo;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::str::Utf8Error;

#[cfg(all(feature = "kdf", feature = "insecure"))]
use crate::decrypt_kdf::*;

use crate::pfx::Pfx;
use crate::safe_bag::{PrivateKeyInfo, SafeContents};
use cms::encrypted_data::EncryptedData;
use const_oid::db::{rfc5911, rfc5912};
use const_oid::ObjectIdentifier;
use der::asn1::ContextSpecific;
use der::asn1::OctetString;
use der::{Any, Decode, Encode};
use pkcs5::pbes2::PBES2_OID;
use pkcs8::EncryptedPrivateKeyInfo;
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

    /// Encountered an unexpected SafeBag
    UnexpectedSafeBag(ObjectIdentifier),

    /// Encountered an unexpected AuthSafe
    UnexpectedAuthSafe(ObjectIdentifier),

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
            Error::UnexpectedSafeBag(oid) => write!(f, "Unexpected SafeBag type: {}", oid),
            Error::UnexpectedAuthSafe(oid) => {
                write!(f, "Unexpected AuthenticatedSafe type: {}", oid)
            }
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

impl From<Utf8Error> for Error {
    fn from(err: Utf8Error) -> Error {
        Error::Utf8Error(err)
    }
}

/// Result type for PKCS #12 der
pub type Result<T> = core::result::Result<T, Error>;

fn process_safe_contents(
    data: &[u8],
    password: &[u8],
) -> Result<(Option<PrivateKeyInfo>, Vec<Certificate>)> {
    let mut key: Option<PrivateKeyInfo> = None;
    let mut cert: Vec<Certificate> = vec![];

    let safe_contents = SafeContents::from_der(data)?;
    for safe_bag in safe_contents {
        match safe_bag.bag_id {
            crate::PKCS_12_CERT_BAG_OID => {
                let cs: ContextSpecific<CertBag> =
                    ContextSpecific::from_der(&safe_bag.bag_value)?;
                let _ = cert.push(
                    Certificate::from_der(cs.value.cert_value.as_bytes())
                        ?,
                );
            }
            crate::PKCS_12_PKCS8_KEY_BAG_OID => {
                let cs_tmp: ContextSpecific<OtherEncryptedPrivateKeyInfo> =
                    ContextSpecific::from_der(&safe_bag.bag_value)?;
                match cs_tmp.value.encryption_algorithm.oid {
                    PBES2_OID => {
                        let cs: ContextSpecific<EncryptedPrivateKeyInfo<'_>> =
                            ContextSpecific::from_der(&safe_bag.bag_value)
                                ?;
                        let mut ciphertext = cs.value.encrypted_data.to_vec();
                        let plaintext = cs
                            .value
                            .encryption_algorithm
                            .decrypt_in_place(password, &mut ciphertext)
                            .map_err(|e| Error::Pkcs5(e))?;
                        if key.is_none() {
                            key = Some(
                                PrivateKeyInfo::from_der(plaintext)?,
                            );
                        } else {
                            return Err(Error::UnexpectedSafeBag(
                                cs_tmp.value.encryption_algorithm.oid,
                            ));
                        }
                    }
                    #[cfg(all(feature = "kdf", feature = "insecure"))]
                    _ => {
                        let cur_key = pkcs12_pbe_key(
                            cs_tmp.value.encrypted_data,
                            password,
                            &cs_tmp.value.encryption_algorithm,
                        )?;
                        if key.is_some() {
                            return Err(Error::UnexpectedAuthSafe(
                                cs_tmp.value.encryption_algorithm.oid,
                            ));
                        }
                        key = Some(cur_key);
                    }
                    #[cfg(not(all(feature = "kdf", feature = "insecure")))]
                    _ => {
                        return Err(Error::UnexpectedAlgorithm(
                            cs_tmp.value.encryption_algorithm.oid,
                        ))
                    }
                };
            }
            crate::PKCS_12_KEY_BAG_OID => {
                if key.is_none() {
                    let cs: ContextSpecific<PrivateKeyInfo> =
                        ContextSpecific::from_der(&safe_bag.bag_value)
                            ?;
                    key = Some(cs.value);
                } else {
                    return Err(Error::UnexpectedSafeBag(safe_bag.bag_id));
                }
            }
            _ => return Err(Error::UnexpectedSafeBag(safe_bag.bag_id)),
        };
    }
    Ok((key, cert))
}

fn process_encrypted_data(
    data: &Any,
    password: &[u8],
) -> Result<(Option<PrivateKeyInfo>, Vec<Certificate>)> {
    let enc_data_os = &data.to_der()?;
    let enc_data = EncryptedData::from_der(enc_data_os.as_slice())?;

    match enc_data.enc_content_info.content_enc_alg.oid {
        PBES2_OID => {
            let enc_params = match enc_data
                .enc_content_info
                .content_enc_alg
                .parameters
                .as_ref()
            {
                Some(params) => params.to_der()?,
                None => return Err(Error::MissingParameters),
            };
            let params = pkcs8::pkcs5::pbes2::Parameters::from_der(&enc_params)
                ?;
            let scheme = pkcs5::EncryptionScheme::try_from(params.clone())
                .map_err(|_e| Error::EncryptionScheme)?;
            match enc_data.enc_content_info.encrypted_content {
                Some(content) => {
                    let mut ciphertext = content.as_bytes().to_vec();
                    let plaintext = scheme
                        .decrypt_in_place(password, &mut ciphertext)
                        .map_err(|e| Error::Pkcs5(e))?;
                    process_safe_contents(plaintext, password)
                }
                None => return Err(Error::MissingContent),
            }
        }
        #[cfg(all(feature = "kdf", feature = "insecure"))]
        crate::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC => {
            let plaintext = match enc_data.enc_content_info.encrypted_content {
                Some(encrypted_content) => pkcs12_pbe(
                    encrypted_content,
                    password,
                    &enc_data.enc_content_info.content_enc_alg,
                )?,
                None => return Err(Error::MissingParameters),
            };
            process_safe_contents(&plaintext, password)
        }
        _ => {
            return Err(Error::UnexpectedAlgorithm(
                enc_data.enc_content_info.content_enc_alg.oid,
            ))
        }
    }
}

/// Takes an encoded PKCS #12 object and a password and returns PrivateKeyInfo and Certificate. This only
/// works with PKCS #12 objects containing a single certificate and a single private key.
pub fn decrypt_pfx(
    pfx_data: &[u8],
    password: &[u8],
) -> Result<(Option<PrivateKeyInfo>, Vec<Certificate>)> {
    let mut key: Option<PrivateKeyInfo> = None;
    let mut cert: Vec<Certificate> = vec![];
    let pfx = Pfx::from_der(pfx_data)?;
    let auth_safes_os =
        OctetString::from_der(&pfx.auth_safe.content.to_der()?)
            ?;
    let auth_safes =
        AuthenticatedSafe::from_der(auth_safes_os.as_bytes())?;
    for auth_safe in &auth_safes {
        let (cur_key, mut cur_cert) = match auth_safe.content_type {
            rfc5911::ID_ENCRYPTED_DATA => process_encrypted_data(&auth_safe.content, password)?,
            rfc5911::ID_DATA => {
                let os =
                    OctetString::from_der(&auth_safe.content.to_der()?)
                        ?;

                process_safe_contents(&os.as_bytes(), password)?
            }
            _ => return Err(Error::UnexpectedAuthSafe(auth_safe.content_type)),
        };
        if cur_key.is_some() {
            if key.is_some() {
                return Err(Error::UnexpectedAuthSafe(auth_safe.content_type));
            }
            key = cur_key;
        }
        if !cur_cert.is_empty() {
            cert.append(&mut cur_cert);
        }
    }

    #[cfg(feature = "kdf")]
    if let Some(mac_data) = pfx.mac_data {
        use crate::kdf::*;
        use digest::OutputSizeUser;
        use hmac::{Hmac, Mac};

        #[cfg(feature = "insecure")]
        const OID_SHA_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

        let s = core::str::from_utf8(password).map_err(|e| Error::Utf8Error(e))?;

        match mac_data.mac.algorithm.oid {
            #[cfg(feature = "insecure")]
            OID_SHA_1 => {
                use sha1::Sha1;
                type HmacSha1 = Hmac<Sha1>;

                let mac_key = derive_key::<Sha1>(
                    &s,
                    mac_data.mac_salt.as_bytes(),
                    Pkcs12KeyType::Mac,
                    mac_data.iterations,
                    Sha1::output_size(),
                );

                let mut mac = HmacSha1::new_from_slice(&mac_key).map_err(|_e| Error::MacError)?;
                mac.update(pfx.auth_safe.content.value());
                mac.verify_slice(mac_data.mac.digest.as_bytes())
                    .map_err(|_e| Error::MacError)?;
            }
            rfc5912::ID_SHA_256 => {
                use sha2::Sha256;
                type HmacSha256 = Hmac<Sha256>;
                let mac_key = derive_key::<Sha256>(
                    &s,
                    mac_data.mac_salt.as_bytes(),
                    Pkcs12KeyType::Mac,
                    mac_data.iterations,
                    Sha256::output_size(),
                );

                let mut mac = HmacSha256::new_from_slice(&mac_key).map_err(|_e| Error::MacError)?;
                mac.update(pfx.auth_safe.content.value());
                mac.verify_slice(mac_data.mac.digest.as_bytes())
                    .map_err(|_e| Error::MacError)?;
            }
            rfc5912::ID_SHA_384 => {
                use sha2::Sha384;
                type HmacSha384 = Hmac<Sha384>;
                let mac_key = derive_key::<Sha384>(
                    &s,
                    mac_data.mac_salt.as_bytes(),
                    Pkcs12KeyType::Mac,
                    mac_data.iterations,
                    Sha384::output_size(),
                );

                let mut mac = HmacSha384::new_from_slice(&mac_key).map_err(|_e| Error::MacError)?;
                mac.update(pfx.auth_safe.content.value());
                mac.verify_slice(mac_data.mac.digest.as_bytes())
                    .map_err(|_e| Error::MacError)?;
            }
            rfc5912::ID_SHA_512 => {
                use sha2::Sha512;
                type HmacSha512 = Hmac<Sha512>;
                let mac_key = derive_key::<Sha512>(
                    &s,
                    mac_data.mac_salt.as_bytes(),
                    Pkcs12KeyType::Mac,
                    mac_data.iterations,
                    Sha512::output_size(),
                );

                let mut mac = HmacSha512::new_from_slice(&mac_key).map_err(|_e| Error::MacError)?;
                mac.update(pfx.auth_safe.content.value());
                mac.verify_slice(mac_data.mac.digest.as_bytes())
                    .map_err(|_e| Error::MacError)?;
            }
            _ => return Err(Error::UnexpectedAlgorithm(mac_data.mac.algorithm.oid)),
        };
    }

    Ok((key, cert))
}
