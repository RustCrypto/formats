//! Convenience functions for working with some common PKCS #12 use cases

use crate::authenticated_safe::AuthenticatedSafe;
use crate::cert_type::CertBag;
use crate::pfx::Pfx;
use crate::safe_bag::{PrivateKeyInfo, SafeContents};
use cms::encrypted_data::EncryptedData;
use const_oid::db::rfc5911;
use der::asn1::ContextSpecific;
use der::asn1::OctetString;
use der::{Any, Decode, Encode};
use pkcs8::EncryptedPrivateKeyInfo;
use x509_cert::Certificate;

/// Error type
#[derive(Debug)]
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
    UnexpectedSafeBag,

    /// Encountered an unexpected AuthSafe
    UnexpectedAuthSafe,

    /// Missing expected content
    MissingContent,
}
type Result<T> = core::result::Result<T, Error>;

fn process_safe_contents(
    data: &[u8],
    password: &[u8],
) -> Result<(Option<PrivateKeyInfo>, Option<Certificate>)> {
    let mut key: Option<PrivateKeyInfo> = None;
    let mut cert: Option<Certificate> = None;

    let safe_contents = SafeContents::from_der(data).map_err(|e| Error::Asn1(e))?;
    for safe_bag in safe_contents {
        match safe_bag.bag_id {
            crate::PKCS_12_CERT_BAG_OID => {
                let cs: ContextSpecific<CertBag> =
                    ContextSpecific::from_der(&safe_bag.bag_value).map_err(|e| Error::Asn1(e))?;
                if cert.is_none() {
                    cert = Some(
                        Certificate::from_der(cs.value.cert_value.as_bytes())
                            .map_err(|e| Error::Asn1(e))?,
                    );
                } else {
                    return Err(Error::UnexpectedSafeBag);
                }
            }
            crate::PKCS_12_PKCS8_KEY_BAG_OID => {
                let cs: ContextSpecific<EncryptedPrivateKeyInfo<'_>> =
                    ContextSpecific::from_der(&safe_bag.bag_value).map_err(|e| Error::Asn1(e))?;
                let mut ciphertext = cs.value.encrypted_data.to_vec();
                let plaintext = cs
                    .value
                    .encryption_algorithm
                    .decrypt_in_place(password, &mut ciphertext)
                    .map_err(|e| Error::Pkcs5(e))?;
                if key.is_none() {
                    key = Some(PrivateKeyInfo::from_der(plaintext).map_err(|e| Error::Asn1(e))?);
                } else {
                    return Err(Error::UnexpectedSafeBag);
                }
            }
            _ => return Err(Error::UnexpectedSafeBag),
        };
    }
    Ok((key, cert))
}

fn process_encrypted_data(
    data: &Any,
    password: &[u8],
) -> Result<(Option<PrivateKeyInfo>, Option<Certificate>)> {
    let enc_data_os = &data.to_der().map_err(|e| Error::Asn1(e))?;
    let enc_data = EncryptedData::from_der(enc_data_os.as_slice()).map_err(|e| Error::Asn1(e))?;
    let enc_params = match enc_data
        .enc_content_info
        .content_enc_alg
        .parameters
        .as_ref()
    {
        Some(params) => params.to_der().map_err(|e| Error::Asn1(e))?,
        None => return Err(Error::MissingParameters),
    };

    let params =
        pkcs8::pkcs5::pbes2::Parameters::from_der(&enc_params).map_err(|e| Error::Asn1(e))?;

    let scheme =
        pkcs5::EncryptionScheme::try_from(params.clone()).map_err(|_e| Error::EncryptionScheme)?;
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

/// Takes an encoded PKCS #12 object and a password and returns PrivateKeyInfo and Certificate. This only
/// works with PKCS #12 objects containing a single certificate and a single private key.
pub fn decrypt_pfx(
    pfx_data: &[u8],
    password: &[u8],
) -> Result<(Option<PrivateKeyInfo>, Option<Certificate>)> {
    let mut key: Option<PrivateKeyInfo> = None;
    let mut cert: Option<Certificate> = None;
    let pfx = Pfx::from_der(pfx_data).map_err(|e| Error::Asn1(e))?;
    let auth_safes_os =
        OctetString::from_der(&pfx.auth_safe.content.to_der().map_err(|e| Error::Asn1(e))?)
            .map_err(|e| Error::Asn1(e))?;
    let auth_safes =
        AuthenticatedSafe::from_der(auth_safes_os.as_bytes()).map_err(|e| Error::Asn1(e))?;
    for auth_safe in auth_safes {
        let (cur_key, cur_cert) = match auth_safe.content_type {
            rfc5911::ID_ENCRYPTED_DATA => process_encrypted_data(&auth_safe.content, password)?,
            rfc5911::ID_DATA => {
                let os =
                    OctetString::from_der(&auth_safe.content.to_der().map_err(|e| Error::Asn1(e))?)
                        .map_err(|e| Error::Asn1(e))?;

                process_safe_contents(&os.as_bytes(), password)?
            }
            _ => return Err(Error::UnexpectedAuthSafe),
        };
        if cur_key.is_some() {
            if key.is_some() {
                return Err(Error::UnexpectedAuthSafe);
            }
            key = cur_key;
        }
        if cur_cert.is_some() {
            if cert.is_some() {
                return Err(Error::UnexpectedAuthSafe);
            }
            cert = cur_cert;
        }
    }
    Ok((key, cert))
}
