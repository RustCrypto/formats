//! Utility functions for interacting with ASN.1 structures associated with [PKCS #12 objects](crate::pfx::Pfx)

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use log::{error, warn};

#[cfg(feature = "legacy")]
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use crate::{
    AuthenticatedSafe, CertBag, MacData,
    kdf::{Pkcs12KeyType, derive_key_utf8},
    pfx::Pfx,
    safe_bag::SafeContents,
};
use cms::encrypted_data::EncryptedData;
use const_oid::ObjectIdentifier;
use const_oid::db::rfc2985::PKCS_9_AT_LOCAL_KEY_ID;
use const_oid::db::rfc5911::{ID_DATA, ID_ENCRYPTED_DATA};
use der::{
    Any, Decode, Encode,
    asn1::{ContextSpecific, OctetString},
};
use pkcs8::EncryptedPrivateKeyInfo;
use subtle::ConstantTimeEq;
use x509_cert::attr::{Attribute, Attributes};
use zeroize::Zeroizing;

use super::{
    MAX_ITERATION_COUNT,
    error::{Error, Result},
    supported_algs::MacAlgorithm,
};

/// DER-encoded certificates extracted from a PKCS #12 safe contents.
pub struct CertContents {
    /// DER-encoded main (end-entity) certificate.
    pub cert: CertAndAttributes,
    /// DER-encoded additional certificates (CA / intermediate chain).
    pub additional_certs: Vec<CertAndAttributes>,
}

/// A DER-encoded certificate together with its PKCS #12 bag attributes.
#[derive(Debug, PartialEq)]
pub struct CertAndAttributes {
    /// DER-encoded certificate.
    pub der: Vec<u8>,
    /// Optional `localKeyID` attribute value.
    pub local_key_id: Option<Vec<u8>>,
    /// Optional `friendlyName` attribute value.
    pub friendly_name: Option<String>,
    /// Any additional bag attributes beyond `localKeyID` and `friendlyName`.
    pub other_attributes: Option<Vec<Attribute>>,
}

/// Return type for [`get_key`]: the decrypted key bytes (zeroized on drop) and parsed bag attributes.
pub type KeyContents = (Zeroizing<Vec<u8>>, ParsedAttributes);

/// Fully decoded contents of a PKCS #12 object.
pub struct Pkcs12Contents {
    /// DER-encoded private key (zeroized on drop).
    pub key_der: Zeroizing<Vec<u8>>,
    /// Optional `localKeyID` attribute from the key bag.
    pub key_id: Option<Vec<u8>>,
    /// Optional `friendlyName` attribute from the key bag.
    pub friendly_name: Option<String>,
    /// Any additional key bag attributes beyond `localKeyID` and `friendlyName`.
    pub other_key_attributes: Option<Vec<Attribute>>,
    /// End-entity certificate and attributes.
    pub certificate: CertAndAttributes,
    /// Additional certificates and attributes (CA / intermediate chain).
    pub additional_certificates: Vec<CertAndAttributes>,
}

/// Returns `true` if the OID identifies a known PKCS#12 legacy PBE algorithm.
/// Used without the `legacy` feature to produce a clear error message.
#[cfg(not(feature = "legacy"))]
fn is_known_legacy_pbe_oid(oid: &ObjectIdentifier) -> bool {
    matches!(
        *oid,
        crate::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC
            | crate::PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC
            | crate::PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC
    )
}

/// Returns `true` if the OID identifies a PKCS#12 legacy PBE algorithm.
#[cfg(feature = "legacy")]
fn is_pkcs12_pbe_oid(oid: &ObjectIdentifier) -> bool {
    matches!(
        *oid,
        crate::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC
            | crate::PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC
            | crate::PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC
    )
}

/// Decrypt data encrypted with a PKCS#12 legacy PBE scheme (SHA-1 based KDF with 3DES-CBC or RC2-CBC).
#[cfg(feature = "legacy")]
fn pkcs12_pbe_decrypt<'a>(
    alg_oid: &ObjectIdentifier,
    params_der: &[u8],
    password: &str,
    buffer: &'a mut [u8],
) -> Result<&'a [u8]> {
    use crate::pbe_params::Pkcs12PbeParams;
    use cbc::cipher::{BlockModeDecrypt, InnerIvInit, KeyIvInit, block_padding::Pkcs7};

    let params = Pkcs12PbeParams::from_der(params_der)?;

    if params.iterations as u32 > MAX_ITERATION_COUNT {
        return Err(Error::Pkcs12Builder(format!(
            "The iterations limit exceeded. {} is greater than {}",
            params.iterations, MAX_ITERATION_COUNT
        )));
    }

    let salt = params.salt.as_bytes();
    let iterations = params.iterations;

    let (key_len, iv_len) = match *alg_oid {
        crate::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC => (24, 8),
        crate::PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC => (5, 8),
        crate::PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC => (16, 8),
        _ => {
            return Err(Error::Pkcs12Builder(format!(
                "Unsupported PKCS#12 PBE algorithm: {alg_oid}"
            )));
        }
    };

    let key = Zeroizing::new(derive_key_utf8::<Sha1>(
        password,
        salt,
        Pkcs12KeyType::EncryptionKey,
        iterations,
        key_len,
    )?);
    let iv = Zeroizing::new(derive_key_utf8::<Sha1>(
        password,
        salt,
        Pkcs12KeyType::Iv,
        iterations,
        iv_len,
    )?);

    match *alg_oid {
        crate::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC => {
            cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
                .map_err(|e| {
                    Error::Pkcs12Builder(format!("Failed to init 3DES-CBC decryptor: {e}"))
                })?
                .decrypt_padded::<Pkcs7>(buffer)
                .map_err(|e| Error::Pkcs12Builder(format!("3DES-CBC decryption failed: {e}")))
        }
        crate::PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC => {
            let cipher = rc2::Rc2::new_with_eff_key_len(&key, 40);
            cbc::Decryptor::<rc2::Rc2>::inner_iv_slice_init(cipher, &iv)
                .map_err(|e| {
                    Error::Pkcs12Builder(format!("Failed to init RC2-40-CBC decryptor: {e}"))
                })?
                .decrypt_padded::<Pkcs7>(buffer)
                .map_err(|e| Error::Pkcs12Builder(format!("RC2-40-CBC decryption failed: {e}")))
        }
        crate::PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC => {
            let cipher = rc2::Rc2::new_with_eff_key_len(&key, 128);
            cbc::Decryptor::<rc2::Rc2>::inner_iv_slice_init(cipher, &iv)
                .map_err(|e| {
                    Error::Pkcs12Builder(format!("Failed to init RC2-128-CBC decryptor: {e}"))
                })?
                .decrypt_padded::<Pkcs7>(buffer)
                .map_err(|e| Error::Pkcs12Builder(format!("RC2-128-CBC decryption failed: {e}")))
        }
        _ => unreachable!(),
    }
}

/// Extract certificates and optional key ID from decrypted SafeContents bytes.
///
/// Returns a [CertContents]. The main certificate is the first `CertBag` that carries a
/// `localKeyID` attribute, or simply the first `CertBag` if none do. All remaining `CertBag`
/// entries are returned as additional certificates.
fn extract_certs_from_safe_contents(plaintext: &[u8]) -> Result<CertContents> {
    let safe_bags = SafeContents::from_der(plaintext)?;
    let mut main_cert: Option<CertContents> = None;
    let mut additional_certs: Vec<CertAndAttributes> = Vec::new();

    for safe_bag in safe_bags {
        match safe_bag.bag_id {
            crate::PKCS_12_CERT_BAG_OID => {
                let attrs = parse_attributes(safe_bag.bag_attributes);
                let cs: ContextSpecific<CertBag> = ContextSpecific::from_der(&safe_bag.bag_value)?;
                let der = cs.value.cert_value.as_bytes().to_vec();

                if main_cert
                    .as_ref()
                    .is_none_or(|mc| mc.cert.local_key_id.is_none() && attrs.local_key_id.is_some())
                {
                    // Promote this to main cert; demote any previous main to additional
                    if let Some(prev) = main_cert.take() {
                        additional_certs.push(prev.cert);
                    }
                    main_cert = Some(CertContents {
                        cert: CertAndAttributes {
                            der,
                            local_key_id: attrs.local_key_id,
                            friendly_name: attrs.friendly_name,
                            other_attributes: attrs.other,
                        },
                        additional_certs: Vec::new(),
                    });
                } else {
                    additional_certs.push(CertAndAttributes {
                        der,
                        local_key_id: attrs.local_key_id,
                        friendly_name: attrs.friendly_name,
                        other_attributes: attrs.other,
                    });
                }
            }
            _ => {
                warn!("Unexpected SafeBag type. Ignoring and continuing.");
            }
        };
    }

    match main_cert {
        Some(mut cc) => {
            cc.additional_certs = additional_certs;
            Ok(cc)
        }
        None => {
            error!("Failed to find certificate bag");
            Err(Error::NotFound)
        }
    }
}

/// Takes an [`Any`] that notionally contains an [`OctetString`] and returns an [`AuthenticatedSafe`]
/// object or error.
///
/// The [`Any`] value is typically the value from the [`ContentInfo`](cms::content_info::ContentInfo) included in the `auth_safe` field
/// of a [`Pfx`] object. The resulting [`AuthenticatedSafe`] contains a vector of
/// [`ContentInfo`](cms::content_info::ContentInfo) objects
pub fn get_auth_safes(content: &Any) -> Result<AuthenticatedSafe<'_>> {
    let auth_safes_os = OctetString::from_der(&content.to_der()?)?;
    Ok(AuthenticatedSafe::from_der(auth_safes_os.as_bytes())?)
}

/// Takes an [`Any`] that notionally contains an [`OctetString`] and returns a [`SafeContents`]
/// object or error.
///
/// The [`Any`] value is typically the value from the [`ContentInfo`](cms::content_info::ContentInfo) included in an [`AuthenticatedSafe`]
/// read from the `auth_safe` field of a [`Pfx`] object. The resulting [`SafeContents`] contains a vector of
/// [`SafeBag`](crate::safe_bag::SafeBag) objects
pub fn get_safe_bags(content: &Any) -> Result<SafeContents> {
    let safe_bags_os = OctetString::from_der(&content.to_der()?)?;
    Ok(SafeContents::from_der(safe_bags_os.as_bytes())?)
}

/// Takes an [`Any`] that notionally contains an [`OctetString`] wrapping a [`SafeContents`] object.
/// Iterates over the [`SafeBag`](crate::safe_bag::SafeBag) list and decrypts the first bag of type
/// [`PKCS_12_PKCS8_KEY_BAG_OID`](crate::PKCS_12_PKCS8_KEY_BAG_OID) using the provided password,
/// returning a tuple containing the plaintext key bytes (zeroized on drop) and an optional key
/// identifier. Returns an error if no key bag is found or decryption fails.
pub fn get_key(content: &Any, password: &str) -> Result<KeyContents> {
    let safe_bags = get_safe_bags(content)?;
    for safe_bag in safe_bags {
        match safe_bag.bag_id {
            crate::PKCS_12_PKCS8_KEY_BAG_OID => {
                let key_attrs = parse_attributes(safe_bag.bag_attributes);

                // Try PKCS#12 legacy PBE first (requires legacy feature)
                #[cfg(feature = "legacy")]
                {
                    let cs_generic: ContextSpecific<crate::pbe_params::EncryptedPrivateKeyInfo> =
                        ContextSpecific::from_der(&safe_bag.bag_value)?;
                    if is_pkcs12_pbe_oid(&cs_generic.value.encryption_algorithm.oid) {
                        let params_der = cs_generic
                            .value
                            .encryption_algorithm
                            .parameters
                            .as_ref()
                            .ok_or_else(|| {
                                Error::Pkcs12Builder("Missing PKCS#12 PBE parameters".to_string())
                            })?
                            .to_der()?;
                        let mut ciphertext =
                            Zeroizing::new(cs_generic.value.encrypted_data.as_bytes().to_vec());
                        let plaintext = pkcs12_pbe_decrypt(
                            &cs_generic.value.encryption_algorithm.oid,
                            &params_der,
                            password,
                            &mut ciphertext,
                        )?;
                        return Ok((Zeroizing::new(plaintext.to_vec()), key_attrs));
                    }
                }

                #[cfg(not(feature = "legacy"))]
                {
                    let cs_generic: ContextSpecific<crate::pbe_params::EncryptedPrivateKeyInfo> =
                        ContextSpecific::from_der(&safe_bag.bag_value)?;
                    if is_known_legacy_pbe_oid(&cs_generic.value.encryption_algorithm.oid) {
                        return Err(Error::Pkcs12Builder(
                            "This P12 uses legacy PBE encryption. \
                             Enable the `legacy` feature to parse it."
                                .to_string(),
                        ));
                    }
                }

                // PBES2 path
                let cs: ContextSpecific<EncryptedPrivateKeyInfo<OctetString>> =
                    ContextSpecific::from_der(&safe_bag.bag_value)?;

                if let Some(pbes2) = cs.value.encryption_algorithm.pbes2() {
                    if let Some(params) = pbes2.kdf.pbkdf2() {
                        if params.iteration_count > MAX_ITERATION_COUNT {
                            return Err(Error::Pkcs12Builder(format!(
                                "The iterations limit exceeded. {} is greater than {}",
                                params.iteration_count, MAX_ITERATION_COUNT
                            )));
                        }
                    }
                }

                let mut ciphertext = Zeroizing::new(cs.value.encrypted_data.as_bytes().to_vec());
                let plaintext = cs
                    .value
                    .encryption_algorithm
                    .decrypt_in_place(password, &mut ciphertext)?;
                return Ok((Zeroizing::new(plaintext.to_vec()), key_attrs));
            }
            _ => {
                warn!("Unexpected SafeBag type. Ignoring and continuing...");
            }
        };
    }
    Err(Error::Pkcs12Builder(String::from(
        "Failed to find SafeBag containing key",
    )))
}

/// Takes an [`Any`] that notionally contains an [`EncryptedData`] whose payload is an encrypted
/// [`SafeContents`]. Attempts to decrypt the content using the provided password, then extracts and
/// returns a [`CertContents`] containing the DER-encoded end-entity certificate, any additional
/// certificate DER blobs, and an optional key identifier.
pub fn get_cert(content: &Any, password: &str) -> Result<CertContents> {
    let enc_data = EncryptedData::from_der(&content.to_der()?)?;

    let Some(ciphertext_os) = enc_data.enc_content_info.encrypted_content else {
        return Err(Error::Pkcs12Builder(String::from(
            "Failed to read encrypted content",
        )));
    };
    let mut ciphertext = Zeroizing::new(ciphertext_os.as_bytes().to_vec());

    // Try PKCS#12 legacy PBE first (requires legacy feature)
    #[cfg(feature = "legacy")]
    if is_pkcs12_pbe_oid(&enc_data.enc_content_info.content_enc_alg.oid) {
        let params_der = enc_data
            .enc_content_info
            .content_enc_alg
            .parameters
            .as_ref()
            .ok_or_else(|| Error::Pkcs12Builder("Missing PKCS#12 PBE parameters".to_string()))?
            .to_der()?;
        let plaintext = pkcs12_pbe_decrypt(
            &enc_data.enc_content_info.content_enc_alg.oid,
            &params_der,
            password,
            &mut ciphertext,
        )?;
        return extract_certs_from_safe_contents(plaintext);
    }

    #[cfg(not(feature = "legacy"))]
    if is_known_legacy_pbe_oid(&enc_data.enc_content_info.content_enc_alg.oid) {
        return Err(Error::Pkcs12Builder(
            "This P12 uses legacy PBE encryption. \
             Enable the `legacy` feature to parse it."
                .to_string(),
        ));
    }

    // PBES2 path
    let enc_params = match enc_data
        .enc_content_info
        .content_enc_alg
        .parameters
        .as_ref()
    {
        Some(r) => r.to_der()?,
        None => {
            return Err(Error::Pkcs12Builder(String::from(
                "Failed to obtain reference to parameters",
            )));
        }
    };

    let params = pkcs5::pbes2::Parameters::from_der(&enc_params)?;
    if let Some(kdf_params) = params.kdf.pbkdf2() {
        if kdf_params.iteration_count > MAX_ITERATION_COUNT {
            return Err(Error::Pkcs12Builder(format!(
                "The iterations limit exceeded. {} is greater than {}",
                kdf_params.iteration_count, MAX_ITERATION_COUNT
            )));
        }
    }

    let scheme = pkcs5::EncryptionScheme::from(params.clone());
    let plaintext = scheme.decrypt_in_place(password, &mut ciphertext)?;
    extract_certs_from_safe_contents(plaintext)
}

/// Parsed bag attributes: the well-known `localKeyID` and `friendlyName` values plus any
/// remaining attributes.
pub struct ParsedAttributes {
    /// Optional `localKeyID` attribute value.
    pub local_key_id: Option<Vec<u8>>,
    /// Optional `friendlyName` attribute value.
    pub friendly_name: Option<String>,
    /// Any additional bag attributes beyond `localKeyID` and `friendlyName`.
    pub other: Option<Vec<Attribute>>,
}

/// Extract `localKeyID`, `friendlyName`, and any remaining attributes from an optional attribute set.
fn parse_attributes(attributes: Option<Attributes>) -> ParsedAttributes {
    use const_oid::db::rfc2985::PKCS_9_AT_FRIENDLY_NAME;
    use der::asn1::BmpString;

    let mut local_key_id = None;
    let mut friendly_name = None;
    let mut other = Vec::new();

    if let Some(attributes) = attributes {
        for attribute in attributes.iter() {
            if attribute.oid == PKCS_9_AT_LOCAL_KEY_ID {
                if let Some(value) = attribute.values.iter().next() {
                    local_key_id = Some(value.value().to_vec());
                } else {
                    warn!(
                        "Found a key ID attribute but it had no value. Ignoring and continuing..."
                    );
                }
            } else if attribute.oid == PKCS_9_AT_FRIENDLY_NAME {
                if let Some(value) = attribute.values.iter().next() {
                    if let Ok(bmp) = BmpString::from_der(&value.to_der().unwrap_or_default()) {
                        friendly_name = Some(bmp.to_string());
                    } else {
                        warn!(
                            "Found a friendlyName attribute but could not decode the BMP string. Ignoring and continuing..."
                        );
                    }
                } else {
                    warn!(
                        "Found a friendlyName attribute but it had no value. Ignoring and continuing..."
                    );
                }
            } else {
                other.push(attribute.clone());
            }
        }
    }

    ParsedAttributes {
        local_key_id,
        friendly_name,
        other: if other.is_empty() { None } else { Some(other) },
    }
}

/// Takes a DER-encoded [PKCS #12 object](crate::pfx::Pfx) and password, attempts to decrypt it and, if successful, returns
/// a [`Pkcs12Contents`] containing the private key, the end-entity certificate, an optional key
/// identifier, and any additional certificates (e.g. CA/intermediate chain certificates).
///
/// This method assumes this basic high-level representation of the structure (though the order of
/// the AuthenticatedSafe elements is unimportant).
///
/// ```text
/// SEQUENCE {          -- PFX
///   SEQUENCE {        -- AuthSafe
///     [0] {
///       SEQUENCE {    -- AuthenticatedSafes
///         SEQUENCE {  -- AuthenticatedSafe
///             contentType: ID_ENCRYPTED_DATA
///             content: SafeContents (including SafeBag of type PKCS_12_CERT_BAG_OID)
///           }
///         SEQUENCE {  -- AuthenticatedSafe
///             contentType: ID_DATA
///             content: SafeContents (including SafeBag of type PKCS_12_PKCS8_KEY_BAG_OID)
///           }
///         }
///       }
///     }
///   SEQUENCE {        -- MacData
///     SEQUENCE {
///       SEQUENCE {
///         }
///       }
///     }
///   }
/// ```
pub fn parse_pkcs12(der_p12: &[u8], password: &str) -> Result<Pkcs12Contents> {
    let mut recovered_cert_data = None;
    let mut recovered_key_and_key_id = None;
    let pfx = Pfx::from_der(der_p12)?;
    let auth_safes_os = OctetString::from_der(&pfx.auth_safe.content.to_der()?)?;
    if let Some(mac_data) = &pfx.mac_data {
        check_mac(password, mac_data, auth_safes_os.as_bytes())?;
    } else {
        warn!(
            "MacData was absent. While this is permitted by the specification, it may indicate a stripping attack."
        );
    }
    let auth_safes = get_auth_safes(&pfx.auth_safe.content)?;
    for auth_safe in auth_safes {
        if ID_ENCRYPTED_DATA == auth_safe.content_type {
            recovered_cert_data = Some(get_cert(&auth_safe.content, password)?);
        } else if ID_DATA == auth_safe.content_type {
            recovered_key_and_key_id = Some(get_key(&auth_safe.content, password)?);
        }
    }
    if let Some(cert_contents) = recovered_cert_data
        && let Some((recovered_key, key_attrs)) = recovered_key_and_key_id
    {
        let key_id = if key_attrs.local_key_id.is_some() {
            key_attrs.local_key_id
        } else {
            cert_contents.cert.local_key_id.clone()
        };
        return Ok(Pkcs12Contents {
            key_der: recovered_key,
            key_id,
            friendly_name: key_attrs.friendly_name,
            other_key_attributes: key_attrs.other,
            certificate: cert_contents.cert,
            additional_certificates: cert_contents.additional_certs,
        });
    }
    Err(Error::NotFound)
}

/// Check MAC given a password, an optional MacData and the content to authenticate.
fn check_mac(password: &str, mac_data: &MacData, content: &[u8]) -> Result<()> {
    if mac_data.iterations < 1 {
        return Err(Error::Pkcs12Builder(format!(
            "Invalid MAC iteration count: {}",
            mac_data.iterations
        )));
    }
    if mac_data.iterations as u32 > MAX_ITERATION_COUNT {
        return Err(Error::Pkcs12Builder(format!(
            "The iterations limit exceeded. {} is greater than {}",
            mac_data.iterations, MAX_ITERATION_COUNT
        )));
    }

    let md = MacAlgorithm::try_from(mac_data.mac.algorithm.oid)?;

    let mac_key = Zeroizing::new(match md {
        #[cfg(feature = "legacy")]
        MacAlgorithm::HmacSha1 => derive_key_utf8::<Sha1>(
            password,
            mac_data.mac_salt.as_bytes(),
            Pkcs12KeyType::Mac,
            mac_data.iterations,
            md.output_size(),
        )?,
        MacAlgorithm::HmacSha256 => derive_key_utf8::<Sha256>(
            password,
            mac_data.mac_salt.as_bytes(),
            Pkcs12KeyType::Mac,
            mac_data.iterations,
            md.output_size(),
        )?,
        MacAlgorithm::HmacSha384 => derive_key_utf8::<Sha384>(
            password,
            mac_data.mac_salt.as_bytes(),
            Pkcs12KeyType::Mac,
            mac_data.iterations,
            md.output_size(),
        )?,
        MacAlgorithm::HmacSha512 => derive_key_utf8::<Sha512>(
            password,
            mac_data.mac_salt.as_bytes(),
            Pkcs12KeyType::Mac,
            mac_data.iterations,
            md.output_size(),
        )?,
    });
    let mac = generate_mac(md, &mac_key, content)?;

    match mac.ct_eq(mac_data.mac.digest.as_bytes()).unwrap_u8() {
        1 => Ok(()),
        _ => Err(Error::Pkcs12Builder(String::from(
            "MAC verification failed",
        ))),
    }
}

/// Generate a MAC given a MAC key and content
fn generate_mac(md: MacAlgorithm, mac_key: &[u8], content: &[u8]) -> Result<Vec<u8>> {
    Ok(md.compute_hmac(mac_key, content)?)
}
