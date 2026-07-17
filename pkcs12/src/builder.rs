//! Builder for PKCS #12 objects.
//!
//! This module provides [`Pkcs12Builder`] for creating a `Pfx` containing one private key and one
//! certificate, plus optional additional certificates (e.g. CA/intermediate chain certificates),
//! all protected with password-based encryption (PBES2 / PBKDF2 by default) and a password-based MAC.
//!
//! [`MacDataBuilder`] is provided for creating the `MacData` structure included in a `Pfx`.
//!
//! Helper functions [`add_key_id_attr`] and [`add_friendly_name_attr`] are provided for setting the
//! `localKeyID` and `friendlyName` PKCS #9 attributes on certificate and key bags.
//!
//! # Features
//!
//! - PBES2 encryption with configurable PBKDF2 PRF and AES-CBC cipher
//! - Configurable MAC algorithm and iteration count
//! - Optional additional certificates (CA/intermediate chain)
//! - `localKeyID` and `friendlyName` attribute helpers
//! - Parsing and decryption of existing PKCS #12 files via [`parse_pkcs12`](asn1_utils::parse_pkcs12)
//! - Per-bag attribute preservation (key ID, friendly name, and arbitrary attributes are retained for each certificate and the key bag)
//! - Legacy PKCS #12 PBE support (SHA-1/3DES-CBC, SHA-1/RC2-CBC) with the `legacy` feature

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub mod asn1_utils;
pub mod error;
pub mod mac_data_builder;

pub mod supported_algs;

#[doc(inline)]
pub use asn1_utils::{
    CertAndAttributes, CertContents, ParsedAttributes, Pkcs12Contents, parse_pkcs12,
};
#[doc(inline)]
pub use error::{Error, Result};
#[doc(inline)]
pub use mac_data_builder::MacDataBuilder;
#[cfg(feature = "legacy")]
#[doc(inline)]
pub use supported_algs::LegacyPbeAlgorithm;
#[doc(inline)]
pub use supported_algs::{EncryptionAlgorithm, MacAlgorithm};

use rand_core::CryptoRng;

use pkcs5::{
    pbes2,
    pbes2::{AES_256_CBC_OID, Kdf, PBES2_OID, Pbkdf2Params, Pbkdf2Prf},
};
use pkcs8::EncryptedPrivateKeyInfo;
use spki::AlgorithmIdentifier;

#[cfg(doc)]
use crate::MacData;
use crate::{
    CertBag, PKCS_12_CERT_BAG_OID, PKCS_12_PKCS8_KEY_BAG_OID, PKCS_12_X509_CERT_OID,
    pfx::{Pfx, Version},
    safe_bag::SafeBag,
};
use cms::{
    content_info::{CmsVersion, ContentInfo},
    encrypted_data::EncryptedData,
    enveloped_data::EncryptedContentInfo,
};
use const_oid::db::{
    rfc2985::PKCS_9_AT_LOCAL_KEY_ID,
    rfc5911::{ID_DATA, ID_ENCRYPTED_DATA},
};
use der::{
    Any, AnyRef, Decode, Encode,
    asn1::{OctetString, SetOfVec},
};
use log::{error, warn};
use pkcs5::pbes2::{PBKDF2_OID, Salt};
use x509_cert::{Certificate, attr::Attribute, spki::AlgorithmIdentifierOwned};
use zeroize::Zeroizing;

/// Maximum number of iterations that will be performed when parsing a PKCS #12 object
pub const MAX_ITERATION_COUNT: u32 = 100_000_000;

/// Helper for building [PKCS #12 objects](crate::pfx::Pfx) that contain one private key and one
/// certificate, plus optional additional certificates (e.g. CA/intermediate chain certificates).
/// No pairwise consistency check between the key and certificate is performed; the caller is
/// responsible for ensuring they correspond.
///
/// For each of the key and certificate a KDF algorithm, an encryption algorithm, and a set of
/// bag attributes may be specified independently. By default, PBKDF2 with HMAC-SHA-256 is used as
/// the KDF algorithm and AES-256-CBC is used as the encryption algorithm.
///
/// Though not recommended, if omitting [`MacData`] is desired, invoke the `omit_mac` method.
///
/// Use [`build_with_rng`](Pkcs12Builder::build_with_rng) to let the builder generate all required
/// random material (salts and IVs) automatically. Use [`build`](Pkcs12Builder::build) only when
/// all algorithm identifiers have been fully populated beforehand.
///
/// A builder instance should not be reused after a failed call to `build_with_rng`, as
/// internal state may be partially populated. Create a new `Pkcs12Builder` instead.
pub struct Pkcs12Builder {
    cert_attributes: Option<SetOfVec<Attribute>>,
    cert_kdf_algorithm: Option<Pbkdf2Prf>,
    cert_enc_algorithm: Option<EncryptionAlgorithm>,
    cert_kdf_algorithm_identifier: Option<AlgorithmIdentifierOwned>,
    cert_enc_algorithm_identifier: Option<AlgorithmIdentifierOwned>,
    key_attributes: Option<SetOfVec<Attribute>>,
    key_kdf_algorithm: Option<Pbkdf2Prf>,
    key_enc_algorithm: Option<EncryptionAlgorithm>,
    key_kdf_algorithm_identifier: Option<AlgorithmIdentifierOwned>,
    key_enc_algorithm_identifier: Option<AlgorithmIdentifierOwned>,
    mac_data_builder: Option<MacDataBuilder>,
    iterations: Option<u32>,
    omit_mac: bool,
    additional_certs: Vec<Certificate>,
    #[cfg(feature = "legacy")]
    cert_legacy_pbe: Option<LegacyPbeAlgorithm>,
    #[cfg(feature = "legacy")]
    key_legacy_pbe: Option<LegacyPbeAlgorithm>,
    #[cfg(feature = "legacy")]
    cert_legacy_pbe_salt: Option<Vec<u8>>,
    #[cfg(feature = "legacy")]
    key_legacy_pbe_salt: Option<Vec<u8>>,
}

impl Default for Pkcs12Builder {
    /// Generate a new Pkcs12Builder instance with all default values.
    fn default() -> Self {
        Pkcs12Builder::new()
    }
}

impl Pkcs12Builder {
    /// Generate a new Pkcs12Builder instance with all default values.
    pub fn new() -> Pkcs12Builder {
        Pkcs12Builder {
            cert_attributes: None,
            cert_kdf_algorithm: None,
            cert_enc_algorithm: None,
            cert_kdf_algorithm_identifier: None,
            cert_enc_algorithm_identifier: None,
            key_attributes: None,
            key_kdf_algorithm: None,
            key_enc_algorithm: None,
            key_kdf_algorithm_identifier: None,
            key_enc_algorithm_identifier: None,
            mac_data_builder: None,
            iterations: None,
            omit_mac: false,
            additional_certs: vec![],
            #[cfg(feature = "legacy")]
            cert_legacy_pbe: None,
            #[cfg(feature = "legacy")]
            key_legacy_pbe: None,
            #[cfg(feature = "legacy")]
            cert_legacy_pbe_salt: None,
            #[cfg(feature = "legacy")]
            key_legacy_pbe_salt: None,
        }
    }

    /// Set attributes to associated with the certificate included in the generated [PKCS #12 object](crate::pfx::Pfx).
    pub fn cert_attributes(&mut self, attrs: Option<SetOfVec<Attribute>>) -> &mut Self {
        self.cert_attributes = attrs;
        self
    }
    /// Add an additional certificate (e.g. a CA or intermediate certificate) to include in the
    /// generated [PKCS #12 object](crate::pfx::Pfx). Additional certificates are included as
    /// `CertBag` entries without `localKeyID` attributes. May be called multiple times.
    pub fn additional_cert(&mut self, cert: Certificate) -> &mut Self {
        self.additional_certs.push(cert);
        self
    }
    /// Set the PBKDF2 PRF to use as the KDF when protecting the certificate in the generated
    /// [PKCS #12 object](crate::pfx::Pfx). A random salt is generated by
    /// [`build_with_rng`](Pkcs12Builder::build_with_rng). Calling this clears any previously set
    /// [`cert_kdf_algorithm_identifier`](Pkcs12Builder::cert_kdf_algorithm_identifier).
    pub fn cert_kdf_algorithm(&mut self, alg: Option<Pbkdf2Prf>) -> &mut Self {
        self.cert_kdf_algorithm_identifier = None;
        self.cert_kdf_algorithm = alg;
        self
    }
    /// Set the encryption algorithm to use when protecting the certificate in the generated
    /// [PKCS #12 object](crate::pfx::Pfx). A random IV is generated by
    /// [`build_with_rng`](Pkcs12Builder::build_with_rng). Calling this clears any previously set
    /// [`cert_enc_algorithm_identifier`](Pkcs12Builder::cert_enc_algorithm_identifier).
    pub fn cert_enc_algorithm(&mut self, alg: Option<EncryptionAlgorithm>) -> &mut Self {
        self.cert_enc_algorithm_identifier = None;
        self.cert_enc_algorithm = alg;
        self
    }
    /// Set the KDF algorithm to use when protecting the certificate in the generated PKCS #12
    /// object using a fully populated [`AlgorithmIdentifier`] (including salt and iteration count).
    /// This takes precedence over [`cert_kdf_algorithm`](Pkcs12Builder::cert_kdf_algorithm) and
    /// calling this clears any previously set enum value.
    pub fn cert_kdf_algorithm_identifier(
        &mut self,
        alg: Option<AlgorithmIdentifierOwned>,
    ) -> &mut Self {
        if let Some(alg) = &alg
            && let Some(params) = &alg.parameters
        {
            match params.to_der() {
                Ok(der_params) => match Pbkdf2Params::from_der(&der_params) {
                    Ok(kdf_params) => {
                        if kdf_params.salt.as_bytes().len() < 16 {
                            warn!("Provided salt length is shorter than the recommended length");
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to encode parameters passed into cert_kdf_algorithm_identifier as part of a salt length check with: ({e:?}). Ignoring and continuing..."
                        );
                    }
                },
                Err(e) => {
                    warn!(
                        "Failed to encode parameters passed into cert_kdf_algorithm_identifier as part of a salt length check with: ({e:?}). Ignoring and continuing..."
                    );
                }
            }
        }

        self.cert_kdf_algorithm = None;
        self.cert_kdf_algorithm_identifier = alg;
        self
    }
    /// Set the encryption algorithm to use when protecting the certificate in the generated PKCS
    /// #12 object using a fully populated [`AlgorithmIdentifier`] (including IV). This takes
    /// precedence over [`cert_enc_algorithm`](Pkcs12Builder::cert_enc_algorithm) and calling this
    /// clears any previously set enum value.
    pub fn cert_enc_algorithm_identifier(
        &mut self,
        alg: Option<AlgorithmIdentifierOwned>,
    ) -> &mut Self {
        self.cert_enc_algorithm = None;
        self.cert_enc_algorithm_identifier = alg;
        self
    }
    /// Set attributes to associated with the key included in the generated [PKCS #12 object](crate::pfx::Pfx).
    pub fn key_attributes(&mut self, attrs: Option<SetOfVec<Attribute>>) -> &mut Self {
        self.key_attributes = attrs;
        self
    }
    /// Set the PBKDF2 PRF to use as the KDF when protecting the key in the generated
    /// [PKCS #12 object](crate::pfx::Pfx). A random salt is generated by
    /// [`build_with_rng`](Pkcs12Builder::build_with_rng). Calling this clears any previously set
    /// [`key_kdf_algorithm_identifier`](Pkcs12Builder::key_kdf_algorithm_identifier).
    pub fn key_kdf_algorithm(&mut self, alg: Option<Pbkdf2Prf>) -> &mut Self {
        self.key_kdf_algorithm_identifier = None;
        self.key_kdf_algorithm = alg;
        self
    }
    /// Set the encryption algorithm to use when protecting the key in the generated
    /// [PKCS #12 object](crate::pfx::Pfx). A random IV is generated by
    /// [`build_with_rng`](Pkcs12Builder::build_with_rng). Calling this clears any previously set
    /// [`key_enc_algorithm_identifier`](Pkcs12Builder::key_enc_algorithm_identifier).
    pub fn key_enc_algorithm(&mut self, alg: Option<EncryptionAlgorithm>) -> &mut Self {
        self.key_enc_algorithm_identifier = None;
        self.key_enc_algorithm = alg;
        self
    }
    /// Set the KDF algorithm to use when protecting the key in the generated PKCS #12 object
    /// using a fully populated [`AlgorithmIdentifier`] (including salt and iteration count). This
    /// takes precedence over [`key_kdf_algorithm`](Pkcs12Builder::key_kdf_algorithm) and calling
    /// this clears any previously set enum value.
    pub fn key_kdf_algorithm_identifier(
        &mut self,
        alg: Option<AlgorithmIdentifierOwned>,
    ) -> &mut Self {
        if let Some(alg) = &alg
            && let Some(params) = &alg.parameters
        {
            match params.to_der() {
                Ok(der_params) => match Pbkdf2Params::from_der(&der_params) {
                    Ok(kdf_params) => {
                        if kdf_params.salt.as_bytes().len() < 16 {
                            warn!("Provided salt length is shorter than the recommended length");
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to encode parameters passed into key_kdf_algorithm_identifier as part of a salt length check with: ({e:?}). Ignoring and continuing..."
                        );
                    }
                },
                Err(e) => {
                    warn!(
                        "Failed to encode parameters passed into key_kdf_algorithm_identifier as part of a salt length check with: ({e:?}). Ignoring and continuing..."
                    );
                }
            }
        }
        self.key_kdf_algorithm = None;
        self.key_kdf_algorithm_identifier = alg;
        self
    }
    /// Set the encryption algorithm to use when protecting the key in the generated PKCS #12
    /// object using a fully populated [`AlgorithmIdentifier`] (including IV). This takes
    /// precedence over [`key_enc_algorithm`](Pkcs12Builder::key_enc_algorithm) and calling this
    /// clears any previously set enum value.
    pub fn key_enc_algorithm_identifier(
        &mut self,
        alg: Option<AlgorithmIdentifierOwned>,
    ) -> &mut Self {
        self.key_enc_algorithm = None;
        self.key_enc_algorithm_identifier = alg;
        self
    }
    /// Set a MacDataBuilder instance for use in generating a MAC for the [PKCS #12 object](crate::pfx::Pfx).
    /// This sets `omit_mac` to false.
    pub fn mac_data_builder(&mut self, mdb: Option<MacDataBuilder>) -> &mut Self {
        self.omit_mac = false;
        self.mac_data_builder = mdb;
        self
    }

    /// Clears any previously set `mac_data_builder` and sets `omit_mac` to true, which will cause
    /// the generated PKCS #12 object to omit the optional [`MacData`].
    pub fn omit_mac(&mut self) -> &mut Self {
        self.omit_mac = true;
        self.mac_data_builder = None;
        self
    }

    /// Set a legacy PKCS#12 PBE algorithm for the certificate bag. When set, the certificate
    /// will be encrypted using the specified legacy PBE algorithm instead of PBES2. Clears any
    /// previously set PBES2 cert KDF/encryption algorithm settings.
    #[cfg(feature = "legacy")]
    pub fn cert_legacy_pbe_algorithm(&mut self, alg: Option<LegacyPbeAlgorithm>) -> &mut Self {
        if alg.is_some() {
            self.cert_kdf_algorithm = None;
            self.cert_enc_algorithm = None;
            self.cert_kdf_algorithm_identifier = None;
            self.cert_enc_algorithm_identifier = None;
        }
        self.cert_legacy_pbe = alg;
        self
    }

    /// Set the salt for legacy PBE encryption of the certificate bag. Only used when a legacy PBE
    /// algorithm is set via [`cert_legacy_pbe_algorithm`](Pkcs12Builder::cert_legacy_pbe_algorithm).
    /// When using [`build_with_rng`](Pkcs12Builder::build_with_rng), a random salt is generated
    /// automatically if none is set.
    #[cfg(feature = "legacy")]
    pub fn cert_legacy_pbe_salt(&mut self, salt: Option<Vec<u8>>) -> &mut Self {
        self.cert_legacy_pbe_salt = salt;
        self
    }

    /// Set the salt for legacy PBE encryption of the key bag. Only used when a legacy PBE
    /// algorithm is set via [`key_legacy_pbe_algorithm`](Pkcs12Builder::key_legacy_pbe_algorithm).
    /// When using [`build_with_rng`](Pkcs12Builder::build_with_rng), a random salt is generated
    /// automatically if none is set.
    #[cfg(feature = "legacy")]
    pub fn key_legacy_pbe_salt(&mut self, salt: Option<Vec<u8>>) -> &mut Self {
        self.key_legacy_pbe_salt = salt;
        self
    }

    /// Set a legacy PKCS#12 PBE algorithm for the key bag. When set, the key will be encrypted
    /// using the specified legacy PBE algorithm instead of PBES2. Clears any previously set
    /// PBES2 key KDF/encryption algorithm settings.
    #[cfg(feature = "legacy")]
    pub fn key_legacy_pbe_algorithm(&mut self, alg: Option<LegacyPbeAlgorithm>) -> &mut Self {
        if alg.is_some() {
            self.key_kdf_algorithm = None;
            self.key_enc_algorithm = None;
            self.key_kdf_algorithm_identifier = None;
            self.key_enc_algorithm_identifier = None;
        }
        self.key_legacy_pbe = alg;
        self
    }

    fn default_mac_data<R>(rng: &mut R, iterations: u32) -> Result<MacDataBuilder>
    where
        R: CryptoRng,
    {
        let mut salt = vec![0_u8; 16];
        rng.fill_bytes(salt.as_mut_slice());

        let mut md_builder = MacDataBuilder::new_with_salt(MacAlgorithm::HmacSha256, salt);
        md_builder.iterations(Some(iterations))?;
        Ok(md_builder)
    }
    fn default_kdf_alg<R>(rng: &mut R, iteration_count: u32) -> Result<AlgorithmIdentifierOwned>
    where
        R: CryptoRng,
    {
        let mut salt = vec![0_u8; 16];
        rng.fill_bytes(salt.as_mut_slice());

        let cert_kdf_params = Pbkdf2Params {
            salt: Salt::new(salt)?,
            iteration_count,
            key_length: None,
            prf: Pbkdf2Prf::HmacWithSha256,
        };
        let enc_cert_kdf_params = cert_kdf_params.to_der()?;
        let enc_cert_kdf_params_ref = AnyRef::try_from(enc_cert_kdf_params.as_slice())?;
        Ok(AlgorithmIdentifierOwned {
            oid: PBKDF2_OID,
            parameters: Some(Any::from(enc_cert_kdf_params_ref)),
        })
    }

    fn default_enc_alg<R>(rng: &mut R) -> Result<AlgorithmIdentifierOwned>
    where
        R: CryptoRng,
    {
        let mut iv = vec![0_u8; 16];
        rng.fill_bytes(iv.as_mut_slice());

        let cert_iv = OctetString::new(iv)?.to_der()?;
        let cert_iv_ref = AnyRef::try_from(cert_iv.as_slice())?;
        Ok(AlgorithmIdentifier {
            oid: AES_256_CBC_OID,
            parameters: Some(Any::from(cert_iv_ref)),
        })
    }

    /// Set the PBKDF2 iteration count used for both the key and certificate encryption KDFs as
    /// well as the MAC KDF (except where a custom MacDataBuilder is supplied). If not set, a
    /// default of 600,000 iterations is used. Has no effect when algorithm identifiers are supplied
    /// via [`cert_kdf_algorithm_identifier`](Pkcs12Builder::cert_kdf_algorithm_identifier) or
    /// [`key_kdf_algorithm_identifier`](Pkcs12Builder::key_kdf_algorithm_identifier), since those
    /// already encode the iteration count.
    pub fn iterations(&mut self, iterations: Option<u32>) -> Result<&mut Self> {
        if let Some(iterations) = iterations {
            if iterations > i32::MAX as u32 {
                return Err(Error::Pkcs12Builder(format!(
                    "Invalid number of iterations provided ({iterations})"
                )));
            }
        }
        self.iterations = iterations;
        Ok(self)
    }

    /// Casts the u32 to an i32 if possible, else returns 600000 as a default.
    fn get_iterations(&self) -> i32 {
        if let Some(iterations) = self.iterations {
            if iterations <= i32::MAX as u32 {
                return iterations as i32;
            } else {
                error!("Invalid number of iterations provided ({iterations})");
            }
        }
        600000
    }

    /// Builds a [PKCS #12 object](crate::pfx::Pfx) containing the provided certificate and key protected using password-based
    /// encryption and MAC. Where KDF, encryption or MAC details have not been previously specified
    /// default values are used with the provided RNG used to generate any necessary random values.
    /// A default iteration count of 600,000 is used if none is specified.
    pub fn build_with_rng<R>(
        &mut self,
        certificate: &Certificate,
        key: &[u8],
        password: &str,
        rng: &mut R,
    ) -> Result<Vec<u8>>
    where
        R: CryptoRng,
    {
        if let Some(prf) = self.cert_kdf_algorithm {
            let mut salt = vec![0_u8; 16];
            rng.fill_bytes(salt.as_mut_slice());

            let cert_kdf_params = Pbkdf2Params {
                salt: Salt::new(salt)?,
                iteration_count: self.iterations.unwrap_or(600000),
                key_length: None,
                prf,
            };
            let enc_cert_kdf_params = cert_kdf_params.to_der()?;
            let enc_cert_kdf_params_ref = AnyRef::try_from(enc_cert_kdf_params.as_slice())?;
            self.cert_kdf_algorithm_identifier = Some(AlgorithmIdentifierOwned {
                oid: PBKDF2_OID,
                parameters: Some(Any::from(enc_cert_kdf_params_ref)),
            });
        }

        if let Some(enc_alg) = &self.cert_enc_algorithm {
            let mut iv = vec![0_u8; 16];
            rng.fill_bytes(iv.as_mut_slice());

            let cert_iv = OctetString::new(iv)?.to_der()?;
            let cert_iv_ref = AnyRef::try_from(cert_iv.as_slice())?;
            self.cert_enc_algorithm_identifier = Some(AlgorithmIdentifier {
                oid: enc_alg.oid(),
                parameters: Some(Any::from(cert_iv_ref)),
            });
        }

        if let Some(prf) = self.key_kdf_algorithm {
            let mut salt = vec![0_u8; 16];
            rng.fill_bytes(salt.as_mut_slice());

            let key_kdf_params = Pbkdf2Params {
                salt: Salt::new(salt)?,
                iteration_count: self.iterations.unwrap_or(600000),
                key_length: None,
                prf,
            };
            let enc_key_kdf_params = key_kdf_params.to_der()?;
            let enc_key_kdf_params_ref = AnyRef::try_from(enc_key_kdf_params.as_slice())?;
            self.key_kdf_algorithm_identifier = Some(AlgorithmIdentifierOwned {
                oid: PBKDF2_OID,
                parameters: Some(Any::from(enc_key_kdf_params_ref)),
            });
        }

        if let Some(enc_alg) = &self.key_enc_algorithm {
            let mut iv = vec![0_u8; 16];
            rng.fill_bytes(iv.as_mut_slice());

            let key_iv = OctetString::new(iv)?.to_der()?;
            let key_iv_ref = AnyRef::try_from(key_iv.as_slice())?;
            self.key_enc_algorithm_identifier = Some(AlgorithmIdentifier {
                oid: enc_alg.oid(),
                parameters: Some(Any::from(key_iv_ref)),
            });
        }

        #[cfg(feature = "legacy")]
        let use_cert_legacy = self.cert_legacy_pbe.is_some();
        #[cfg(not(feature = "legacy"))]
        let use_cert_legacy = false;

        #[cfg(feature = "legacy")]
        let use_key_legacy = self.key_legacy_pbe.is_some();
        #[cfg(not(feature = "legacy"))]
        let use_key_legacy = false;

        if !use_cert_legacy && self.cert_kdf_algorithm_identifier.is_none() {
            self.cert_kdf_algorithm_identifier =
                Some(Self::default_kdf_alg(rng, self.get_iterations() as u32)?);
        }
        if !use_cert_legacy && self.cert_enc_algorithm_identifier.is_none() {
            self.cert_enc_algorithm_identifier = Some(Self::default_enc_alg(rng)?);
        }
        if !use_key_legacy && self.key_kdf_algorithm_identifier.is_none() {
            self.key_kdf_algorithm_identifier =
                Some(Self::default_kdf_alg(rng, self.get_iterations() as u32)?);
        }
        if !use_key_legacy && self.key_enc_algorithm_identifier.is_none() {
            self.key_enc_algorithm_identifier = Some(Self::default_enc_alg(rng)?);
        }
        if self.mac_data_builder.is_none() && !self.omit_mac {
            self.mac_data_builder = Some(Self::default_mac_data(
                rng,
                self.iterations.unwrap_or(600000),
            )?);
        }
        if let Some(mdb) = &mut self.mac_data_builder
            && !mdb.has_salt()
        {
            let mut salt = vec![0_u8; 16];
            rng.fill_bytes(salt.as_mut_slice());
            mdb.salt(Some(salt));
        }
        #[cfg(feature = "legacy")]
        {
            if self.cert_legacy_pbe.is_some() && self.cert_legacy_pbe_salt.is_none() {
                let mut salt = vec![0u8; 16];
                rng.fill_bytes(salt.as_mut_slice());
                self.cert_legacy_pbe_salt = Some(salt);
            }
            if self.key_legacy_pbe.is_some() && self.key_legacy_pbe_salt.is_none() {
                let mut salt = vec![0u8; 16];
                rng.fill_bytes(salt.as_mut_slice());
                self.key_legacy_pbe_salt = Some(salt);
            }
        }
        let result = self.build(certificate, key, password);
        self.cert_kdf_algorithm_identifier = None;
        self.cert_enc_algorithm_identifier = None;
        self.key_kdf_algorithm_identifier = None;
        self.key_enc_algorithm_identifier = None;
        #[cfg(feature = "legacy")]
        {
            self.cert_legacy_pbe_salt = None;
            self.key_legacy_pbe_salt = None;
        }
        if let Some(mdb) = &mut self.mac_data_builder {
            mdb.salt(None);
        }

        result
    }

    /// Build PBES2 EncryptedData for the certificate bag.
    fn build_pbes2_cert_encrypted_data(
        &self,
        der_cert_safe_bags: &[u8],
        password: &str,
    ) -> Result<EncryptedData> {
        let der_cert_kdf_alg = match &self.cert_kdf_algorithm_identifier {
            Some(cert_kdf_alg) => match &cert_kdf_alg.parameters {
                Some(params) => params.to_der()?,
                None => {
                    return Err(Error::Pkcs12Builder(String::from(
                        "No parameters provided for certificate KDF algorithm",
                    )));
                }
            },
            None => {
                return Err(Error::Pkcs12Builder(String::from(
                    "No certificate KDF algorithm provided",
                )));
            }
        };

        let cert_kdf = Kdf::from(Pbkdf2Params::from_der(&der_cert_kdf_alg)?);

        let der_cert_enc_alg = match &self.cert_enc_algorithm_identifier {
            Some(cert_enc_alg) => cert_enc_alg.to_der()?,
            None => {
                return Err(Error::Pkcs12Builder(String::from(
                    "No certificate encryption algorithm provided",
                )));
            }
        };
        let cert_encryption = pbes2::EncryptionScheme::from_der(&der_cert_enc_alg)?;

        let cert_params = pbes2::Parameters {
            kdf: cert_kdf,
            encryption: cert_encryption,
        };
        let cert_scheme = pkcs5::EncryptionScheme::from(cert_params.clone());
        let mut enc_buf = Zeroizing::new(vec![]);
        enc_buf.extend_from_slice(der_cert_safe_bags);
        enc_buf.extend_from_slice(&[0u8; 16]);
        let cert_ciphertext =
            match cert_scheme.encrypt_in_place(password, &mut enc_buf, der_cert_safe_bags.len()) {
                Ok(ct) => ct,
                Err(e) => {
                    return Err(Error::Pkcs12Builder(format!(
                        "Failed to encrypt certificate: {e:?}"
                    )));
                }
            };

        let der_cert_params = cert_params.to_der()?;
        let der_cert_params_ref = AnyRef::try_from(der_cert_params.as_slice())?;

        Ok(EncryptedData {
            version: CmsVersion::V0,
            enc_content_info: EncryptedContentInfo {
                content_type: ID_DATA,
                content_enc_alg: AlgorithmIdentifier {
                    oid: PBES2_OID,
                    parameters: Some(Any::from(der_cert_params_ref)),
                },
                encrypted_content: Some(OctetString::new(cert_ciphertext)?),
            },
            unprotected_attrs: None,
        })
    }

    /// Build PBES2 encrypted DER for the key bag.
    fn build_pbes2_key_encrypted_data(&self, key: &[u8], password: &str) -> Result<Vec<u8>> {
        let der_key_kdf_alg = match &self.key_kdf_algorithm_identifier {
            Some(key_kdf_alg) => match &key_kdf_alg.parameters {
                Some(params) => params.to_der()?,
                None => {
                    return Err(Error::Pkcs12Builder(String::from(
                        "No parameters provided for key KDF algorithm",
                    )));
                }
            },
            None => {
                return Err(Error::Pkcs12Builder(String::from(
                    "No key KDF algorithm provided",
                )));
            }
        };
        let key_kdf = Kdf::from(Pbkdf2Params::from_der(&der_key_kdf_alg)?);

        let der_key_enc_alg = match &self.key_enc_algorithm_identifier {
            Some(key_enc_alg) => key_enc_alg.to_der()?,
            None => {
                return Err(Error::Pkcs12Builder(String::from(
                    "No key encryption algorithm provided",
                )));
            }
        };
        let key_encryption = pbes2::EncryptionScheme::from_der(&der_key_enc_alg)?;

        let key_params = pbes2::Parameters {
            kdf: key_kdf,
            encryption: key_encryption,
        };
        let key_scheme = pkcs5::EncryptionScheme::from(key_params.clone());
        let mut enc_buf = Zeroizing::new(key.to_vec());
        enc_buf.extend_from_slice(&[0u8; 16]);
        let key_ciphertext = match key_scheme.encrypt_in_place(password, &mut enc_buf, key.len()) {
            Ok(ct) => ct,
            Err(e) => {
                return Err(Error::Pkcs12Builder(format!(
                    "Failed to encrypt key: {e:?}"
                )));
            }
        };

        let enc_epki = EncryptedPrivateKeyInfo {
            encryption_algorithm: key_scheme,
            encrypted_data: OctetString::new(key_ciphertext)?,
        };
        Ok(enc_epki.to_der()?)
    }

    /// Builds a [PKCS #12 object](crate::pfx::Pfx) containing the provided certificate and key protected using password-based
    /// encryption and MAC. KDF, encryption and, except where `omit_mac` is used, MAC information must have been previously provided to
    /// successfully use this function. To use default values, use the build_with_rng function.
    pub fn build(&self, certificate: &Certificate, key: &[u8], password: &str) -> Result<Vec<u8>> {
        let der_cert = certificate.to_der()?;
        let cert_bag = CertBag {
            cert_id: PKCS_12_X509_CERT_OID,
            cert_value: OctetString::new(der_cert.clone())?,
        };
        let der_cert_bag_inner = cert_bag.to_der()?;
        let cert_safe_bag = SafeBag {
            bag_id: PKCS_12_CERT_BAG_OID,
            bag_value: der_cert_bag_inner,
            bag_attributes: self.cert_attributes.clone(),
        };
        let mut cert_safe_bags = vec![cert_safe_bag];
        for additional_cert in &self.additional_certs {
            let der_additional = additional_cert.to_der()?;
            let additional_bag = CertBag {
                cert_id: PKCS_12_X509_CERT_OID,
                cert_value: OctetString::new(der_additional)?,
            };
            cert_safe_bags.push(SafeBag {
                bag_id: PKCS_12_CERT_BAG_OID,
                bag_value: additional_bag.to_der()?,
                bag_attributes: None,
            });
        }
        let der_cert_safe_bags = cert_safe_bags.to_der()?;

        // --- Cert bag encryption ---
        #[cfg(feature = "legacy")]
        let enc_data1 = if let Some(legacy_alg) = &self.cert_legacy_pbe {
            let iterations = self.get_iterations();
            let salt = self.cert_legacy_pbe_salt.as_ref().ok_or_else(|| {
                Error::Pkcs12Builder(String::from(
                    "No salt provided for certificate legacy PBE. Use build_with_rng to generate salts automatically.",
                ))
            })?;
            let cert_ciphertext =
                pkcs12_pbe_encrypt(legacy_alg, password, salt, iterations, &der_cert_safe_bags)?;

            let pbe_params = crate::pbe_params::Pkcs12PbeParams {
                salt: OctetString::new(salt.clone())?,
                iterations,
            };
            let der_pbe_params = pbe_params.to_der()?;
            let der_pbe_params_ref = AnyRef::try_from(der_pbe_params.as_slice())?;

            EncryptedData {
                version: CmsVersion::V0,
                enc_content_info: EncryptedContentInfo {
                    content_type: ID_DATA,
                    content_enc_alg: AlgorithmIdentifier {
                        oid: legacy_alg.oid(),
                        parameters: Some(Any::from(der_pbe_params_ref)),
                    },
                    encrypted_content: Some(OctetString::new(cert_ciphertext)?),
                },
                unprotected_attrs: None,
            }
        } else {
            self.build_pbes2_cert_encrypted_data(&der_cert_safe_bags, password)?
        };

        #[cfg(not(feature = "legacy"))]
        let enc_data1 = self.build_pbes2_cert_encrypted_data(&der_cert_safe_bags, password)?;

        let der_enc_data1 = enc_data1.to_der()?;
        let der_data_ref1 = AnyRef::try_from(der_enc_data1.as_slice())?;

        // --- Key bag encryption ---
        #[cfg(feature = "legacy")]
        let der_enc_epki = if let Some(legacy_alg) = &self.key_legacy_pbe {
            let iterations = self.get_iterations();
            let salt = self.key_legacy_pbe_salt.as_ref().ok_or_else(|| {
                Error::Pkcs12Builder(String::from(
                    "No salt provided for key legacy PBE. Use build_with_rng to generate salts automatically.",
                ))
            })?;
            let key_ciphertext = pkcs12_pbe_encrypt(legacy_alg, password, salt, iterations, key)?;

            let pbe_params = crate::pbe_params::Pkcs12PbeParams {
                salt: OctetString::new(salt.clone())?,
                iterations,
            };
            let der_pbe_params = pbe_params.to_der()?;
            let der_pbe_params_ref = AnyRef::try_from(der_pbe_params.as_slice())?;

            let epki = crate::pbe_params::EncryptedPrivateKeyInfo {
                encryption_algorithm: AlgorithmIdentifierOwned {
                    oid: legacy_alg.oid(),
                    parameters: Some(Any::from(der_pbe_params_ref)),
                },
                encrypted_data: OctetString::new(key_ciphertext)?,
            };
            epki.to_der()?
        } else {
            self.build_pbes2_key_encrypted_data(key, password)?
        };

        #[cfg(not(feature = "legacy"))]
        let der_enc_epki = self.build_pbes2_key_encrypted_data(key, password)?;

        let shrouded_key_bag = SafeBag {
            bag_id: PKCS_12_PKCS8_KEY_BAG_OID,
            bag_value: der_enc_epki,
            bag_attributes: self.key_attributes.clone(),
        };
        let sb = vec![shrouded_key_bag];
        let der_enc_data2 = sb.to_der()?;
        let os2 = OctetString::new(der_enc_data2)?.to_der()?;
        let der_data_ref2 = AnyRef::try_from(os2.as_slice())?;

        let auth_safes = vec![
            ContentInfo {
                content_type: ID_ENCRYPTED_DATA,
                content: Any::from(der_data_ref1),
            },
            ContentInfo {
                content_type: ID_DATA,
                content: Any::from(der_data_ref2),
            },
        ];

        let content_bytes = auth_safes.to_der()?;
        let os = OctetString::new(content_bytes.clone())?.to_der()?;
        let content = AnyRef::try_from(os.as_slice())?;

        let auth_safe = ContentInfo {
            content_type: ID_DATA,
            content: Any::from(content),
        };

        let mac_data = match &self.mac_data_builder {
            Some(md_build) => Some(md_build.build(password, &content_bytes)?),
            None => {
                if !self.omit_mac {
                    return Err(Error::Pkcs12Builder(String::from(
                        "No MacData builder was found but one was expected. This is a bug.",
                    )));
                }
                None
            }
        };

        let pfx = Pfx {
            version: Version::V3,
            auth_safe,
            mac_data,
        };
        Ok(pfx.to_der()?)
    }
}

/// Encrypt data using a PKCS#12 legacy PBE scheme (SHA-1 based KDF with 3DES-CBC or RC2-CBC).
#[cfg(feature = "legacy")]
fn pkcs12_pbe_encrypt(
    alg: &LegacyPbeAlgorithm,
    password: &str,
    salt: &[u8],
    iterations: i32,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    use crate::kdf::{Pkcs12KeyType, derive_key_utf8};
    use cbc::cipher::{BlockModeEncrypt, InnerIvInit, KeyIvInit, block_padding::Pkcs7};
    use sha1::Sha1;

    let key = Zeroizing::new(derive_key_utf8::<Sha1>(
        password,
        salt,
        Pkcs12KeyType::EncryptionKey,
        iterations,
        alg.key_len(),
    )?);
    let iv = Zeroizing::new(derive_key_utf8::<Sha1>(
        password,
        salt,
        Pkcs12KeyType::Iv,
        iterations,
        alg.iv_len(),
    )?);

    // Allocate buffer with room for padding (up to one block = 8 bytes)
    let mut buf = vec![0u8; plaintext.len() + 8];
    buf[..plaintext.len()].copy_from_slice(plaintext);

    match alg {
        LegacyPbeAlgorithm::ShaAnd3KeyTripleDesCbc => {
            let ct = cbc::Encryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
                .map_err(|e| {
                    Error::Pkcs12Builder(format!("Failed to init 3DES-CBC encryptor: {e}"))
                })?
                .encrypt_padded::<Pkcs7>(&mut buf, plaintext.len())
                .map_err(|e| Error::Pkcs12Builder(format!("3DES-CBC encryption failed: {e}")))?;
            Ok(ct.to_vec())
        }
        LegacyPbeAlgorithm::ShaAnd128BitRc2Cbc => {
            let cipher = rc2::Rc2::new_with_eff_key_len(&key, 128);
            let ct = cbc::Encryptor::<rc2::Rc2>::inner_iv_slice_init(cipher, &iv)
                .map_err(|e| {
                    Error::Pkcs12Builder(format!("Failed to init RC2-128-CBC encryptor: {e}"))
                })?
                .encrypt_padded::<Pkcs7>(&mut buf, plaintext.len())
                .map_err(|e| Error::Pkcs12Builder(format!("RC2-128-CBC encryption failed: {e}")))?;
            Ok(ct.to_vec())
        }
    }
}

/// Adds an [`Attribute`] containing the provided key ID to the provided set of attributes.
pub fn add_key_id_attr(attrs: &mut SetOfVec<Attribute>, key_id: &[u8]) -> Result<()> {
    let attr_bytes = OctetString::new(key_id)?.to_der()?;
    let attr_bytes_ref = AnyRef::try_from(attr_bytes.as_slice())?;
    let mut values = SetOfVec::new();
    values.insert(Any::from(attr_bytes_ref))?;
    let attr = Attribute {
        oid: PKCS_9_AT_LOCAL_KEY_ID,
        values,
    };
    Ok(attrs.insert(attr)?)
}

/// Adds an [`Attribute`] containing the provided friendly name to the provided set of attributes.
///
/// The friendly name is encoded as a BMP string (UCS-2) per PKCS #9.
pub fn add_friendly_name_attr(attrs: &mut SetOfVec<Attribute>, name: &str) -> Result<()> {
    use const_oid::db::rfc2985::PKCS_9_AT_FRIENDLY_NAME;
    use der::asn1::BmpString;

    let bmp = BmpString::from_utf8(name)?;
    let attr_bytes = bmp.to_der()?;
    let attr_bytes_ref = AnyRef::try_from(attr_bytes.as_slice())?;
    let mut values = SetOfVec::new();
    values.insert(Any::from(attr_bytes_ref))?;
    let attr = Attribute {
        oid: PKCS_9_AT_FRIENDLY_NAME,
        values,
    };
    Ok(attrs.insert(attr)?)
}
