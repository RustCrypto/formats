//! OpenSSH certificate builder.

use super::{CertType, Certificate, OptionsMap, SigningKey};
use crate::{public, Error, Result, Signature};
use alloc::{string::String, vec::Vec};

#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

#[cfg(doc)]
use crate::PrivateKey;

/// OpenSSH certificate builder.
///
/// This type provides the core functionality of an OpenSSH certificate
/// authority.
///
/// It can build and sign OpenSSH certificates.
///
/// ## Principals
///
/// Certificates are valid for a specific set of principal names:
///
/// - Usernames for [`CertType::User`].
/// - Hostnames for [`CertType::Host`].
///
/// When building a certificate, you will either need to specify principals
/// by calling [`Builder::valid_principal`] one or more times, or explicitly
/// marking a certificate as valid for all principals (i.e. "golden ticket")
/// using the [`Builder::all_principals_valid`] method.
pub struct Builder {
    public_key: public::KeyData,
    nonce: Vec<u8>,
    serial: Option<u64>,
    cert_type: Option<CertType>,
    key_id: Option<String>,
    valid_principals: Option<Vec<String>>,
    valid_after: u64,
    valid_before: u64,
    critical_options: OptionsMap,
    extensions: OptionsMap,
    comment: Option<String>,
}

impl Builder {
    /// Recommended size for a nonce.
    pub const RECOMMENDED_NONCE_SIZE: usize = 16;

    /// Create a new certificate builder for the given subject's public key.
    ///
    /// Also requires a nonce (random value typically 16 or 32 bytes long) and
    /// the validity window of the certificate as Unix seconds.
    pub fn new(
        nonce: impl Into<Vec<u8>>,
        public_key: impl Into<public::KeyData>,
        valid_after: u64,
        valid_before: u64,
    ) -> Self {
        Self {
            nonce: nonce.into(),
            public_key: public_key.into(),
            serial: None,
            cert_type: None,
            key_id: None,
            valid_principals: None,
            valid_after,
            valid_before,
            critical_options: OptionsMap::new(),
            extensions: OptionsMap::new(),
            comment: None,
        }
    }

    /// Create a new certificate builder, generating a random nonce using the
    /// provided random number generator.
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    pub fn new_with_random_nonce(
        mut rng: impl CryptoRng + RngCore,
        public_key: impl Into<public::KeyData>,
        valid_after: u64,
        valid_before: u64,
    ) -> Self {
        let mut nonce = vec![0u8; Self::RECOMMENDED_NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        Self::new(nonce, public_key, valid_after, valid_before)
    }

    /// Set certificate serial number.
    ///
    /// Default: `0`.
    pub fn serial(&mut self, serial: u64) -> Result<&mut Self> {
        if self.serial.is_some() {
            field_invalid("serial")?;
        }

        self.serial = Some(serial);
        Ok(self)
    }

    /// Set certificate type: user or host.
    ///
    /// Default: [`CertType::User`].
    pub fn cert_type(&mut self, cert_type: CertType) -> Result<&mut Self> {
        if self.cert_type.is_some() {
            field_invalid("cert_type")?;
        }

        self.cert_type = Some(cert_type);
        Ok(self)
    }

    /// Set key ID: label to identify this particular certificate.
    ///
    /// Default `""`
    pub fn key_id(&mut self, key_id: impl Into<String>) -> Result<&mut Self> {
        if self.key_id.is_some() {
            field_invalid("key_id")?;
        }

        self.key_id = Some(key_id.into());
        Ok(self)
    }

    /// Add a principal (i.e. username or hostname) to `valid_principals`.
    pub fn valid_principal(&mut self, principal: impl Into<String>) -> Result<&mut Self> {
        match &mut self.valid_principals {
            Some(principals) => principals.push(principal.into()),
            None => self.valid_principals = Some(vec![principal.into()]),
        }

        Ok(self)
    }

    /// Mark this certificate as being valid for all principals.
    ///
    /// # ⚠️ Security Warning
    ///
    /// Use this method with care! It generates "golden ticket" certificates
    /// which can e.g. authenticate as any user on a system, or impersonate
    /// any host.
    pub fn all_principals_valid(&mut self) -> Result<&mut Self> {
        self.valid_principals = Some(Vec::new());
        Ok(self)
    }

    /// Add a critical option to this certificate.
    ///
    /// Critical options must be recognized or the certificate must be rejected.
    pub fn critical_option(
        &mut self,
        name: impl Into<String>,
        data: impl Into<String>,
    ) -> Result<&mut Self> {
        let name = name.into();
        let data = data.into();

        if self.critical_options.contains_key(&name) {
            field_invalid("critical_options")?;
        }

        self.critical_options.insert(name, data);
        Ok(self)
    }

    /// Add an extension to this certificate.
    ///
    /// Extensions can be unrecognized without impacting the certificate.
    pub fn extension(
        &mut self,
        name: impl Into<String>,
        data: impl Into<String>,
    ) -> Result<&mut Self> {
        let name = name.into();
        let data = data.into();

        if self.extensions.contains_key(&name) {
            field_invalid("extensions")?;
        }

        self.extensions.insert(name, data);
        Ok(self)
    }

    /// Add a comment to this certificate.
    ///
    /// Default `""`
    pub fn comment(&mut self, comment: impl Into<String>) -> Result<&mut Self> {
        if self.comment.is_some() {
            field_invalid("comment")?;
        }

        self.comment = Some(comment.into());
        Ok(self)
    }

    /// Sign the certificate using the provided signer type.
    ///
    /// The [`PrivateKey`] type can be used as a signer.
    pub fn sign<S: SigningKey>(self, signing_key: &S) -> Result<Certificate> {
        // Empty valid principals result in a "golden ticket", so this check
        // ensures that was explicitly configured via `all_principals_valid`.
        let valid_principals = match self.valid_principals {
            Some(principals) => principals,
            None => {
                return Err(Error::CertificateFieldInvalid {
                    name: "valid_principals",
                })
            }
        };

        let mut cert = Certificate {
            nonce: self.nonce,
            public_key: self.public_key,
            serial: self.serial.unwrap_or_default(),
            cert_type: self.cert_type.unwrap_or_default(),
            key_id: self.key_id.unwrap_or_default(),
            valid_principals,
            valid_after: self.valid_after,
            valid_before: self.valid_before,
            critical_options: self.critical_options,
            extensions: self.extensions,
            reserved: Vec::new(),
            comment: self.comment.unwrap_or_default(),
            signature_key: signing_key.public_key(),
            signature: Signature::placeholder(),
        };

        let mut tbs_cert = Vec::new();
        cert.encode_tbs(&mut tbs_cert)?;
        cert.signature = signing_key.try_sign(&tbs_cert)?;

        #[cfg(all(debug_assertions, feature = "fingerprint"))]
        cert.validate_at(
            cert.valid_after,
            &[cert.signature_key.fingerprint(Default::default())?],
        )?;

        Ok(cert)
    }
}

/// Return an error for an invalid certificate field.
fn field_invalid(name: &'static str) -> Result<()> {
    Err(Error::CertificateFieldInvalid { name })
}
