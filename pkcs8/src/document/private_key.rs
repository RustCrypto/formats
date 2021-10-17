//! PKCS#8 private key document.

use crate::{DecodePrivateKey, EncodePrivateKey, Error, PrivateKeyInfo, Result};
use alloc::{borrow::ToOwned, vec::Vec};
use core::{convert::TryFrom, fmt};
use der::Encodable;
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "encryption")]
use {
    crate::{EncryptedPrivateKeyDocument, EncryptedPrivateKeyInfo},
    pkcs5::pbes2,
    rand_core::{CryptoRng, RngCore},
};

#[cfg(feature = "pem")]
use {
    crate::{pem, private_key_info::PEM_TYPE_LABEL, LineEnding},
    alloc::string::String,
    core::str::FromStr,
};

#[cfg(feature = "std")]
use std::{fs, path::Path};

#[cfg(any(feature = "encryption", feature = "std"))]
use core::convert::TryInto;

/// PKCS#8 private key document.
///
/// This type provides storage for [`PrivateKeyInfo`] encoded as ASN.1 DER
/// with the invariant that the contained-document is "well-formed", i.e. it
/// will parse successfully according to this crate's parsing rules.
#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub struct PrivateKeyDocument(Zeroizing<Vec<u8>>);

impl PrivateKeyDocument {
    /// Parse the [`PrivateKeyInfo`] contained in this [`PrivateKeyDocument`]
    pub fn private_key_info(&self) -> PrivateKeyInfo<'_> {
        PrivateKeyInfo::try_from(self.0.as_ref()).expect("malformed PrivateKeyDocument")
    }

    /// Encrypt this private key using a symmetric encryption key derived
    /// from the provided password.
    ///
    /// Uses the following algorithms for encryption:
    /// - PBKDF: scrypt with default parameters:
    ///   - log₂(N): 15
    ///   - r: 8
    ///   - p: 1
    /// - Cipher: AES-256-CBC (best available option for PKCS#5 encryption)
    #[cfg(feature = "encryption")]
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    pub fn encrypt(
        &self,
        mut rng: impl CryptoRng + RngCore,
        password: impl AsRef<[u8]>,
    ) -> Result<EncryptedPrivateKeyDocument> {
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);

        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);

        let pbes2_params = pbes2::Parameters::scrypt_aes256cbc(Default::default(), &salt, &iv)
            .map_err(|_| Error::Crypto)?;

        self.encrypt_with_params(pbes2_params, password)
    }

    /// Encrypt this private key using a symmetric encryption key derived
    /// from the provided password and [`pbes2::Parameters`].
    #[cfg(feature = "encryption")]
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    pub fn encrypt_with_params(
        &self,
        pbes2_params: pbes2::Parameters<'_>,
        password: impl AsRef<[u8]>,
    ) -> Result<EncryptedPrivateKeyDocument> {
        pbes2_params
            .encrypt(password, self.as_ref())
            .map_err(|_| Error::Crypto)
            .and_then(|encrypted_data| {
                EncryptedPrivateKeyInfo {
                    encryption_algorithm: pbes2_params.into(),
                    encrypted_data: &encrypted_data,
                }
                .try_into()
            })
    }
}

impl DecodePrivateKey for PrivateKeyDocument {
    fn from_pkcs8_private_key_info(private_key: PrivateKeyInfo<'_>) -> Result<Self> {
        Ok(Self(Zeroizing::new(private_key.to_vec()?)))
    }

    fn from_pkcs8_der(bytes: &[u8]) -> Result<Self> {
        // Ensure document is well-formed
        PrivateKeyInfo::try_from(bytes)?;
        Ok(Self(Zeroizing::new(bytes.to_owned())))
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    fn from_pkcs8_pem(s: &str) -> Result<Self> {
        let (label, der_bytes) = pem::decode_vec(s.as_bytes())?;

        if label != PEM_TYPE_LABEL {
            return Err(pem::Error::Label.into());
        }

        // Ensure document is well-formed
        PrivateKeyInfo::try_from(der_bytes.as_slice())?;
        Ok(Self(Zeroizing::new(der_bytes)))
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn read_pkcs8_der_file(path: impl AsRef<Path>) -> Result<Self> {
        fs::read(path)?.try_into()
    }

    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn read_pkcs8_pem_file(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_pkcs8_pem(&Zeroizing::new(fs::read_to_string(path)?))
    }
}

impl EncodePrivateKey for PrivateKeyDocument {
    fn to_pkcs8_der(&self) -> Result<PrivateKeyDocument> {
        Ok(self.clone())
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    fn to_pkcs8_pem(&self, line_ending: LineEnding) -> Result<Zeroizing<String>> {
        let pem_doc = pem::encode_string(PEM_TYPE_LABEL, line_ending, self.as_ref())?;
        Ok(Zeroizing::new(pem_doc))
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn write_pkcs8_der_file(&self, path: impl AsRef<Path>) -> Result<()> {
        write_secret_file(path, self.as_ref())
    }

    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn write_pkcs8_pem_file(&self, path: impl AsRef<Path>, line_ending: LineEnding) -> Result<()> {
        let pem_doc = self.to_pkcs8_pem(line_ending)?;
        write_secret_file(path, pem_doc.as_bytes())
    }
}

impl AsRef<[u8]> for PrivateKeyDocument {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<PrivateKeyInfo<'_>> for PrivateKeyDocument {
    type Error = Error;

    fn try_from(private_key_info: PrivateKeyInfo<'_>) -> Result<PrivateKeyDocument> {
        PrivateKeyDocument::from_pkcs8_private_key_info(private_key_info)
    }
}

impl TryFrom<&PrivateKeyInfo<'_>> for PrivateKeyDocument {
    type Error = Error;

    fn try_from(private_key_info: &PrivateKeyInfo<'_>) -> Result<PrivateKeyDocument> {
        PrivateKeyDocument::from_pkcs8_private_key_info(private_key_info.clone())
    }
}

impl TryFrom<&[u8]> for PrivateKeyDocument {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        PrivateKeyDocument::from_pkcs8_der(bytes)
    }
}

impl TryFrom<Vec<u8>> for PrivateKeyDocument {
    type Error = Error;

    fn try_from(mut bytes: Vec<u8>) -> Result<Self> {
        // Ensure document is well-formed
        if let Err(err) = PrivateKeyInfo::try_from(bytes.as_slice()) {
            bytes.zeroize();
            return Err(err);
        }

        Ok(Self(Zeroizing::new(bytes)))
    }
}

impl fmt::Debug for PrivateKeyDocument {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_tuple("PrivateKeyDocument")
            .field(&self.private_key_info())
            .finish()
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl FromStr for PrivateKeyDocument {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_pkcs8_pem(s)
    }
}

/// Write a file containing secret data to the filesystem, restricting the
/// file permissions so it's only readable by the owner
#[cfg(all(unix, feature = "std"))]
pub(super) fn write_secret_file(path: impl AsRef<Path>, data: &[u8]) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};

    /// File permissions for secret data
    #[cfg(unix)]
    const SECRET_FILE_PERMS: u32 = 0o600;

    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(SECRET_FILE_PERMS)
        .open(path)
        .and_then(|mut file| file.write_all(data))?;

    Ok(())
}

/// Write a file containing secret data to the filesystem
// TODO(tarcieri): permissions hardening on Windows
#[cfg(all(not(unix), feature = "std"))]
pub(super) fn write_secret_file(path: impl AsRef<Path>, data: &[u8]) -> Result<()> {
    fs::write(path, data)?;
    Ok(())
}
