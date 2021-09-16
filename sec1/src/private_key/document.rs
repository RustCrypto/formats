//! SEC1 EC private key document.

use crate::{EcPrivateKey, Error, FromEcPrivateKey, Result, ToEcPrivateKey};
use alloc::{borrow::ToOwned, vec::Vec};
use core::{
    convert::{TryFrom, TryInto},
    fmt,
};
use der::{Decodable, Encodable};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "pem")]
use {
    crate::{pem, private_key::PEM_TYPE_LABEL, LineEnding},
    alloc::string::String,
    core::str::FromStr,
};

#[cfg(feature = "std")]
use std::{fs, path::Path, str};

/// SEC1 `EC PRIVATE KEY` document.
///
/// This type provides storage for [`EcPrivateKey`] encoded as ASN.1 DER
/// with the invariant that the contained-document is "well-formed", i.e. it
/// will parse successfully according to this crate's parsing rules.
#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub struct EcPrivateKeyDocument(Zeroizing<Vec<u8>>);

impl EcPrivateKeyDocument {
    /// Parse the [`EcPrivateKey`] contained in this [`EcPrivateKeyDocument`]
    pub fn private_key(&self) -> EcPrivateKey<'_> {
        EcPrivateKey::from_der(self.0.as_ref()).expect("malformed EcPrivateKeyDocument")
    }

    /// Borrow the inner DER encoded bytes.
    pub fn as_der(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl FromEcPrivateKey for EcPrivateKeyDocument {
    fn from_sec1_der(bytes: &[u8]) -> Result<Self> {
        // Ensure document is well-formed
        EcPrivateKey::from_der(bytes)?;
        Ok(Self(Zeroizing::new(bytes.to_owned())))
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    fn from_sec1_pem(s: &str) -> Result<Self> {
        let (label, der_bytes) = pem::decode_vec(s.as_bytes())?;

        if label != PEM_TYPE_LABEL {
            return Err(pem::Error::Label.into());
        }

        // Ensure document is well-formed
        EcPrivateKey::from_der(der_bytes.as_slice())?;
        Ok(Self(Zeroizing::new(der_bytes)))
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn read_sec1_der_file(path: &Path) -> Result<Self> {
        fs::read(path)?.try_into()
    }

    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn read_sec1_pem_file(path: &Path) -> Result<Self> {
        Self::from_sec1_pem(&Zeroizing::new(fs::read_to_string(path)?))
    }
}

impl ToEcPrivateKey for EcPrivateKeyDocument {
    fn to_sec1_der(&self) -> Result<EcPrivateKeyDocument> {
        Ok(self.clone())
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    fn to_sec1_pem(&self, line_ending: LineEnding) -> Result<Zeroizing<String>> {
        let pem_doc = pem::encode_string(PEM_TYPE_LABEL, line_ending, self.as_der())?;
        Ok(Zeroizing::new(pem_doc))
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn write_sec1_der_file(&self, path: &Path) -> Result<()> {
        write_secret_file(path, self.as_der())
    }

    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn write_sec1_pem_file(&self, path: &Path, line_ending: LineEnding) -> Result<()> {
        let pem_doc = self.to_sec1_pem(line_ending)?;
        write_secret_file(path, pem_doc.as_bytes())
    }
}

impl AsRef<[u8]> for EcPrivateKeyDocument {
    fn as_ref(&self) -> &[u8] {
        self.as_der()
    }
}

impl TryFrom<&[u8]> for EcPrivateKeyDocument {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        EcPrivateKeyDocument::from_sec1_der(bytes)
    }
}

impl TryFrom<EcPrivateKey<'_>> for EcPrivateKeyDocument {
    type Error = Error;

    fn try_from(private_key: EcPrivateKey<'_>) -> Result<Self> {
        Self::try_from(&private_key)
    }
}

impl TryFrom<&EcPrivateKey<'_>> for EcPrivateKeyDocument {
    type Error = Error;

    fn try_from(private_key: &EcPrivateKey<'_>) -> Result<Self> {
        Ok(Self(Zeroizing::new(private_key.to_vec()?)))
    }
}

impl TryFrom<Vec<u8>> for EcPrivateKeyDocument {
    type Error = Error;

    fn try_from(mut bytes: Vec<u8>) -> Result<Self> {
        // Ensure document is well-formed
        if let Err(err) = EcPrivateKey::from_der(bytes.as_slice()) {
            bytes.zeroize();
            return Err(err.into());
        }

        Ok(Self(Zeroizing::new(bytes)))
    }
}

impl fmt::Debug for EcPrivateKeyDocument {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_tuple("EcPrivateKeyDocument")
            .field(&self.private_key())
            .finish()
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl FromStr for EcPrivateKeyDocument {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_sec1_pem(s)
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
