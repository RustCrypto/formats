//! Traits for parsing objects from SEC1 encoded documents

use crate::{EcPrivateKey, Error, Result};
use core::convert::TryFrom;
use der::Decodable;

#[cfg(feature = "alloc")]
use crate::EcPrivateKeyDocument;

#[cfg(feature = "pem")]
use {crate::LineEnding, alloc::string::String};

#[cfg(feature = "std")]
use std::path::Path;

#[cfg(any(feature = "pem", feature = "std"))]
use {der::Document, zeroize::Zeroizing};

/// Parse an [`EcPrivateKey`] from a SEC1-encoded document.
pub trait DecodeEcPrivateKey: for<'a> TryFrom<EcPrivateKey<'a>, Error = Error> + Sized {
    /// Deserialize SEC1 private key from ASN.1 DER-encoded data
    /// (binary format).
    fn from_sec1_der(bytes: &[u8]) -> Result<Self> {
        Self::try_from(EcPrivateKey::from_der(bytes)?)
    }

    /// Deserialize SEC1-encoded private key from PEM.
    ///
    /// Keys in this format begin with the following:
    ///
    /// ```text
    /// -----BEGIN EC PRIVATE KEY-----
    /// ```
    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    fn from_sec1_pem(s: &str) -> Result<Self> {
        EcPrivateKeyDocument::from_sec1_pem(s).and_then(|doc| Self::try_from(doc.decode()))
    }

    /// Load SEC1 private key from an ASN.1 DER-encoded file on the local
    /// filesystem (binary format).
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn read_sec1_der_file(path: impl AsRef<Path>) -> Result<Self> {
        EcPrivateKeyDocument::read_sec1_der_file(path).and_then(|doc| Self::try_from(doc.decode()))
    }

    /// Load SEC1 private key from a PEM-encoded file on the local filesystem.
    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn read_sec1_pem_file(path: impl AsRef<Path>) -> Result<Self> {
        EcPrivateKeyDocument::read_sec1_pem_file(path).and_then(|doc| Self::try_from(doc.decode()))
    }
}

/// Serialize a [`EcPrivateKey`] to a SEC1 encoded document.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub trait EncodeEcPrivateKey {
    /// Serialize a [`EcPrivateKeyDocument`] containing a SEC1-encoded private key.
    fn to_sec1_der(&self) -> Result<EcPrivateKeyDocument>;

    /// Serialize this private key as PEM-encoded SEC1 with the given [`LineEnding`].
    ///
    /// To use the OS's native line endings, pass `Default::default()`.
    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    fn to_sec1_pem(&self, line_ending: LineEnding) -> Result<Zeroizing<String>> {
        self.to_sec1_der()?.to_sec1_pem(line_ending)
    }

    /// Write ASN.1 DER-encoded SEC1 private key to the given path.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn write_sec1_der_file(&self, path: impl AsRef<Path>) -> Result<()> {
        self.to_sec1_der()?.write_sec1_der_file(path)
    }

    /// Write ASN.1 DER-encoded SEC1 private key to the given path.
    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn write_sec1_pem_file(&self, path: impl AsRef<Path>, line_ending: LineEnding) -> Result<()> {
        self.to_sec1_der()?.write_sec1_pem_file(path, line_ending)
    }
}
