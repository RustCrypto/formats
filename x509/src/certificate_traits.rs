//! CertificateDocument implementation

use crate::Certificate;
use der::{Error, Result};

#[cfg(any(feature = "alloc", feature = "std"))]
use {crate::certificate_document::CertificateDocument, der::Document};

#[cfg(feature = "std")]
use std::path::Path;

#[cfg(feature = "pem")]
use {alloc::string::String, der::pem::LineEnding};

/// Parse a public key object from an encoded Certificate document.
pub trait DecodeCertificate: for<'a> TryFrom<Certificate<'a>, Error = Error> + Sized {
    /// Deserialize object from ASN.1 DER-encoded [`Certificate`]
    /// (binary format).
    fn from_certificate_der(bytes: &[u8]) -> Result<Self> {
        Self::try_from(Certificate::try_from(bytes)?)
    }

    /// Deserialize certificate from a [`CertificateDocument`].
    #[cfg(any(feature = "alloc", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
    fn from_certificate_doc(doc: &CertificateDocument) -> Result<Self> {
        Self::try_from(doc.decode())
    }

    /// Deserialize PEM-encoded [`Certificate`].
    ///
    /// Keys in this format begin with the following delimiter:
    ///
    /// ```text
    /// -----BEGIN CERTIFICATE-----
    /// ```
    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    fn from_certificate_pem(s: &str) -> Result<Self> {
        CertificateDocument::from_certificate_pem(s)
            .and_then(|doc| Self::from_certificate_doc(&doc))
    }

    /// Load public key object from an ASN.1 DER-encoded file on the local
    /// filesystem (binary format).
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn read_certificate_der_file(path: impl AsRef<Path>) -> Result<Self> {
        CertificateDocument::read_certificate_der_file(path)
            .and_then(|doc| Self::from_certificate_doc(&doc))
    }

    /// Load public key object from a PEM-encoded file on the local filesystem.
    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "pem", feature = "std"))))]
    fn read_certificate_pem_file(path: impl AsRef<Path>) -> Result<Self> {
        CertificateDocument::read_certificate_pem_file(path)
            .and_then(|doc| Self::from_certificate_doc(&doc))
    }
}

/// Serialize a certificate object to a DER-encoded document.
#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub trait EncodeCertificate {
    /// Serialize a [`CertificateDocument`] containing a Certificate.
    fn to_certificate_der(&self) -> Result<CertificateDocument>;

    /// Serialize this public key as PEM-encoded Certificate with the given [`LineEnding`].
    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    fn to_certificate_pem(&self, line_ending: LineEnding) -> Result<String> {
        self.to_certificate_der()?.to_certificate_pem(line_ending)
    }

    /// Write ASN.1 DER-encoded public key to the given path
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn write_certificate_der_file(&self, path: impl AsRef<Path>) -> Result<()> {
        self.to_certificate_der()?.write_certificate_der_file(path)
    }

    /// Write ASN.1 DER-encoded public key to the given path
    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "pem", feature = "std"))))]
    fn write_certificate_pem_file(
        &self,
        path: impl AsRef<Path>,
        line_ending: LineEnding,
    ) -> Result<()> {
        self.to_certificate_der()?
            .write_certificate_pem_file(path, line_ending)
    }
}
