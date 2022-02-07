//! CertificateDocument implementation

use crate::certificate_traits::*;
use crate::Certificate;
use der::{Error, Result};

use alloc::vec::Vec;
use core::fmt;
use der::{Decodable, Document};

#[cfg(feature = "std")]
use std::path::Path;

#[cfg(feature = "pem")]
use {
    alloc::string::String,
    core::str::FromStr,
    der::pem::{self, LineEnding},
};

/// Certificate document.
///
/// This type provides storage for [`Certificate`] encoded as ASN.1
/// DER with the invariant that the contained-document is "well-formed", i.e.
/// it will parse successfully according to this crate's parsing rules.
#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub struct CertificateDocument(Vec<u8>);

impl<'a> TryFrom<&'a [u8]> for Certificate<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Self::from_der(bytes)
    }
}

impl<'a> Document<'a> for CertificateDocument {
    type Message = Certificate<'a>;
    const SENSITIVE: bool = false;
}

impl DecodeCertificate for CertificateDocument {
    fn from_certificate_der(bytes: &[u8]) -> Result<Self> {
        Self::from_der(bytes)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    fn from_certificate_pem(s: &str) -> Result<Self> {
        Self::from_pem(s)
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn read_certificate_der_file(path: impl AsRef<Path>) -> Result<Self> {
        Self::read_der_file(path)
    }

    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "pem", feature = "std"))))]
    fn read_certificate_pem_file(path: impl AsRef<Path>) -> Result<Self> {
        Self::read_pem_file(path)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl EncodeCertificate for CertificateDocument {
    fn to_certificate_der(&self) -> Result<CertificateDocument> {
        Ok(self.clone())
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    fn to_certificate_pem(&self, line_ending: LineEnding) -> Result<String> {
        self.to_pem(line_ending)
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn write_certificate_der_file(&self, path: impl AsRef<Path>) -> Result<()> {
        self.write_der_file(path)
    }

    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "pem", feature = "std"))))]
    fn write_certificate_pem_file(
        &self,
        path: impl AsRef<Path>,
        line_ending: LineEnding,
    ) -> Result<()> {
        self.write_pem_file(path, line_ending)
    }
}

impl AsRef<[u8]> for CertificateDocument {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<&[u8]> for CertificateDocument {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_der(bytes)
    }
}

impl TryFrom<Certificate<'_>> for CertificateDocument {
    type Error = Error;

    fn try_from(cert: Certificate<'_>) -> Result<CertificateDocument> {
        Self::try_from(&cert)
    }
}

impl TryFrom<&Certificate<'_>> for CertificateDocument {
    type Error = Error;

    fn try_from(cert: &Certificate<'_>) -> Result<CertificateDocument> {
        Self::from_msg(cert)
    }
}

impl TryFrom<Vec<u8>> for CertificateDocument {
    type Error = der::Error;

    fn try_from(bytes: Vec<u8>) -> der::Result<Self> {
        // Ensure document is well-formed
        Certificate::from_der(bytes.as_slice())?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for CertificateDocument {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_tuple("CertificateDocument")
            .field(&self.decode())
            .finish()
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl FromStr for CertificateDocument {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_certificate_pem(s)
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl pem::PemLabel for CertificateDocument {
    const TYPE_LABEL: &'static str = "CERTIFICATE";
}
