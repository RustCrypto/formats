//! CertificateDocument implementation

use crate::Certificate;
use der::{Error, Result};

use alloc::vec::Vec;
use core::fmt;
use der::{Decode, Document};

#[cfg(feature = "pem")]
use {core::str::FromStr, der::pem};

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
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
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
        Self::from_pem(s)
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl pem::PemLabel for CertificateDocument {
    const TYPE_LABEL: &'static str = "CERTIFICATE";
}
