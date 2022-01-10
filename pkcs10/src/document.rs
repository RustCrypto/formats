//! Certification request document.

use super::CertReq;

use alloc::vec::Vec;
use core::fmt;

use der::{Decodable, Document};

#[cfg(feature = "pem")]
use {core::str::FromStr, der::pem};

/// Certification request document.
///
/// This type provides storage for [`CertReq`] encoded as ASN.1
/// DER with the invariant that the contained-document is "well-formed", i.e.
/// it will parse successfully according to this crate's parsing rules.
#[derive(Clone)]
pub struct CertReqDocument(Vec<u8>);

impl<'a> Document<'a> for CertReqDocument {
    type Message = CertReq<'a>;
    const SENSITIVE: bool = false;
}

impl AsRef<[u8]> for CertReqDocument {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<&[u8]> for CertReqDocument {
    type Error = der::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bytes.to_vec().try_into()
    }
}

impl TryFrom<CertReq<'_>> for CertReqDocument {
    type Error = der::Error;

    fn try_from(cr: CertReq<'_>) -> Result<CertReqDocument, Self::Error> {
        Self::try_from(&cr)
    }
}

impl TryFrom<&CertReq<'_>> for CertReqDocument {
    type Error = der::Error;

    fn try_from(cr: &CertReq<'_>) -> Result<CertReqDocument, Self::Error> {
        Self::from_msg(cr)
    }
}

impl TryFrom<Vec<u8>> for CertReqDocument {
    type Error = der::Error;

    fn try_from(bytes: Vec<u8>) -> der::Result<Self> {
        // Ensure document is well-formed
        CertReq::from_der(bytes.as_slice())?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for CertReqDocument {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_tuple("CertReqDocument")
            .field(&self.decode())
            .finish()
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl FromStr for CertReqDocument {
    type Err = der::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_pem(s)
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl pem::PemLabel for CertReqDocument {
    const TYPE_LABEL: &'static str = "CERTIFICATE REQUEST";
}
