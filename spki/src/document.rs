//! SPKI public key document.

use crate::{FromPublicKey, SubjectPublicKeyInfo, ToPublicKey};
use alloc::{borrow::ToOwned, vec::Vec};
use core::{
    convert::{TryFrom, TryInto},
    fmt,
};
use der::{Encodable, Error, Result};

#[cfg(feature = "std")]
use std::{fs, path::Path};

#[cfg(feature = "pem")]
use {
    alloc::string::String,
    core::str::FromStr,
    der::pem::{self, LineEnding},
};

/// Type label for PEM-encoded private keys.
#[cfg(feature = "pem")]
pub(crate) const PEM_TYPE_LABEL: &str = "PUBLIC KEY";

/// SPKI public key document.
///
/// This type provides storage for [`SubjectPublicKeyInfo`] encoded as ASN.1
/// DER with the invariant that the contained-document is "well-formed", i.e.
/// it will parse successfully according to this crate's parsing rules.
#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub struct PublicKeyDocument(Vec<u8>);

impl PublicKeyDocument {
    /// Parse the [`SubjectPublicKeyInfo`] contained in this [`PublicKeyDocument`]
    pub fn spki(&self) -> SubjectPublicKeyInfo<'_> {
        SubjectPublicKeyInfo::try_from(self.0.as_slice()).expect("malformed PublicKeyDocument")
    }
}

impl FromPublicKey for PublicKeyDocument {
    fn from_spki(spki: SubjectPublicKeyInfo<'_>) -> Result<Self> {
        Ok(Self(spki.to_vec()?))
    }

    fn from_public_key_der(bytes: &[u8]) -> Result<Self> {
        // Ensure document is well-formed
        SubjectPublicKeyInfo::try_from(bytes)?;
        Ok(Self(bytes.to_owned()))
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    fn from_public_key_pem(s: &str) -> Result<Self> {
        let (label, der_bytes) = pem::decode_vec(s.as_bytes())?;

        if label != PEM_TYPE_LABEL {
            return Err(pem::Error::Label.into());
        }

        // Ensure document is well-formed
        SubjectPublicKeyInfo::try_from(der_bytes.as_slice())?;
        Ok(Self(der_bytes))
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn read_public_key_der_file(path: impl AsRef<Path>) -> Result<Self> {
        fs::read(path)?.try_into()
    }

    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn read_public_key_pem_file(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_public_key_pem(&fs::read_to_string(path)?)
    }
}

impl ToPublicKey for PublicKeyDocument {
    fn to_public_key_der(&self) -> Result<PublicKeyDocument> {
        Ok(self.clone())
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    fn to_public_key_pem(&self, line_ending: LineEnding) -> Result<String> {
        Ok(pem::encode_string(PEM_TYPE_LABEL, line_ending, &self.0)?)
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn write_public_key_der_file(&self, path: impl AsRef<Path>) -> Result<()> {
        fs::write(path, self.as_ref())?;
        Ok(())
    }

    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn write_public_key_pem_file(
        &self,
        path: impl AsRef<Path>,
        line_ending: LineEnding,
    ) -> Result<()> {
        fs::write(path, self.to_public_key_pem(line_ending)?.as_bytes())?;
        Ok(())
    }
}

impl AsRef<[u8]> for PublicKeyDocument {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<SubjectPublicKeyInfo<'_>> for PublicKeyDocument {
    type Error = Error;

    fn try_from(spki: SubjectPublicKeyInfo<'_>) -> Result<PublicKeyDocument> {
        PublicKeyDocument::try_from(&spki)
    }
}

impl TryFrom<&SubjectPublicKeyInfo<'_>> for PublicKeyDocument {
    type Error = Error;

    fn try_from(spki: &SubjectPublicKeyInfo<'_>) -> Result<PublicKeyDocument> {
        spki.to_vec()?.try_into()
    }
}

impl TryFrom<&[u8]> for PublicKeyDocument {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        // Ensure document is well-formed
        SubjectPublicKeyInfo::try_from(bytes)?;
        Ok(Self(bytes.to_owned()))
    }
}

impl TryFrom<Vec<u8>> for PublicKeyDocument {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        // Ensure document is well-formed
        SubjectPublicKeyInfo::try_from(bytes.as_slice())?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for PublicKeyDocument {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_tuple("PublicKeyDocument")
            .field(&self.spki())
            .finish()
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl FromStr for PublicKeyDocument {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_public_key_pem(s)
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl pem::PemLabel for PublicKeyDocument {
    const TYPE_LABEL: &'static str = "PUBLIC KEY";
}
