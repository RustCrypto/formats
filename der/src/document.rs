//! ASN.1 DER-encoded documents stored on the heap.

use crate::{Decodable, Encodable, Error, Result};
use alloc::vec::Vec;
use core::{
    fmt::{self, Debug},
    marker::PhantomData,
};

#[cfg(feature = "pem")]
use {
    crate::pem::{self, PemLabel},
    alloc::string::String,
    core::str::FromStr,
};

#[cfg(feature = "std")]
use std::{fs, path::Path};

/// ASN.1 DER-encoded document.
///
/// This type wraps an encoded ASN.1 DER message which is guaranteed to
/// infallibly decode as type `T`.
///
/// It implements common functionality related to encoding/decoding such
/// documents, such as PEM encapsulation as well as reading/writing documents
/// from/to the filesystem.
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub struct Document<T, const SENSITIVE: bool> {
    /// ASN.1 DER-encoded document guaranteed to decode to `T` infallibly.
    der_bytes: Vec<u8>,

    /// Rust type corresponding to the ASN.1 DER message the bytes can be
    /// infallibly deserialized as.
    msg_type: PhantomData<T>,
}

impl<T, const SENSITIVE: bool> Document<T, SENSITIVE> {
    /// Borrow the inner serialized bytes of this document.
    pub fn as_der(&self) -> &[u8] {
        self.der_bytes.as_slice()
    }

    /// Decode this document as ASN.1 DER.
    pub fn decode<'a>(&'a self) -> T
    where
        T: Decodable<'a> + Sized,
    {
        self.try_decode().expect("ASN.1 DER document malformed")
    }

    /// Create a new document from the provided ASN.1 DER bytes.
    pub fn from_der(bytes: impl Into<Vec<u8>>) -> Result<Self>
    where
        T: for<'a> Decodable<'a> + Sized,
    {
        let doc = Self {
            der_bytes: bytes.into(),
            msg_type: PhantomData,
        };

        // Ensure document parses successfully
        doc.try_decode()?;
        Ok(doc)
    }

    /// Return an allocated ASN.1 DER serialization as a byte vector.
    pub fn to_der(&self) -> Vec<u8> {
        self.der_bytes.clone()
    }

    /// Encode the provided type as ASN.1 DER.
    pub fn from_msg(msg: &T) -> Result<Self>
    where
        T: for<'a> Decodable<'a> + Encodable + Sized,
    {
        msg.to_vec()?.try_into()
    }

    /// Decode ASN.1 DER document from PEM.
    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    pub fn from_pem(s: &str) -> Result<Self>
    where
        T: for<'a> Decodable<'a> + PemLabel + Sized,
    {
        let (label, der_bytes) = pem::decode_vec(s.as_bytes())?;

        if label != T::TYPE_LABEL {
            return Err(pem::Error::Label.into());
        }

        der_bytes.try_into()
    }

    /// Encode ASN.1 DER document as a PEM string.
    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    pub fn to_pem(&self, line_ending: pem::LineEnding) -> Result<String>
    where
        T: PemLabel,
    {
        Ok(pem::encode_string(
            T::TYPE_LABEL,
            line_ending,
            self.as_der(),
        )?)
    }

    /// Read ASN.1 DER document from a file.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn read_der_file(path: impl AsRef<Path>) -> Result<Self>
    where
        T: for<'a> Decodable<'a> + Sized,
    {
        fs::read(path)?.try_into()
    }

    /// Write ASN.1 DER document to a file.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn write_der_file(&self, path: impl AsRef<Path>) -> Result<()> {
        write_file(path, self.as_der(), SENSITIVE)
    }

    /// Read PEM-encoded ASN.1 DER document from a file.
    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "pem", feature = "std"))))]
    pub fn read_pem_file(path: impl AsRef<Path>) -> Result<Self>
    where
        T: for<'a> Decodable<'a> + PemLabel + Sized,
    {
        Self::from_pem(&fs::read_to_string(path)?)
    }

    /// Write PEM-encoded ASN.1 DER document to a file.
    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "pem", feature = "std"))))]
    pub fn write_pem_file(&self, path: impl AsRef<Path>, line_ending: pem::LineEnding) -> Result<()>
    where
        T: PemLabel,
    {
        write_file(path, self.to_pem(line_ending)?.as_bytes(), SENSITIVE)
    }

    /// Attempt to decode `self.der_bytes` as `T`.
    ///
    /// This method doesn't uphold the invariant that `T` always decodes
    /// successfully, but is needed to make the lifetimes for the constructor
    /// work.
    fn try_decode<'a>(&'a self) -> Result<T>
    where
        T: Decodable<'a> + Sized,
    {
        T::from_der(self.as_der())
    }
}

impl<T, const SENSITIVE: bool> AsRef<[u8]> for Document<T, SENSITIVE> {
    fn as_ref(&self) -> &[u8] {
        self.as_der()
    }
}

impl<T> Debug for Document<T, false>
where
    T: for<'a> Decodable<'a> + Debug + Sized,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_tuple("Document").field(&self.decode()).finish()
    }
}

impl<T> Debug for Document<T, true> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Document").finish_non_exhaustive()
    }
}

// NOTE: `Drop` is defined unconditionally to ensure bounds do not change based
// on selected cargo features, which would not be a purely additive change
impl<T, const SENSITIVE: bool> Drop for Document<T, SENSITIVE> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        if SENSITIVE {
            use zeroize::Zeroize;
            self.der_bytes.zeroize();
        }
    }
}

impl<T, const SENSITIVE: bool> TryFrom<&[u8]> for Document<T, SENSITIVE>
where
    T: for<'a> Decodable<'a> + Sized,
{
    type Error = Error;

    fn try_from(der_bytes: &[u8]) -> Result<Self> {
        Self::from_der(der_bytes)
    }
}

impl<T, const SENSITIVE: bool> TryFrom<Vec<u8>> for Document<T, SENSITIVE>
where
    T: for<'a> Decodable<'a> + Sized,
{
    type Error = Error;

    fn try_from(der_bytes: Vec<u8>) -> Result<Self> {
        Self::from_der(der_bytes)
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl<T, const SENSITIVE: bool> FromStr for Document<T, SENSITIVE>
where
    T: for<'a> Decodable<'a> + PemLabel + Sized,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_pem(s)
    }
}

/// Write a file to the filesystem, potentially using hardened permissions
/// if the file contains secret data.
#[cfg(feature = "std")]
fn write_file(path: impl AsRef<Path>, data: &[u8], sensitive: bool) -> Result<()> {
    if sensitive {
        write_secret_file(path, data)
    } else {
        Ok(fs::write(path, data)?)
    }
}

/// Write a file containing secret data to the filesystem, restricting the
/// file permissions so it's only readable by the owner
#[cfg(all(unix, feature = "std"))]
fn write_secret_file(path: impl AsRef<Path>, data: &[u8]) -> Result<()> {
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
fn write_secret_file(path: impl AsRef<Path>, data: &[u8]) -> Result<()> {
    fs::write(path, data)?;
    Ok(())
}
