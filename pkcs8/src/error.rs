//! Error types

use core::fmt;

#[cfg(feature = "pem")]
use crate::pem;

/// Result type
pub type Result<T> = core::result::Result<T, Error>;

/// Error type
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// ASN.1 DER-related errors.
    Asn1(der::Error),

    /// Cryptographic errors.
    ///
    /// This is primarily used for relaying PKCS#5-related errors for
    /// PKCS#8 documents which have been encrypted under a password.
    Crypto,

    /// File not found error.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    FileNotFound,

    /// Malformed cryptographic key contained in a PKCS#8 document.
    ///
    /// This is intended for relaying errors related to the raw data contained
    /// within [`PrivateKeyInfo::private_key`][`crate::PrivateKeyInfo::private_key`]
    /// or [`SubjectPublicKeyInfo::subject_public_key`][`crate::SubjectPublicKeyInfo::subject_public_key`].
    KeyMalformed,

    /// I/O errors.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    Io,

    /// [`AlgorithmIdentifier::parameters`][`crate::AlgorithmIdentifier::parameters`]
    /// is malformed or otherwise encoded in an unexpected manner.
    ParametersMalformed,

    /// PEM encoding errors.
    #[cfg(feature = "pem")]
    Pem(pem::Error),

    /// Permission denied reading file.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    PermissionDenied,

    /// PKCS#1 errors.
    #[cfg(feature = "pkcs1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pkcs1")))]
    Pkcs1(pkcs1::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Asn1(err) => write!(f, "PKCS#8 ASN.1 error: {}", err),
            Error::Crypto => f.write_str("PKCS#8 cryptographic error"),
            #[cfg(feature = "std")]
            Error::FileNotFound => f.write_str("file not found"),
            Error::KeyMalformed => f.write_str("PKCS#8 cryptographic key data malformed"),
            #[cfg(feature = "std")]
            Error::Io => f.write_str("I/O error"),
            Error::ParametersMalformed => f.write_str("PKCS#8 algorithm parameters malformed"),
            #[cfg(feature = "pem")]
            Error::Pem(err) => write!(f, "PKCS8 {}", err),
            #[cfg(feature = "std")]
            Error::PermissionDenied => f.write_str("permission denied"),
            #[cfg(feature = "pkcs1")]
            Error::Pkcs1(err) => write!(f, "{}", err),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
    }
}

impl From<der::ErrorKind> for Error {
    fn from(err: der::ErrorKind) -> Error {
        Error::Asn1(err.into())
    }
}

#[cfg(feature = "pem")]
impl From<pem::Error> for Error {
    fn from(err: pem::Error) -> Error {
        Error::Pem(err)
    }
}

#[cfg(feature = "pkcs1")]
impl From<pkcs1::Error> for Error {
    fn from(err: pkcs1::Error) -> Error {
        Error::Pkcs1(err)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        match err.kind() {
            std::io::ErrorKind::NotFound => Error::FileNotFound,
            std::io::ErrorKind::PermissionDenied => Error::PermissionDenied,
            _ => Error::Io,
        }
    }
}
