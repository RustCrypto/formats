//! Error types

use core::fmt;

#[cfg(feature = "pem")]
use crate::pem;

/// Result type with `sec1` crate's [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// ASN.1 DER-related errors.
    Asn1(der::Error),

    /// Cryptographic errors.
    ///
    /// These can be used by EC implementations to signal that a key is
    /// invalid for cryptographic reasons. This means the document parsed
    /// correctly, but one of the values contained within was invalid, e.g.
    /// a number expected to be a prime was not a prime.
    Crypto,

    /// File not found error.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    FileNotFound,

    /// I/O errors.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    Io,

    /// PEM encoding errors.
    #[cfg(feature = "pem")]
    Pem(pem::Error),

    /// Permission denied reading file.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    PermissionDenied,

    /// Errors relating to the `Elliptic-Curve-Point-to-Octet-String` or
    /// `Octet-String-to-Elliptic-Curve-Point` encodings.
    PointEncoding,

    /// Version errors
    Version,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Asn1(err) => write!(f, "SEC1 ASN.1 error: {}", err),
            Error::Crypto => f.write_str("SEC1 cryptographic error"),
            #[cfg(feature = "std")]
            Error::FileNotFound => f.write_str("file not found"),
            #[cfg(feature = "std")]
            Error::Io => f.write_str("I/O error"),
            #[cfg(feature = "pem")]
            Error::Pem(err) => write!(f, "SEC1 {}", err),
            Error::PointEncoding => f.write_str("elliptic curve point encoding error"),
            Error::Version => f.write_str("SEC1 version error"),
            #[cfg(feature = "std")]
            Error::PermissionDenied => f.write_str("permission denied"),
        }
    }
}

#[cfg(feature = "pem")]
impl From<pem::Error> for Error {
    fn from(err: pem::Error) -> Error {
        Error::Pem(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
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
