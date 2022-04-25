//! Error types

use crate::pem;
use core::fmt;

#[cfg(feature = "alloc")]
use crate::certificate;

/// Result type with `ssh-key`'s [`Error`] as the error type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Algorithm-related errors.
    Algorithm,

    /// Base64-related errors.
    Base64(base64ct::Error),

    /// Certificate field is invalid or already set.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    CertificateFieldInvalid(certificate::Field),

    /// Certificate validation failed.
    CertificateValidation,

    /// Character encoding-related errors.
    CharacterEncoding,

    /// Cryptographic errors.
    Crypto,

    /// Cannot perform operation on decrypted private key.
    Decrypted,

    /// ECDSA key encoding errors.
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    Ecdsa(sec1::Error),

    /// Cannot perform operation on encrypted private key.
    Encrypted,

    /// Other format encoding errors.
    FormatEncoding,

    /// Input/output errors.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    Io(std::io::ErrorKind),

    /// Invalid length.
    Length,

    /// Overflow errors.
    Overflow,

    /// PEM encoding errors.
    Pem(pem::Error),

    /// Public key does not match private key.
    PublicKey,

    /// Invalid timestamp (e.g. in a certificate)
    Time,

    /// Unexpected trailing data at end of message.
    TrailingData {
        /// Number of bytes of remaining data at end of message.
        remaining: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Algorithm => write!(f, "unknown or unsupported algorithm"),
            Error::Base64(err) => write!(f, "Base64 encoding error: {}", err),
            #[cfg(feature = "alloc")]
            Error::CertificateFieldInvalid(field) => {
                write!(f, "certificate field invalid: {}", field)
            }
            Error::CertificateValidation => write!(f, "certificate validation failed"),
            Error::CharacterEncoding => write!(f, "character encoding invalid"),
            Error::Crypto => write!(f, "cryptographic error"),
            Error::Decrypted => write!(f, "private key is already decrypted"),
            #[cfg(feature = "ecdsa")]
            Error::Ecdsa(err) => write!(f, "ECDSA encoding error: {}", err),
            Error::Encrypted => write!(f, "private key is encrypted"),
            Error::FormatEncoding => write!(f, "format encoding error"),
            #[cfg(feature = "std")]
            Error::Io(err) => write!(f, "I/O error: {}", std::io::Error::from(*err)),
            Error::Length => write!(f, "length invalid"),
            Error::Overflow => write!(f, "internal overflow error"),
            Error::Pem(err) => write!(f, "{}", err),
            Error::PublicKey => write!(f, "public key is incorrect"),
            Error::Time => write!(f, "invalid time"),
            Error::TrailingData { remaining } => write!(
                f,
                "unexpected trailing data at end of message ({} bytes)",
                remaining
            ),
        }
    }
}

impl From<base64ct::Error> for Error {
    fn from(err: base64ct::Error) -> Error {
        Error::Base64(err)
    }
}

impl From<base64ct::InvalidLengthError> for Error {
    fn from(_: base64ct::InvalidLengthError) -> Error {
        Error::Length
    }
}

impl From<core::array::TryFromSliceError> for Error {
    fn from(_: core::array::TryFromSliceError) -> Error {
        Error::Length
    }
}

impl From<core::num::TryFromIntError> for Error {
    fn from(_: core::num::TryFromIntError) -> Error {
        Error::Overflow
    }
}

impl From<core::str::Utf8Error> for Error {
    fn from(_: core::str::Utf8Error) -> Error {
        Error::CharacterEncoding
    }
}

impl From<pem_rfc7468::Error> for Error {
    fn from(err: pem_rfc7468::Error) -> Error {
        Error::Pem(err)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl From<alloc::string::FromUtf8Error> for Error {
    fn from(_: alloc::string::FromUtf8Error) -> Error {
        Error::CharacterEncoding
    }
}

#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
impl From<sec1::Error> for Error {
    fn from(err: sec1::Error) -> Error {
        Error::Ecdsa(err)
    }
}

#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl From<rsa::errors::Error> for Error {
    fn from(_: rsa::errors::Error) -> Error {
        Error::Crypto
    }
}

#[cfg(feature = "signature")]
#[cfg_attr(docsrs, doc(cfg(feature = "signature")))]
impl From<signature::Error> for Error {
    fn from(_: signature::Error) -> Error {
        Error::Crypto
    }
}

#[cfg(feature = "signature")]
#[cfg_attr(docsrs, doc(cfg(feature = "signature")))]
impl From<Error> for signature::Error {
    fn from(_: Error) -> signature::Error {
        signature::Error::new()
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Io(err.kind())
    }
}

#[cfg(feature = "std")]
impl From<std::time::SystemTimeError> for Error {
    fn from(_: std::time::SystemTimeError) -> Error {
        Error::Time
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
