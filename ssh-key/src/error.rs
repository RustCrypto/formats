//! Error types

use core::fmt;

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

    /// Character encoding-related errors.
    CharacterEncoding,

    /// ECDSA key encoding errors.
    #[cfg(feature = "sec1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sec1")))]
    Ecdsa(sec1::Error),

    /// Invalid length.
    Length,

    /// Overflow errors.
    Overflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Algorithm => f.write_str("unknown or unsupported algorithm"),
            Error::Base64(err) => write!(f, "Base64 encoding error: {}", err),
            Error::CharacterEncoding => f.write_str("character encoding invalid"),
            #[cfg(feature = "sec1")]
            Error::Ecdsa(err) => write!(f, "ECDSA encoding error: {}", err),
            Error::Length => f.write_str("length invalid"),
            Error::Overflow => f.write_str("internal overflow error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

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

#[cfg(feature = "sec1")]
#[cfg_attr(docsrs, doc(cfg(feature = "sec1")))]
impl From<sec1::Error> for Error {
    fn from(err: sec1::Error) -> Error {
        Error::Ecdsa(err)
    }
}
