//! Error types.

use core::fmt;

#[cfg(feature = "base64")]
use base64ct::Error as B64Error;

/// Result type for `mcf`.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Base64 encoding errors.
    #[cfg(feature = "base64")]
    Base64(B64Error),

    /// `$` delimiter either missing or in an unexpected place
    DelimiterInvalid,

    /// Encoding validation failure or error during encode time
    EncodingInvalid,

    /// MCF field (between `$` characters) is not well-formed
    FieldInvalid,

    /// MCF identifier missing
    IdentifierMissing,

    /// MCF identifier invalid (must be `a-z`, `0-9`, or `-`)
    IdentifierInvalid,
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            #[cfg(feature = "base64")]
            Error::Base64(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "base64")]
            Error::Base64(base64_err) => write!(f, "{base64_err}"),
            Error::DelimiterInvalid => write!(f, "invalid use of `$` delimiter"),
            Error::EncodingInvalid => write!(f, "invalid MCF encoding"),
            Error::FieldInvalid => write!(f, "invalid MCF field (between `$` characters)"),
            Error::IdentifierMissing => write!(f, "MCF identifier missing"),
            Error::IdentifierInvalid => write!(f, "MCF identifier invalid"),
        }
    }
}

#[cfg(feature = "base64")]
impl From<B64Error> for Error {
    fn from(base64_err: B64Error) -> Self {
        Error::Base64(base64_err)
    }
}

impl From<fmt::Error> for Error {
    fn from(_: fmt::Error) -> Self {
        Error::EncodingInvalid
    }
}
