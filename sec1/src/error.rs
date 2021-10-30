//! Error types

use core::fmt;

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
            Error::PointEncoding => f.write_str("elliptic curve point encoding error"),
            Error::Version => f.write_str("SEC1 version error"),
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
