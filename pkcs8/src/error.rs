//! Error types

use core::fmt;

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

    /// Malformed cryptographic key contained in a PKCS#8 document.
    ///
    /// This is intended for relaying errors related to the raw data contained
    /// within [`PrivateKeyInfo::private_key`][`crate::PrivateKeyInfo::private_key`]
    /// or [`SubjectPublicKeyInfo::subject_public_key`][`crate::SubjectPublicKeyInfo::subject_public_key`].
    KeyMalformed,

    /// [`AlgorithmIdentifier::parameters`][`crate::AlgorithmIdentifier::parameters`]
    /// is malformed or otherwise encoded in an unexpected manner.
    ParametersMalformed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Asn1(err) => write!(f, "PKCS#8 ASN.1 error: {}", err),
            Error::Crypto => f.write_str("PKCS#8 cryptographic error"),
            Error::KeyMalformed => f.write_str("PKCS#8 cryptographic key data malformed"),
            Error::ParametersMalformed => f.write_str("PKCS#8 algorithm parameters malformed"),
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
