//! Error types

use core::fmt;
use der::asn1::ObjectIdentifier;

/// Result type with `spki` crate's [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Algorithm parameters are missing.
    AlgorithmParametersMissing,

    /// ASN.1 DER-related errors.
    Asn1(der::Error),

    /// Unknown algorithm OID.
    UnknownOid {
        /// Unrecognized OID value found in e.g. a SPKI `AlgorithmIdentifier`.
        oid: ObjectIdentifier,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AlgorithmParametersMissing => {
                f.write_str("AlgorithmIdentifier parameters missing")
            }
            Error::Asn1(err) => write!(f, "ASN.1 error: {}", err),
            Error::UnknownOid { oid } => {
                write!(f, "unknown/unsupported algorithm OID: {}", oid)
            }
        }
    }
}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
