//! OCSP builder module

use alloc::fmt;

mod request;
mod response;

pub use self::request::OcspRequestBuilder;
pub use self::response::OcspResponseBuilder;

/// Error type
#[derive(Debug)]
pub enum Error {
    /// ASN.1 DER-related errors
    Asn1(der::Error),

    /// Public key errors
    PublicKey(spki::Error),

    /// Signing errors
    Signature(signature::Error),
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Asn1(err) => write!(f, "ASN.1 error: {err}"),
            Error::PublicKey(err) => write!(f, "public key error: {err}"),
            Error::Signature(err) => write!(f, "signature error: {err}"),
        }
    }
}

impl From<der::Error> for Error {
    fn from(other: der::Error) -> Self {
        Self::Asn1(other)
    }
}

impl From<spki::Error> for Error {
    fn from(other: spki::Error) -> Self {
        Self::PublicKey(other)
    }
}

impl From<signature::Error> for Error {
    fn from(other: signature::Error) -> Self {
        Self::Signature(other)
    }
}
