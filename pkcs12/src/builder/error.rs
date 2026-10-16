//! Error and Result types for the `builder` module

use alloc::string::String;

/// Result type for the `builder` module
pub type Result<T> = core::result::Result<T, Error>;

/// Error type for the `builder` module
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// ASN.1 encoding/decoding error
    Asn1(der::Error),
    /// Invalid key length
    InvalidLength(crypto_common::InvalidLength),
    /// Something that was sought was not found
    NotFound,
    /// PKCS5-related error
    Pkcs5(pkcs5::Error),
    /// String-based error originating from PKCS #12 structure construction or parsing logic
    Pkcs12Builder(String),
}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
    }
}

impl From<pkcs5::Error> for Error {
    fn from(err: pkcs5::Error) -> Error {
        Error::Pkcs5(err)
    }
}

impl From<crypto_common::InvalidLength> for Error {
    fn from(err: crypto_common::InvalidLength) -> Error {
        Error::InvalidLength(err)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Asn1(e) => write!(f, "ASN.1 error: {e}"),
            Error::InvalidLength(e) => write!(f, "invalid length: {e}"),
            Error::NotFound => write!(f, "not found"),
            Error::Pkcs5(e) => write!(f, "PKCS#5 error: {e}"),
            Error::Pkcs12Builder(msg) => write!(f, "{msg}"),
        }
    }
}

impl core::error::Error for Error {}
