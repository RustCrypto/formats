//! OCSP builder errors

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
