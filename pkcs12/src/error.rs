//! Error types
use core::fmt;

/// Result type
pub type Result<T> = core::result::Result<T, Error>;

/// Error type
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Given parameters are invalid for this algorithm
    InternalError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InternalError => {
                write!(f, "PKCS#12 internal error")
            }
       }
    }
}
