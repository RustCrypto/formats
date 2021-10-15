//! Validity [`Validity`] as defined in RFC 5280

use crate::Time;
use core::convert::TryFrom;
use der::{Decodable, Error, Result, Sequence};

/// X.509 `Validity` as defined in [RFC 5280 Section 4.1.2.5]
///
/// ```text
/// Validity ::= SEQUENCE {
///     notBefore      Time,
///     notAfter       Time  }
/// ```
/// [RFC 5280 Section 4.1.2.5]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Validity {
    /// notBefore value
    pub not_before: Time,

    /// notAfter value
    pub not_after: Time,
}

impl<'a> TryFrom<&'a [u8]> for Validity {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Self::from_der(bytes)
    }
}
