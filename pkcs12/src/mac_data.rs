//! MacData-related types

use crate::digest_info::DigestInfo;
use der::{Sequence, ValueOrd, asn1::OctetString};

/// The `MacData` type is defined in [RFC 7292 Section 4].
///
/// ```text
/// MacData ::= SEQUENCE {
///     mac         DigestInfo,
///     macSalt     OCTET STRING,
///     iterations  INTEGER DEFAULT 1
///     -- Note: The default is for historical reasons and its
///     --       use is deprecated.
///}
/// ```
///
/// [RFC 7292 Section 4]: https://www.rfc-editor.org/rfc/rfc7292#section-4
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct MacData {
    /// the MAC digest info
    pub mac: DigestInfo,

    /// the MAC salt
    pub mac_salt: OctetString,

    /// the number of iterations
    #[asn1(default = "default_one")]
    pub iterations: i32,
}

fn default_one() -> i32 {
    1
}
