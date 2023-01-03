use crate::digest_info::DigestInfo;
use der::{
    asn1::{Int, OctetString},
    Sequence, ValueOrd,
};

/// ```text
/// MacData ::= SEQUENCE {
///     mac         DigestInfo,
///     macSalt     OCTET STRING,
///     iterations  INTEGER DEFAULT 1
///     -- Note: The default is for historical reasons and its
///     --       use is deprecated.
///}
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct MacData<'a> {
    /// the MAC digest info
    pub mac: DigestInfo<'a>,

    /// the MAC salt
    pub mac_salt: OctetString,

    /// the number of iterations
    pub iterations: Int,
}
