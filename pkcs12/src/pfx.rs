use core::cmp::Ordering;

use der::{Enumerated, Sequence, ValueOrd};

use crate::{content_info::ContentInfo, mac_data::MacData};

/// just the version v3
#[derive(Clone, Copy, Debug, Enumerated, Eq, PartialEq, PartialOrd, Ord)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Version {
    /// syntax version 3
    V3 = 3,
}

impl ValueOrd for Version {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        Ok(self.cmp(other))
    }
}

/// ```text
/// PFX ::= SEQUENCE {
///     version     INTEGER {v3(3)}(v3,...),
///     authSafe    ContentInfo,
///     macData     MacData OPTIONAL
/// }
///
/// ```
#[derive(Debug, Sequence)]
pub struct Pfx<'a> {
    /// the syntax version number.
    pub version: Version,

    /// the authenticated safe
    pub auth_safe: ContentInfo<'a>,

    /// the message digest info
    pub mac_data: MacData<'a>,
}
