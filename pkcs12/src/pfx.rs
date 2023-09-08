//! PFX-related types

use core::cmp::Ordering;

use der::{Enumerated, Sequence, ValueOrd};

use crate::mac_data::MacData;
use cms::content_info::ContentInfo;

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

/// The `PFX` type is defined in [RFC 7292 Section 4].
///
/// ```text
/// PFX ::= SEQUENCE {
///     version     INTEGER {v3(3)}(v3,...),
///     authSafe    ContentInfo,
///     macData     MacData OPTIONAL
/// }
///
/// ```
///
/// [RFC 7292 Section 4]: https://www.rfc-editor.org/rfc/rfc7292#section-4
#[derive(Debug, Sequence)]
pub struct Pfx {
    /// the syntax version number.
    pub version: Version,

    /// the authenticated safe
    pub auth_safe: ContentInfo,

    /// the message digest info
    pub mac_data: Option<MacData>,
}
