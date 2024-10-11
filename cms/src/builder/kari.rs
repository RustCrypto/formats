//! Key Agreement Recipient Info (Kari) Builder
//!
//! This module contains the building logic for Key Agreement Recipient Info.
//! It partially implements [RFC 5753].
//!
//! [RFC 5753]: https://datatracker.ietf.org/doc/html/rfc5753
//!
//!

use super::AlgorithmIdentifierOwned;
use super::UserKeyingMaterial;

use der::{asn1::OctetString, Sequence};

/// The `EccCmsSharedInfo` type is defined in [RFC 5753 Section 7.2].
///
/// ```text
///   EccCmsSharedInfo ::= SEQUENCE {
///       keyInfo         AlgorithmIdentifier,
///       entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
///       suppPubInfo [2] EXPLICIT OCTET STRING  }
/// ```
///
/// [RFC 5753 Section 7.2]: https://www.rfc-editor.org/rfc/rfc5753#section-7.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EccCmsSharedInfo {
    /// Object identifier of the key-encryption algorithm
    pub key_info: AlgorithmIdentifierOwned,
    /// Additional keying material - optional
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub entity_u_info: Option<UserKeyingMaterial>,
    /// Length of the generated KEK, in bits, represented as a 32-bit number
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    pub supp_pub_info: OctetString,
}
