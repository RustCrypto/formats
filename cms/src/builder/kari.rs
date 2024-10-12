//! Key Agreement Recipient Info (Kari) Builder
//!
//! This module contains the building logic for Key Agreement Recipient Info.
//! It partially implements [RFC 5753].
//!
//! [RFC 5753]: https://datatracker.ietf.org/doc/html/rfc5753
//!
//!

use super::{AlgorithmIdentifierOwned, UserKeyingMaterial};

use const_oid::ObjectIdentifier;
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

/// Represents supported key agreement algorithm for ECC - as defined in [RFC 5753 Section 7.1.4].
///
/// As per [RFC 5753 Section 8], the following are supported:
/// - dhSinglePass-stdDH-sha224kdf-scheme
/// - dhSinglePass-stdDH-sha256kdf-scheme
/// - dhSinglePass-stdDH-sha384kdf-scheme
/// - dhSinglePass-stdDH-sha512kdf-scheme
///
/// [RFC 5753 Section 7.1.4]: https://datatracker.ietf.org/doc/html/rfc5753#section-7.1.4
/// [RFC 5753 Section 8]: https://datatracker.ietf.org/doc/html/rfc5753#section-8

pub enum KeyAgreementAlgorithm {
    /// dhSinglePass-stdDH-sha224kdf-scheme
    SinglePassStdDhSha224Kdf,
    /// dhSinglePass-stdDH-sha256kdf-scheme
    SinglePassStdDhSha256Kdf,
    /// dhSinglePass-stdDH-sha384kdf-scheme
    SinglePassStdDhSha384Kdf,
    /// dhSinglePass-stdDH-sh512df-scheme
    SinglePassStdDhSha512Kdf,
}
impl KeyAgreementAlgorithm {
    /// Return the OID of the algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            Self::SinglePassStdDhSha224Kdf => {
                const_oid::db::rfc5753::DH_SINGLE_PASS_STD_DH_SHA_224_KDF_SCHEME
            }
            Self::SinglePassStdDhSha256Kdf => {
                const_oid::db::rfc5753::DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME
            }
            Self::SinglePassStdDhSha384Kdf => {
                const_oid::db::rfc5753::DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME
            }
            Self::SinglePassStdDhSha512Kdf => {
                const_oid::db::rfc5753::DH_SINGLE_PASS_STD_DH_SHA_512_KDF_SCHEME
            }
        }
    }
}
