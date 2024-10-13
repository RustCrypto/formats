//! Key Agreement Recipient Info (Kari) Builder
//!
//! This module contains the building logic for Key Agreement Recipient Info.
//! It partially implements [RFC 5753].
//!
//! [RFC 5753]: https://datatracker.ietf.org/doc/html/rfc5753
//!

use super::{utils::HashDigest, AlgorithmIdentifierOwned, UserKeyingMaterial};
use const_oid::ObjectIdentifier;
use der::{asn1::OctetString, Any, Sequence};
use elliptic_curve::{CurveArithmetic, PublicKey};

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
/// As per [RFC 5753 Section 8]:
/// ```text
/// Implementations that support EnvelopedData with the ephemeral-static
/// ECDH standard primitive:
///
/// - MUST support the dhSinglePass-stdDH-sha256kdf-scheme key
///    agreement algorithm, the id-aes128-wrap key wrap algorithm, and
///    the id-aes128-cbc content encryption algorithm; and
/// - MAY support the dhSinglePass-stdDH-sha1kdf-scheme, dhSinglePass-
///    stdDH-sha224kdf-scheme, dhSinglePass-stdDH-sha384kdf-scheme, and
///    dhSinglePass-stdDH-sha512kdf-scheme key agreement algorithms;
///    the id-alg-CMS3DESwrap, id-aes192-wrap, and id-aes256-wrap key
///    wrap algorithms; and the des-ede3-cbc, id-aes192-cbc, and id-
///    aes256-cbc content encryption algorithms; other algorithms MAY
///    also be supported.
/// ```
///
/// As such the following are currently supported:
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
    fn oid(&self) -> ObjectIdentifier {
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
impl From<&KeyAgreementAlgorithm> for HashDigest {
    fn from(ka_algo: &KeyAgreementAlgorithm) -> Self {
        match ka_algo {
            KeyAgreementAlgorithm::SinglePassStdDhSha224Kdf => Self::Sha224,
            KeyAgreementAlgorithm::SinglePassStdDhSha256Kdf => Self::Sha256,
            KeyAgreementAlgorithm::SinglePassStdDhSha384Kdf => Self::Sha384,
            KeyAgreementAlgorithm::SinglePassStdDhSha512Kdf => Self::Sha512,
        }
    }
}

/// Contains information required to encrypt the content encryption key with a method based on ECC key agreement
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcKeyEncryptionInfo<C>
where
    C: CurveArithmetic,
{
    /// Encrypt key with EC
    Ec(PublicKey<C>),
}
impl<C> EcKeyEncryptionInfo<C>
where
    C: CurveArithmetic + const_oid::AssociatedOid,
{
    /// Returns the OID associated with the curve used in this `EcKeyEncryptionInfo`.
    pub fn get_oid(&self) -> ObjectIdentifier {
        C::OID
    }
}
impl<C> From<&EcKeyEncryptionInfo<C>> for AlgorithmIdentifierOwned
where
    C: CurveArithmetic + const_oid::AssociatedOid,
{
    fn from(ec_key_encryption_info: &EcKeyEncryptionInfo<C>) -> Self {
        let parameters = Some(Any::from(&ec_key_encryption_info.get_oid()));
        AlgorithmIdentifierOwned {
            oid: elliptic_curve::ALGORITHM_OID, // id-ecPublicKey
            parameters,                         // Curve OID
        }
    }
}
