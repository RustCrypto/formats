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
use der::{asn1::OctetString, Any, Sequence};

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
///  Implementations that support EnvelopedData with the ephemeral-static
///  ECDH standard primitive:
///
///  - MUST support the dhSinglePass-stdDH-sha256kdf-scheme key
///    agreement algorithm, the id-aes128-wrap key wrap algorithm, and
///    the id-aes128-cbc content encryption algorithm; and
/// - MAY support the dhSinglePass-stdDH-sha1kdf-scheme, dhSinglePass-
///     stdDH-sha224kdf-scheme, dhSinglePass-stdDH-sha384kdf-scheme, and
///     dhSinglePass-stdDH-sha512kdf-scheme key agreement algorithms;
///     the id-alg-CMS3DESwrap, id-aes192-wrap, and id-aes256-wrap key
///     wrap algorithms; and the des-ede3-cbc, id-aes192-cbc, and id-
///     aes256-cbc content encryption algorithms; other algorithms MAY
///     also be supported.
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

/// Represents supported key wrap algorithm for ECC - as defined in [RFC 5753 Section 7.1.5].
///
/// As per [RFC 5753 Section 8]:
/// ```text
///  Implementations that support EnvelopedData with the ephemeral-static
///  ECDH standard primitive:
///
///  - MUST support the dhSinglePass-stdDH-sha256kdf-scheme key
///    agreement algorithm, the id-aes128-wrap key wrap algorithm, and
///    the id-aes128-cbc content encryption algorithm; and
/// - MAY support the dhSinglePass-stdDH-sha1kdf-scheme, dhSinglePass-
///     stdDH-sha224kdf-scheme, dhSinglePass-stdDH-sha384kdf-scheme, and
///     dhSinglePass-stdDH-sha512kdf-scheme key agreement algorithms;
///     the id-alg-CMS3DESwrap, id-aes192-wrap, and id-aes256-wrap key
///     wrap algorithms; and the des-ede3-cbc, id-aes192-cbc, and id-
///     aes256-cbc content encryption algorithms; other algorithms MAY
///     also be supported.
/// ```
///
/// As such the following algorithm are currently supported
/// - id-aes128-wrap
/// - id-aes192-wrap - (OPTIONAL)
/// - id-aes256-wrap - (OPTIONAL)
///
/// [RFC 5753 Section 8]: https://datatracker.ietf.org/doc/html/rfc5753#section-8
/// [RFC 5753 Section 7.1.5]: https://datatracker.ietf.org/doc/html/rfc5753#section-7.1.5
#[derive(Copy, Clone)]
pub enum KeyWrapAlgorithm {
    /// id-aes128-wrap
    Aes128,
    /// id-aes192-wrap
    Aes192,
    /// id-aes256-wrap
    Aes256,
}
impl KeyWrapAlgorithm {
    /// Return the Object Identifier (OID) of the algorithm.
    ///
    /// OID are defined in [RFC 3565 Section 2.3.2]
    ///
    /// [RFC 3565 Section 2.3.2]:
    /// ```text
    /// NIST has assigned the following OIDs to define the AES key wrap
    /// algorithm.
    ///
    ///     id-aes128-wrap OBJECT IDENTIFIER ::= { aes 5 }
    ///     id-aes192-wrap OBJECT IDENTIFIER ::= { aes 25 }
    ///     id-aes256-wrap OBJECT IDENTIFIER ::= { aes 45 }
    ///
    /// In all cases the parameters field MUST be absent.
    /// ```
    ///
    /// [RFC 3565 Section 2.3.2]: https://datatracker.ietf.org/doc/html/rfc3565#section-2.3.2
    fn oid(&self) -> ObjectIdentifier {
        match self {
            Self::Aes128 => const_oid::db::rfc5911::ID_AES_128_WRAP,
            Self::Aes192 => const_oid::db::rfc5911::ID_AES_192_WRAP,
            Self::Aes256 => const_oid::db::rfc5911::ID_AES_256_WRAP,
        }
    }

    /// Return parameters of the algorithm to be used in the context of `AlgorithmIdentifierOwned`.
    ///
    /// It should be absent as defined in [RFC 3565 Section 2.3.2] and per usage in [RFC 5753 Section 7.2].
    ///
    /// [RFC 3565 Section 2.3.2]: https://datatracker.ietf.org/doc/html/rfc3565#section-2.3.2
    /// [RFC 5753 Section 7.2]: https://datatracker.ietf.org/doc/html/rfc5753#section-7.2
    fn parameters(&self) -> Option<Any> {
        match self {
            Self::Aes128 => None,
            Self::Aes192 => None,
            Self::Aes256 => None,
        }
    }

    /// Return key size of the algorithm in number of bits
    pub fn key_size_in_bits(&self) -> u32 {
        match self {
            Self::Aes128 => 128,
            Self::Aes192 => 192,
            Self::Aes256 => 256,
        }
    }
}
impl From<KeyWrapAlgorithm> for AlgorithmIdentifierOwned {
    /// Convert a `KeyWrapAlgorithm` to the corresponding `AlgorithmIdentifierOwned`.
    ///
    /// Conversion is done as defined in [RFC 3565 Section 2.3.2] and according to [RFC 5753 Section 7.2]:
    ///
    /// [RFC 3565 Section 2.3.2]
    /// ```text
    /// keyInfo contains the object identifier of the key-encryption
    /// algorithm (used to wrap the CEK) and associated parameters.  In
    /// this specification, 3DES wrap has NULL parameters while the AES
    /// wraps have absent parameters.
    /// ```
    ///
    /// [RFC 5753 Section 73.2]
    /// ```text
    /// keyInfo contains the object identifier of the key-encryption
    /// algorithm (used to wrap the CEK) and associated parameters.  In
    /// this specification, 3DES wrap has NULL parameters while the AES
    /// wraps have absent parameters.
    /// ```
    ///
    /// [RFC 3565 Section 2.3.2]: https://datatracker.ietf.org/doc/html/rfc3565#section-2.3.2
    /// [RFC 5753 Section 7.2]: https://datatracker.ietf.org/doc/html/rfc5753#section-7.2
    fn from(kw_algo: KeyWrapAlgorithm) -> Self {
        Self {
            oid: kw_algo.oid(),
            parameters: kw_algo.parameters(),
        }
    }
}
