//! KEMRecipientInfo-related types

use crate::{
    content_info::CmsVersion,
    enveloped_data::{EncryptedKey, RecipientIdentifier, UserKeyingMaterial},
};
use const_oid::ObjectIdentifier;
use der::{Sequence, asn1::OctetString};
use spki::AlgorithmIdentifierOwned;

/// From [RFC9629 Section 3]
/// ```text
///   id-ori OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
///     rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) 13 }
///
///   id-ori-kem OBJECT IDENTIFIER ::= { id-ori 3 }
/// ```
/// [RFC9629 Section 3]: https://datatracker.ietf.org/doc/html/rfc9629#section-3
pub const ID_ORI_KEM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.13.3");

/// The `KEMRecipientInfo` type is defined in [RFC9629 Section 3]
/// ```text
///   KEMRecipientInfo ::= SEQUENCE {
///     version CMSVersion,  -- always set to 0
///     rid RecipientIdentifier,
///     kem KEMAlgorithmIdentifier,
///     kemct OCTET STRING,
///     kdf KeyDerivationAlgorithmIdentifier,
///     kekLength INTEGER (1..65535),
///     ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL,
///     wrap KeyEncryptionAlgorithmIdentifier,
///     encryptedKey EncryptedKey }
/// ```
/// [RFC9629 Section 3]: https://datatracker.ietf.org/doc/html/rfc9629#section-3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct KemRecipientInfo {
    pub version: CmsVersion,
    pub rid: RecipientIdentifier,
    pub kem: AlgorithmIdentifierOwned,
    pub kem_ct: OctetString,
    pub kdf: AlgorithmIdentifierOwned,
    pub kek_length: u16,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub ukm: Option<UserKeyingMaterial>,
    pub wrap: AlgorithmIdentifierOwned,
    pub encrypted_key: EncryptedKey,
}

/// The `CMSORIforKEMOtherInfo` type is defined in [RFC9629 Section 5]
/// ```text
///       CMSORIforKEMOtherInfo ::= SEQUENCE {
///         wrap KeyEncryptionAlgorithmIdentifier,
///         kekLength INTEGER (1..65535),
///         ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL }
/// ```
/// [RFC9629 Section 5]: https://datatracker.ietf.org/doc/html/rfc9629#section-5
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CmsOriForKemOtherInfo {
    pub wrap: AlgorithmIdentifierOwned,
    pub kek_length: u16,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub ukm: Option<UserKeyingMaterial>,
}
