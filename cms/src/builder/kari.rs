//! Key Agreement Recipient Info (Kari) Builder
//!
//! This module contains the building logic for Key Agreement Recipient Info.
//! It partially implements [RFC 5753].
//!
//! [RFC 5753]: https://datatracker.ietf.org/doc/html/rfc5753
//!

// Super imports
use super::{
    utils::{try_ansi_x963_kdf, HashDigest, KeyWrapper},
    AlgorithmIdentifierOwned, CryptoRngCore, KeyWrapAlgorithm, RecipientInfoBuilder,
    RecipientInfoType, Result, UserKeyingMaterial,
};

// Crate imports
#[cfg(doc)]
use crate::enveloped_data::EnvelopedData;
use crate::{
    content_info::CmsVersion,
    enveloped_data::{
        EncryptedKey, KeyAgreeRecipientIdentifier, KeyAgreeRecipientInfo,
        OriginatorIdentifierOrKey, OriginatorPublicKey, RecipientEncryptedKey, RecipientInfo,
    },
};

// Internal imports
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::{
    asn1::{BitString, OctetString},
    Any, Decode, Encode, Sequence,
};

// Alloc imports
use alloc::{vec, vec::Vec};

// RustCrypto imports
use elliptic_curve::{
    ecdh::EphemeralSecret,
    point::PointCompression,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey,
};

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
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy)]
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
    C: CurveArithmetic + AssociatedOid,
{
    /// Returns the OID associated with the curve used.
    pub fn get_oid(&self) -> ObjectIdentifier {
        C::OID
    }
}
impl<C> From<&EcKeyEncryptionInfo<C>> for AlgorithmIdentifierOwned
where
    C: CurveArithmetic + AssociatedOid,
{
    fn from(ec_key_encryption_info: &EcKeyEncryptionInfo<C>) -> Self {
        let parameters = Some(Any::from(&ec_key_encryption_info.get_oid()));
        AlgorithmIdentifierOwned {
            oid: elliptic_curve::ALGORITHM_OID, // id-ecPublicKey
            parameters,                         // Curve OID
        }
    }
}

/// Builds a `KeyAgreeRecipientInfo` according to RFC 5652 § 6.
/// This type uses key agreement:  the recipient's public key and the sender's
/// private key are used to generate a pairwise symmetric key, then
/// the content-encryption key is encrypted in the pairwise symmetric key.
pub struct KeyAgreeRecipientInfoBuilder<'a, R, C>
where
    R: CryptoRngCore,
    C: CurveArithmetic,
{
    /// Optional information which helps generating different keys every time.
    pub ukm: Option<UserKeyingMaterial>,
    /// Encryption algorithm to be used for key encryption
    pub rid: KeyAgreeRecipientIdentifier,
    /// Recipient key info
    pub eckey_encryption_info: EcKeyEncryptionInfo<C>,
    /// Content encryption algorithm
    pub key_agreement_algorithm: KeyAgreementAlgorithm,
    /// Content encryption algorithm
    pub key_wrap_algorithm: KeyWrapAlgorithm,
    /// Rng
    rng: &'a mut R,
}

impl<'a, R, C> KeyAgreeRecipientInfoBuilder<'a, R, C>
where
    R: CryptoRngCore,
    C: CurveArithmetic,
{
    /// Creates a `KeyAgreeRecipientInfoBuilder`
    pub fn new(
        ukm: Option<UserKeyingMaterial>,
        rid: KeyAgreeRecipientIdentifier,
        eckey_encryption_info: EcKeyEncryptionInfo<C>,
        key_agreement_algorithm: KeyAgreementAlgorithm,
        key_wrap_algorithm: KeyWrapAlgorithm,
        rng: &'a mut R,
    ) -> Result<KeyAgreeRecipientInfoBuilder<'a, R, C>> {
        Ok(KeyAgreeRecipientInfoBuilder {
            ukm,
            eckey_encryption_info,
            key_agreement_algorithm,
            key_wrap_algorithm,
            rid,
            rng,
        })
    }
}
impl<'a, R, C> RecipientInfoBuilder for KeyAgreeRecipientInfoBuilder<'a, R, C>
where
    R: CryptoRngCore,
    C: CurveArithmetic + AssociatedOid + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    /// Returns the RecipientInfoType
    fn recipient_info_type(&self) -> RecipientInfoType {
        RecipientInfoType::Kari
    }

    /// Returns the `CMSVersion` for this `RecipientInfo`
    fn recipient_info_version(&self) -> CmsVersion {
        CmsVersion::V3
    }

    /// Build a `KeyAgreeRecipientInfo` as per [RFC 5652 Section 6.2.2] and [RFC 5753 Section 3].
    ///
    /// For now only [EnvelopedData] using `(ephemeral-static) ECDH` is supported - [RFC 5753 Section 3.1.1]
    ///
    /// We follow the flow outlined in - [RFC 5753 Section 3.1.2]:
    ///
    /// Todo:
    /// - Add support for `'Co-factor' ECDH` - see [RFC 5753 Section 3.1.1]
    /// - Add support for `1-Pass ECMQV` - see [RFC 5753 Section 3.2.1]
    ///
    /// [RFC 5753 Section 3]: https://datatracker.ietf.org/doc/html/rfc5753#section-3
    /// [RFC 5652 Section 6.2.2]: https://datatracker.ietf.org/doc/html/rfc5652#section-6.2.2
    /// [RFC 5753 Section 3.1.1]: https://datatracker.ietf.org/doc/html/rfc5753#section-3.1.1
    /// [RFC 5753 Section 3.1.2]: https://datatracker.ietf.org/doc/html/rfc5753#section-3.1.2
    /// [RFC 5753 Section 3.2.1]: https://datatracker.ietf.org/doc/html/rfc5753#section-3.2.1
    fn build(&mut self, content_encryption_key: &[u8]) -> Result<RecipientInfo> {
        // Encrypt key
        let (
            encrypted_key,
            ephemeral_pubkey_encoded_point,
            originator_algorithm_identifier,
            key_encryption_algorithm_identifier,
        ) = match self.eckey_encryption_info {
            EcKeyEncryptionInfo::Ec(recipient_public_key) => {
                // Generate ephemeral key using ecdh
                let ephemeral_secret = EphemeralSecret::random(self.rng);
                let ephemeral_public_key_encoded_point =
                    ephemeral_secret.public_key().to_encoded_point(false);

                // Compute a shared secret with recipient public key. Non-uniformly random, but will be used as input for KDF later.
                let non_uniformly_random_shared_secret =
                    ephemeral_secret.diffie_hellman(&recipient_public_key);
                let non_uniformly_random_shared_secret_bytes =
                    non_uniformly_random_shared_secret.raw_secret_bytes();

                // Generate shared info for KDF
                // As per https://datatracker.ietf.org/doc/html/rfc5753#section-7.2"
                // ```
                // keyInfo contains the object identifier of the key-encryption
                // algorithm (used to wrap the CEK) and associated parameters.  In
                // this specification, 3DES wrap has NULL parameters while the AES
                // wraps have absent parameters.
                // ```
                let key_wrap_algorithm_identifier: AlgorithmIdentifierOwned =
                    self.key_wrap_algorithm.into();
                let key_wrap_algorithm_der = key_wrap_algorithm_identifier.to_der()?;

                // As per https://datatracker.ietf.org/doc/html/rfc5753#section-7.2"
                // ```
                // entityUInfo optionally contains additional keying material
                // supplied by the sending agent.  When used with ECDH and CMS, the
                // entityUInfo field contains the octet string ukm.  When used with
                // ECMQV and CMS, the entityUInfo contains the octet string addedukm
                // (encoded in MQVuserKeyingMaterial).
                // ```
                let entity_u_info = self.ukm.clone();

                // As per https://datatracker.ietf.org/doc/html/rfc5753#section-7.2"
                // ```
                // suppPubInfo contains the length of the generated KEK, in bits,
                // represented as a 32-bit number, as in [CMS-DH] and [CMS-AES].
                // (For example, for AES-256 it would be 00 00 01 00.)
                // ```
                let key_wrap_algo_keysize_bits_in_be_bytes: [u8; 4] =
                    self.key_wrap_algorithm.key_size_in_bits().to_be_bytes();

                let shared_info = EccCmsSharedInfo {
                    key_info: key_wrap_algorithm_identifier,
                    entity_u_info,
                    supp_pub_info: OctetString::new(key_wrap_algo_keysize_bits_in_be_bytes)?,
                };
                let shared_info_der = shared_info.to_der()?;

                // Init a wrapping key (KEK) based on KeyWrapAlgorithm and on CEK (i.e. key to wrap) size
                let mut key_wrapper =
                    KeyWrapper::try_new(&self.key_wrap_algorithm, content_encryption_key.len())?;

                // Derive the Key Encryption Key (KEK) from Shared Secret using ANSI X9.63 KDF
                let digest = HashDigest::from(&self.key_agreement_algorithm);
                try_ansi_x963_kdf(
                    non_uniformly_random_shared_secret_bytes.as_slice(),
                    &shared_info_der,
                    &mut key_wrapper,
                    &digest,
                )?;

                // Wrap the Content Encryption Key (CEK) with the KEK
                key_wrapper.try_wrap(content_encryption_key)?;

                // Return data
                (
                    Vec::from(key_wrapper),
                    ephemeral_public_key_encoded_point,
                    AlgorithmIdentifierOwned::from(&self.eckey_encryption_info),
                    AlgorithmIdentifierOwned {
                        oid: self.key_agreement_algorithm.oid(),
                        parameters: Some(Any::from_der(&key_wrap_algorithm_der)?),
                    },
                )
            }
        };

        // Build RecipientInfo
        Ok(RecipientInfo::Kari(KeyAgreeRecipientInfo {
            originator: OriginatorIdentifierOrKey::OriginatorKey(OriginatorPublicKey {
                algorithm: originator_algorithm_identifier,
                public_key: BitString::from_bytes(ephemeral_pubkey_encoded_point.as_bytes())?,
            }),
            version: self.recipient_info_version(),
            ukm: self.ukm.clone(),
            key_enc_alg: key_encryption_algorithm_identifier,
            recipient_enc_keys: vec![RecipientEncryptedKey {
                rid: self.rid.clone(),
                enc_key: EncryptedKey::new(encrypted_key)?,
            }],
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::eprintln;

    use super::*;
    use p256::{pkcs8::DecodePublicKey, NistP256, PublicKey};

    /// Generate a test P256 EcKeyEncryptionInfo
    fn get_test_ec_key_info() -> EcKeyEncryptionInfo<NistP256> {
        // Public key der bytes:
        // ```rust
        // let public_key_der_bytes = include_bytes!("../../tests/examples/p256-pub.der");
        // ```
        // OR
        // ```bash
        // od -An -vtu1 cms/tests/examples/p256-pub.der | tr -s ' ' | tr -d '\n' | sed 's/ /, /g' | sed 's/^, //' |xargs
        // ```
        let public_key_der_bytes: &[u8] = &[
            48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7,
            3, 66, 0, 4, 28, 172, 255, 181, 95, 47, 44, 239, 216, 157, 137, 235, 55, 75, 38, 129,
            21, 36, 82, 128, 45, 238, 160, 153, 22, 6, 129, 55, 216, 57, 207, 127, 196, 129, 164,
            68, 146, 48, 77, 126, 246, 106, 193, 23, 190, 254, 131, 168, 208, 143, 21, 95, 43, 82,
            249, 246, 24, 221, 68, 112, 41, 4, 142, 15,
        ];
        let p256_public_key = PublicKey::from_public_key_der(public_key_der_bytes)
            .map_err(|e| eprintln!("{}", e))
            .expect("Getting PublicKey failed");
        EcKeyEncryptionInfo::Ec(p256_public_key)
    }

    #[test]
    fn test_keyagreementalgorithm_oid() {
        assert_eq!(
            KeyAgreementAlgorithm::SinglePassStdDhSha224Kdf.oid(),
            const_oid::db::rfc5753::DH_SINGLE_PASS_STD_DH_SHA_224_KDF_SCHEME
        );
        assert_eq!(
            KeyAgreementAlgorithm::SinglePassStdDhSha256Kdf.oid(),
            const_oid::db::rfc5753::DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME
        );
        assert_eq!(
            KeyAgreementAlgorithm::SinglePassStdDhSha384Kdf.oid(),
            const_oid::db::rfc5753::DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME
        );
        assert_eq!(
            KeyAgreementAlgorithm::SinglePassStdDhSha512Kdf.oid(),
            const_oid::db::rfc5753::DH_SINGLE_PASS_STD_DH_SHA_512_KDF_SCHEME
        );
    }

    #[test]
    fn test_from_keyagreementalgorithm_for_hashdigest() {
        assert_eq!(
            HashDigest::from(&KeyAgreementAlgorithm::SinglePassStdDhSha224Kdf),
            HashDigest::Sha224
        );
        assert_eq!(
            HashDigest::from(&KeyAgreementAlgorithm::SinglePassStdDhSha256Kdf),
            HashDigest::Sha256
        );
        assert_eq!(
            HashDigest::from(&KeyAgreementAlgorithm::SinglePassStdDhSha384Kdf),
            HashDigest::Sha384
        );
        assert_eq!(
            HashDigest::from(&KeyAgreementAlgorithm::SinglePassStdDhSha512Kdf),
            HashDigest::Sha512
        );
    }

    #[test]
    fn test_eckeyencryptioninfo_get_oid() {
        let ec_key_encryption_info = get_test_ec_key_info();
        assert_eq!(
            ec_key_encryption_info.get_oid(),
            ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7")
        );
    }

    #[test]
    fn test_algorithmidentifierowned_from_eckeyencryptioninfo() {
        let ec_key_encryption_info = get_test_ec_key_info();

        assert_eq!(
            AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
                parameters: Some(ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7").into()),
            },
            AlgorithmIdentifierOwned::from(&ec_key_encryption_info)
        )
    }
}
