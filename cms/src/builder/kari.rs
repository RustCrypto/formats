//! Key Agreement Recipient Info (Kari) Builder
//!
//! This module contains the building logic for Key Agreement Recipient Info.
//! It partially implements [RFC 5753].
//!
//! [RFC 5753]: https://www.rfc-editor.org/info/rfc5753
//!

// Super imports
use super::{
    AlgorithmIdentifierOwned, CryptoRng, Error, RecipientInfoBuilder, RecipientInfoType, Result,
    UserKeyingMaterial, utils::kw::KeyWrapAlgorithm,
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
use const_oid::{AssociatedOid, DynAssociatedOid, ObjectIdentifier, db::rfc5753};
use der::{
    Any, Decode, Encode, Sequence,
    asn1::{BitString, OctetString},
};

// Core imports
use core::{fmt, marker::PhantomData};

// Alloc imports
use alloc::{string::String, vec, vec::Vec};

// RustCrypto imports
use ansi_x963_kdf::AnsiX963Kdf;
use digest::{Digest, FixedOutputReset};
use elliptic_curve::{
    AffinePoint, CurveArithmetic, FieldBytesSize, Generate, PublicKey,
    ecdh::EphemeralSecret,
    point::PointCompression,
    sec1::{FromSec1Point, ModulusSize, ToSec1Point},
};
use kdf::Kdf;
use x509_cert::certificate::{Profile, Rfc5280};
use zeroize::Zeroizing;

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
/// For [`EcdhKeyAgreement`], a key agreement algorithm derives the key-encryption key from the
/// ECDH shared secret, with the DER-encoded [`EccCmsSharedInfo`] ([RFC 5753 Section 7.2]) as the
/// KDF's non-secret input, and its OID identifies the scheme in the `KeyAgreeRecipientInfo`'s
/// `keyEncryptionAlgorithm`. Any [`Kdf`] with a [`DynAssociatedOid`] is one. The OID names the
/// whole scheme, including the ECDH primitive; the standard and cofactor primitives agree for
/// curves of cofactor 1, such as the NIST P-curves.
///
/// [RFC 5753 Section 7.1.4]: https://www.rfc-editor.org/info/rfc5753#section-7.1.4
/// [RFC 5753 Section 7.2]: https://www.rfc-editor.org/info/rfc5753#section-7.2
/// [RFC 5753 Section 8]: https://www.rfc-editor.org/info/rfc5753#section-8
pub trait KeyAgreementAlgorithm: Kdf + DynAssociatedOid {}

impl<T: Kdf + DynAssociatedOid> KeyAgreementAlgorithm for T {}

/// Support for EnvelopedData with the ephemeral-static ECDH standard primitive, deriving the
/// key-encryption key with the ANSI X9.63 KDF over the digest `D`.
pub struct DhSinglePassStdDhKdf<D> {
    digest: PhantomData<D>,
}

impl<D> DhSinglePassStdDhKdf<D> {
    /// Creates the key agreement algorithm.
    pub fn new() -> Self {
        Self {
            digest: PhantomData,
        }
    }
}

impl<D> Default for DhSinglePassStdDhKdf<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D> Clone for DhSinglePassStdDhKdf<D> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<D> fmt::Debug for DhSinglePassStdDhKdf<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DhSinglePassStdDhKdf").finish()
    }
}

impl<D> Kdf for DhSinglePassStdDhKdf<D>
where
    D: Digest + FixedOutputReset,
{
    fn derive_key(&self, secret: &[u8], non_secret: &[u8], out: &mut [u8]) -> kdf::Result<()> {
        AnsiX963Kdf::<D>::default().derive_key(secret, non_secret, out)
    }
}

impl AssociatedOid for DhSinglePassStdDhKdf<sha2::Sha224> {
    const OID: ObjectIdentifier = rfc5753::DH_SINGLE_PASS_STD_DH_SHA_224_KDF_SCHEME;
}

impl AssociatedOid for DhSinglePassStdDhKdf<sha2::Sha256> {
    const OID: ObjectIdentifier = rfc5753::DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME;
}

impl AssociatedOid for DhSinglePassStdDhKdf<sha2::Sha384> {
    const OID: ObjectIdentifier = rfc5753::DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME;
}

impl AssociatedOid for DhSinglePassStdDhKdf<sha2::Sha512> {
    const OID: ObjectIdentifier = rfc5753::DH_SINGLE_PASS_STD_DH_SHA_512_KDF_SCHEME;
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
impl<C> From<EcKeyEncryptionInfo<C>> for AlgorithmIdentifierOwned
where
    C: CurveArithmetic + AssociatedOid,
{
    fn from(ec_key_encryption_info: EcKeyEncryptionInfo<C>) -> Self {
        let parameters = Some(Any::from(&ec_key_encryption_info.get_oid()));
        AlgorithmIdentifierOwned {
            oid: elliptic_curve::ALGORITHM_OID, // id-ecPublicKey
            parameters,                         // Curve OID
        }
    }
}

/// The result of a key agreement.
pub struct KeyAgreementOutput {
    /// The originator's ephemeral public key, for the `KeyAgreeRecipientInfo`'s `originator`.
    pub originator_key: OriginatorPublicKey,
    /// The key-encryption key, for the key wrap algorithm to wrap the content-encryption key with.
    pub key_encryption_key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for KeyAgreementOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyAgreementOutput")
            .field("originator_key", &self.originator_key)
            .finish_non_exhaustive()
    }
}

/// Performs a key agreement scheme with a recipient's public key, as in
/// [RFC 5753 Section 3.1.2]: generates the originator's ephemeral key pair, computes the shared
/// secret with the recipient's public key and derives the key-encryption key from it.
///
/// [`DynAssociatedOid::oid`] identifies the scheme (e.g. dhSinglePass-stdDH-sha256kdf-scheme) for
/// the `KeyAgreeRecipientInfo`'s `keyEncryptionAlgorithm`. [`EcdhKeyAgreement`] implements it with
/// RustCrypto ECDH and a [`KeyAgreementAlgorithm`]. Implement it to perform the key agreement
/// elsewhere than in process, e.g. in a FIPS 140-3 validated module, where the shared secret need
/// not leave the module.
///
/// [RFC 5753 Section 3.1.2]: https://www.rfc-editor.org/info/rfc5753#section-3.1.2
pub trait KeyAgreement<R: ?Sized>: DynAssociatedOid {
    /// Generates an ephemeral key pair, agrees on a shared secret with the recipient and derives a
    /// key-encryption key of `kek_size` bytes from it, with `shared_info`, the DER-encoded
    /// [`EccCmsSharedInfo`], as the KDF's non-secret input.
    fn agree(&self, shared_info: &[u8], kek_size: usize, rng: &mut R)
    -> Result<KeyAgreementOutput>;
}

/// Ephemeral-static ECDH with RustCrypto, deriving the key-encryption key with the key agreement
/// algorithm `KA` (e.g. [`DhSinglePassStdDhKdf`]), which also identifies the scheme.
#[derive(Clone, Debug)]
pub struct EcdhKeyAgreement<C, KA>
where
    C: CurveArithmetic,
{
    recipient: EcKeyEncryptionInfo<C>,
    key_agreement_algorithm: KA,
}

impl<C, KA> EcdhKeyAgreement<C, KA>
where
    C: CurveArithmetic,
{
    /// Creates an ECDH key agreement with the recipient's public key.
    pub fn new(recipient: EcKeyEncryptionInfo<C>, key_agreement_algorithm: KA) -> Self {
        Self {
            recipient,
            key_agreement_algorithm,
        }
    }
}

impl<C, KA> DynAssociatedOid for EcdhKeyAgreement<C, KA>
where
    C: CurveArithmetic,
    KA: KeyAgreementAlgorithm,
{
    fn oid(&self) -> ObjectIdentifier {
        self.key_agreement_algorithm.oid()
    }
}

impl<C, KA, R> KeyAgreement<R> for EcdhKeyAgreement<C, KA>
where
    R: CryptoRng + ?Sized,
    C: CurveArithmetic + AssociatedOid + PointCompression,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
    KA: KeyAgreementAlgorithm,
{
    fn agree(
        &self,
        shared_info: &[u8],
        kek_size: usize,
        rng: &mut R,
    ) -> Result<KeyAgreementOutput> {
        match &self.recipient {
            EcKeyEncryptionInfo::Ec(recipient_public_key) => {
                let ephemeral_secret = EphemeralSecret::<C>::generate_from_rng(rng);
                let ephemeral_public_key = ephemeral_secret.public_key().to_sec1_point(false);
                // Non-uniformly random: the KDF takes it as input.
                let shared_secret = ephemeral_secret.diffie_hellman(recipient_public_key);
                let mut key_encryption_key = Zeroizing::new(vec![0u8; kek_size]);
                self.key_agreement_algorithm
                    .derive_key(
                        shared_secret.raw_secret_bytes(),
                        shared_info,
                        &mut key_encryption_key,
                    )
                    .map_err(|_| {
                        Error::Builder(String::from("could not derive the key-encryption key"))
                    })?;
                Ok(KeyAgreementOutput {
                    originator_key: OriginatorPublicKey {
                        algorithm: self.recipient.into(),
                        public_key: BitString::from_bytes(ephemeral_public_key.as_bytes())?,
                    },
                    key_encryption_key,
                })
            }
        }
    }
}

/// Builds a `KeyAgreeRecipientInfo` according to RFC 5652 § 6.
/// This type uses key agreement:  the recipient's public key and the sender's
/// private key are used to generate a pairwise symmetric key, then
/// the content-encryption key is encrypted in the pairwise symmetric key.
///
/// The caller supplies the key agreement `A` (e.g. [`EcdhKeyAgreement`]), which derives the
/// key-encryption key, and the key wrap algorithm `KW` (e.g. [`AesKeyWrap`](super::AesKeyWrap)),
/// which wraps the content-encryption key with it.
pub struct KeyAgreeRecipientInfoBuilder<R: ?Sized, A, KW, P: Profile = Rfc5280> {
    /// Optional information which helps generating different keys every time.
    pub ukm: Option<UserKeyingMaterial>,
    /// Recipient identifier
    pub rid: KeyAgreeRecipientIdentifier<P>,
    /// Performs the key agreement with the recipient's public key
    pub key_agreement: A,
    /// Key wrap algorithm
    key_wrap_algorithm: KW,
    /// Rng
    _rng: PhantomData<R>,
}

impl<R: ?Sized, A, KW, P: Profile> KeyAgreeRecipientInfoBuilder<R, A, KW, P> {
    /// Creates a `KeyAgreeRecipientInfoBuilder`
    pub fn new(
        ukm: Option<UserKeyingMaterial>,
        rid: KeyAgreeRecipientIdentifier<P>,
        key_agreement: A,
        key_wrap_algorithm: KW,
    ) -> Result<Self> {
        Ok(KeyAgreeRecipientInfoBuilder {
            ukm,
            rid,
            key_agreement,
            key_wrap_algorithm,
            _rng: PhantomData,
        })
    }
}

impl<R: ?Sized, A, KW, P: Profile> RecipientInfoBuilder<P>
    for KeyAgreeRecipientInfoBuilder<R, A, KW, P>
where
    R: CryptoRng,
    A: KeyAgreement<R>,
    KW: KeyWrapAlgorithm,
{
    /// Associated Rng type
    type Rng = R;

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
    /// [RFC 5753 Section 3]: https://www.rfc-editor.org/info/rfc5753#section-3
    /// [RFC 5652 Section 6.2.2]: https://www.rfc-editor.org/info/rfc5652#section-6.2.2
    /// [RFC 5753 Section 3.1.1]: https://www.rfc-editor.org/info/rfc5753#section-3.1.1
    /// [RFC 5753 Section 3.1.2]: https://www.rfc-editor.org/info/rfc5753#section-3.1.2
    /// [RFC 5753 Section 3.2.1]: https://www.rfc-editor.org/info/rfc5753#section-3.2.1
    fn build_with_rng(
        &mut self,
        content_encryption_key: &[u8],
        rng: &mut Self::Rng,
    ) -> Result<RecipientInfo<P>> {
        // Generate shared info for KDF
        // As per https://www.rfc-editor.org/info/rfc5753#section-7.2"
        // ```
        // keyInfo contains the object identifier of the key-encryption
        // algorithm (used to wrap the CEK) and associated parameters.  In
        // this specification, 3DES wrap has NULL parameters while the AES
        // wraps have absent parameters.
        // ```
        let key_wrap_algorithm_identifier = self.key_wrap_algorithm.algorithm_identifier();
        let key_wrap_algorithm_der = key_wrap_algorithm_identifier.to_der()?;

        // As per https://www.rfc-editor.org/info/rfc5753#section-7.2"
        // ```
        // entityUInfo optionally contains additional keying material
        // supplied by the sending agent.  When used with ECDH and CMS, the
        // entityUInfo field contains the octet string ukm.  When used with
        // ECMQV and CMS, the entityUInfo contains the octet string addedukm
        // (encoded in MQVuserKeyingMaterial).
        // ```
        let entity_u_info = self.ukm.clone();

        // As per https://www.rfc-editor.org/info/rfc5753#section-7.2"
        // ```
        // suppPubInfo contains the length of the generated KEK, in bits,
        // represented as a 32-bit number, as in [CMS-DH] and [CMS-AES].
        // (For example, for AES-256 it would be 00 00 01 00.)
        // ```
        let kek_size = self.key_wrap_algorithm.kek_size();
        let kek_size_in_bits = u32::try_from(kek_size)
            .ok()
            .and_then(|size| size.checked_mul(8))
            .ok_or_else(|| Error::Builder(String::from("key-encryption key too large")))?;

        let shared_info = EccCmsSharedInfo {
            key_info: key_wrap_algorithm_identifier,
            entity_u_info,
            supp_pub_info: OctetString::new(kek_size_in_bits.to_be_bytes())?,
        };

        // Generate the ephemeral key, compute the shared secret with the recipient's public key and
        // derive the key-encryption key (KEK) from it
        let key_agreement_output =
            self.key_agreement
                .agree(&shared_info.to_der()?, kek_size, rng)?;
        if key_agreement_output.key_encryption_key.len() != kek_size {
            return Err(Error::Builder(String::from(
                "key agreement output a key-encryption key of the wrong size",
            )));
        }

        // Wrap the content-encryption key (CEK) with the KEK
        let encrypted_key = self.key_wrap_algorithm.try_wrap(
            &key_agreement_output.key_encryption_key,
            content_encryption_key,
        )?;

        // Build RecipientInfo
        Ok(RecipientInfo::Kari(KeyAgreeRecipientInfo {
            originator: OriginatorIdentifierOrKey::OriginatorKey(
                key_agreement_output.originator_key,
            ),
            version: self.recipient_info_version(),
            ukm: self.ukm.clone(),
            key_enc_alg: AlgorithmIdentifierOwned {
                oid: self.key_agreement.oid(),
                parameters: Some(Any::from_der(&key_wrap_algorithm_der)?),
            },
            recipient_enc_keys: vec![RecipientEncryptedKey {
                rid: self.rid.clone(),
                enc_key: EncryptedKey::new(encrypted_key)?,
            }],
        }))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::eprintln;

    use super::*;
    use p256::{NistP256, PublicKey, pkcs8::DecodePublicKey};

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
            .map_err(|e| eprintln!("{e}"))
            .expect("Getting PublicKey failed");
        EcKeyEncryptionInfo::Ec(p256_public_key)
    }

    #[test]
    fn test_keyagreementalgorithm_oid() {
        assert_eq!(
            DhSinglePassStdDhKdf::<sha2::Sha224>::OID,
            rfc5753::DH_SINGLE_PASS_STD_DH_SHA_224_KDF_SCHEME
        );
        assert_eq!(
            DhSinglePassStdDhKdf::<sha2::Sha256>::OID,
            rfc5753::DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME
        );
        assert_eq!(
            DhSinglePassStdDhKdf::<sha2::Sha384>::OID,
            rfc5753::DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME
        );
        assert_eq!(
            DhSinglePassStdDhKdf::<sha2::Sha512>::OID,
            rfc5753::DH_SINGLE_PASS_STD_DH_SHA_512_KDF_SCHEME
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
            AlgorithmIdentifierOwned::from(ec_key_encryption_info)
        )
    }
}
