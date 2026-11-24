//! Cryptographic Message Syntax Builder

#![cfg(feature = "builder")]

use crate::{
    cert::CertificateChoices,
    content_info::CmsVersion,
    enveloped_data::{
        EncryptedContentInfo, EncryptedKey, EnvelopedData, KekIdentifier, KeyTransRecipientInfo,
        OriginatorInfo, PasswordRecipientInfo, RecipientIdentifier, RecipientInfo, RecipientInfos,
        UserKeyingMaterial,
    },
    revocation::RevocationInfoChoice,
};
use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use cipher::rand_core::{CryptoRng, TryCryptoRng};
use const_oid::{AssociatedOid, ObjectIdentifier};
use core::{fmt, marker::PhantomData};
use der::{
    Any, Decode, Encode, Tag,
    asn1::{Null, OctetString, OctetStringRef, SetOfVec},
};
use digest::{Digest, FixedOutputReset};
use rsa::{Pkcs1v15Encrypt, traits::RandomizedEncryptor};
use spki::{AlgorithmIdentifierOwned, DynAssociatedAlgorithmIdentifier};
use x509_cert::{
    attr::{Attribute, AttributeValue, Attributes},
    certificate::{Profile, Rfc5280},
    time::Time,
};

// Modules
mod content_encryption;
mod kari;
mod signed_data;
mod utils;

// Exports
pub use content_encryption::{
    AesCbcContentDecryptor, ContentDecryptor, ContentEncryptionAlgorithm, ContentEncryptionOutput,
    ContentEncryptor,
};
pub use kari::{
    DhSinglePassStdDhKdf, EcKeyEncryptionInfo, KeyAgreeRecipientInfoBuilder, KeyAgreementAlgorithm,
};
pub use signed_data::{SignedDataBuilder, SignerInfoBuilder};
pub use utils::kw::KeyWrapAlgorithm;

/// Error type
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// ASN.1 DER-related errors.
    Asn1(der::Error),

    /// Public key errors propagated from the [`spki::Error`] type.
    PublicKey(spki::Error),

    /// RNG error.
    Rng,

    /// Signing error propagated for the [`signature::Signer`] type.
    Signature(signature::Error),

    /// Builder no table to build, because the struct is not properly configured
    Builder(String),
}

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Asn1(err) => write!(f, "ASN.1 error: {err}"),
            Error::PublicKey(err) => write!(f, "public key error: {err}"),
            Error::Rng => write!(f, "rng error"),
            Error::Signature(err) => write!(f, "signature error: {err}"),
            Error::Builder(message) => write!(f, "builder error: {message}"),
        }
    }
}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
    }
}

impl From<spki::Error> for Error {
    fn from(err: spki::Error) -> Error {
        Error::PublicKey(err)
    }
}

impl From<signature::Error> for Error {
    fn from(err: signature::Error) -> Error {
        Error::Signature(err)
    }
}

type Result<T> = core::result::Result<T, Error>;

/// Trait for builders of a `RecipientInfo`. RFC 5652 § 6 defines 5 different `RecipientInfo`
/// formats. All implementations must implement this trait.
pub trait RecipientInfoBuilder<P: Profile = Rfc5280> {
    /// Associated Rng type
    type Rng: CryptoRng + ?Sized;

    /// Return the recipient info type
    fn recipient_info_type(&self) -> RecipientInfoType;

    /// Return the recipient info version
    fn recipient_info_version(&self) -> CmsVersion;

    /// Encrypt the `content_encryption_key` using a method, that is specific for the implementing
    /// builder type. Finally return a `RecipientInfo`.
    fn build_with_rng(
        &mut self,
        content_encryption_key: &[u8],
        rng: &mut Self::Rng,
    ) -> Result<RecipientInfo<P>>;
}

/// `RecipientInfoBuilder` must be implemented for these 5 recipient info types
/// as defined in RFC 5652 § 6:
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecipientInfoType {
    /// KeyTransRecipientInfo
    Ktri,
    /// KeyAgreeRecipientInfo
    Kari,
    /// KekRecipientInfo
    Kekri,
    /// PasswordRecipientInfo
    Pwri,
    /// OtherRecipientInfo
    Ori,
}

/// Contains information required to encrypt the content encryption key with a specific method
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyEncryptionInfo {
    /// Encrypt key with RSA
    Rsa(rsa::PublicKey),
    // to be extended here with other asymmetric encryption algorithms
}

/// Encrypts with RSAES-PKCS1-v1_5 for [`KeyEncryptionInfo::Rsa`].
impl RandomizedEncryptor for KeyEncryptionInfo {
    fn encrypt_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        match self {
            KeyEncryptionInfo::Rsa(public_key) => public_key.encrypt(rng, Pkcs1v15Encrypt, msg),
        }
    }
}

/// Identifies RSAES-PKCS1-v1_5 (`rsaEncryption`, NULL parameters) for [`KeyEncryptionInfo::Rsa`].
impl DynAssociatedAlgorithmIdentifier for KeyEncryptionInfo {
    fn algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        match self {
            KeyEncryptionInfo::Rsa(_) => Ok(AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::RSA_ENCRYPTION,
                parameters: Some(Any::from(Null)),
            }),
        }
    }
}

/// Encrypts the content-encryption key with RSAES-OAEP (RFC 8017 § 7.1, identified as in
/// RFC 4055 § 4.1), using the digest `D` for both the hash and MGF1, and an empty label.
///
/// The `id-RSAES-OAEP` parameters name `D`, except that SHA-1, the default, is omitted.
#[derive(Clone, Debug)]
pub struct RsaOaepKeyEncryptor<D>
where
    D: Digest + FixedOutputReset,
{
    key: rsa::oaep::EncryptingKey<D>,
}

impl<D> RsaOaepKeyEncryptor<D>
where
    D: Digest + FixedOutputReset,
{
    /// Creates an RSAES-OAEP key encryptor for the recipient's public key.
    pub fn new(public_key: rsa::PublicKey) -> Self {
        Self {
            key: rsa::oaep::EncryptingKey::new(public_key),
        }
    }
}

impl<D> RandomizedEncryptor for RsaOaepKeyEncryptor<D>
where
    D: Digest + FixedOutputReset,
{
    fn encrypt_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        self.key.encrypt_with_rng(rng, msg)
    }
}

impl<D> DynAssociatedAlgorithmIdentifier for RsaOaepKeyEncryptor<D>
where
    D: Digest + FixedOutputReset + AssociatedOid,
{
    fn algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        let parameters = pkcs1::RsaOaepParamsRef::new::<D>().to_der()?;
        Ok(AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_RSAES_OAEP,
            parameters: Some(Any::from_der(&parameters)?),
        })
    }
}

/// Builds a `KeyTransRecipientInfo` according to RFC 5652 § 6.
/// This type uses the recipient's public key to encrypt the content-encryption key.
///
/// The key encryptor `E` encrypts the content-encryption key and identifies its algorithm, for
/// the `KeyTransRecipientInfo`'s `keyEncryptionAlgorithm`. Implement both traits to perform key
/// transport elsewhere than in process, e.g. in a FIPS 140-3 validated module.
/// [`KeyEncryptionInfo`] implements them with RustCrypto RSAES-PKCS1-v1_5 and
/// [`RsaOaepKeyEncryptor`] with RustCrypto RSAES-OAEP.
pub struct KeyTransRecipientInfoBuilder<R: ?Sized, P: Profile = Rfc5280, E = KeyEncryptionInfo> {
    /// Identifies the recipient
    pub rid: RecipientIdentifier<P>,
    /// Info for key encryption
    pub key_encryption_info: E,
    _rng: PhantomData<R>,
}

impl<R, P: Profile, E> KeyTransRecipientInfoBuilder<R, P, E> {
    /// Creates a `KeyTransRecipientInfoBuilder`
    pub fn new(rid: RecipientIdentifier<P>, key_encryption_info: E) -> Result<Self> {
        Ok(KeyTransRecipientInfoBuilder {
            rid,
            key_encryption_info,
            _rng: PhantomData,
        })
    }
}

impl<R: ?Sized, P: Profile, E> RecipientInfoBuilder<P> for KeyTransRecipientInfoBuilder<R, P, E>
where
    R: CryptoRng,
    E: RandomizedEncryptor + DynAssociatedAlgorithmIdentifier,
{
    type Rng = R;

    fn recipient_info_type(&self) -> RecipientInfoType {
        RecipientInfoType::Ktri
    }

    fn recipient_info_version(&self) -> CmsVersion {
        match self.rid {
            RecipientIdentifier::IssuerAndSerialNumber(_) => CmsVersion::V0,
            RecipientIdentifier::SubjectKeyIdentifier(_) => CmsVersion::V2,
        }
    }

    /// Build a `KeyTransRecipientInfo`. See RFC 5652 § 6.2.1
    /// `content_encryption_key` will be encrypted with the recipient's public key.
    fn build_with_rng(
        &mut self,
        content_encryption_key: &[u8],
        rng: &mut Self::Rng,
    ) -> Result<RecipientInfo<P>> {
        let key_enc_alg = self.key_encryption_info.algorithm_identifier()?;
        let encrypted_key = self
            .key_encryption_info
            .encrypt_with_rng(rng, content_encryption_key)
            .map_err(|_| Error::Builder(String::from("Could not encrypt key")))?;
        let enc_key = EncryptedKey::new(encrypted_key)?;

        Ok(RecipientInfo::Ktri(KeyTransRecipientInfo {
            version: self.recipient_info_version(),
            rid: self.rid.clone(),
            key_enc_alg,
            enc_key,
        }))
    }
}

/// Builds a `KekRecipientInfo` according to RFC 5652 § 6.
/// Uses symmetric key-encryption keys: the content-encryption key is
/// encrypted in a previously distributed symmetric key-encryption key.
pub struct KekRecipientInfoBuilder<R: ?Sized, P: Profile = Rfc5280> {
    /// Specifies a symmetric key-encryption key that was previously distributed to the sender and
    /// one or more recipients.
    pub kek_id: KekIdentifier,
    /// Encryption algorithm to be used for key encryption
    pub key_enc_alg: AlgorithmIdentifierOwned,
    _marker: PhantomData<(P, R)>,
}

impl<R, P: Profile> KekRecipientInfoBuilder<R, P> {
    /// Creates a `KekRecipientInfoBuilder`
    pub fn new(kek_id: KekIdentifier, key_enc_alg: AlgorithmIdentifierOwned) -> Result<Self> {
        Ok(KekRecipientInfoBuilder {
            kek_id,
            key_enc_alg,
            _marker: PhantomData,
        })
    }
}

impl<R: ?Sized, P: Profile> RecipientInfoBuilder<P> for KekRecipientInfoBuilder<R, P>
where
    R: CryptoRng,
{
    type Rng = R;

    /// Returns the RecipientInfoType
    fn recipient_info_type(&self) -> RecipientInfoType {
        RecipientInfoType::Kekri
    }

    /// Returns the `CMSVersion` for this `RecipientInfo`
    fn recipient_info_version(&self) -> CmsVersion {
        CmsVersion::V4
    }

    /// Build a `KekRecipientInfoBuilder`. See RFC 5652 § 6.2.1
    fn build_with_rng(
        &mut self,
        _content_encryption_key: &[u8],
        _rng: &mut Self::Rng,
    ) -> Result<RecipientInfo<P>> {
        Err(Error::Builder(String::from(
            "Building KekRecipientInfo is not implemented, yet.",
        )))
    }
}

/// Trait used for encrypting the content-encryption key for PasswordRecipientInfo.
/// This trait must be implemented by a user and which allows for greater flexibility
/// in choosing key derivation and encryption algorithms. Note, that method
/// `encrypt_rfc3211()` must follow RFC 3211 and encrypt the key twice.
pub trait PwriEncryptor {
    /// Block length of the encryption algorithm.
    const BLOCK_LENGTH_BITS: usize;
    /// Returns the algorithm identifier of the used key derivation algorithm,
    /// which is used to derive an encryption key from the secret/password
    /// shared with the recipient. Includes eventual parameters (e.g. the used iv).
    fn key_derivation_algorithm(&self) -> Result<Option<AlgorithmIdentifierOwned>>;
    /// Returns the algorithm identifier of the used encryption algorithm
    /// including eventual parameters (e.g. the used iv).
    fn key_encryption_algorithm(&self) -> Result<AlgorithmIdentifierOwned>;
    /// Encrypt the padded content-encryption key twice following RFC 3211, § 2.3.1
    fn encrypt_rfc3211<R: CryptoRng + ?Sized>(
        &mut self,
        padded_content_encryption_key: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>>;
}

/// Builds a `PasswordRecipientInfo` according to RFC 5652 § 6 and RFC 3211.
/// Uses a password or shared secret value to encrypt the content-encryption key.
pub struct PasswordRecipientInfoBuilder<E, R: ?Sized, P: Profile = Rfc5280>
where
    E: PwriEncryptor,
{
    /// Identifies the key-derivation algorithm, and any associated parameters, used to derive the
    /// key-encryption key from the password or shared secret value. If this field is `None`,
    /// the key-encryption key is supplied from an external source, for example a hardware crypto
    /// token such as a smart card.
    pub key_derivation_alg: Option<AlgorithmIdentifierOwned>,
    /// Encryption algorithm to be used for key encryption
    pub key_enc_alg: AlgorithmIdentifierOwned,
    /// Provided password encryptor
    pub key_encryptor: E,
    _marker: PhantomData<(P, R)>,
}

impl<E, R, P: Profile> PasswordRecipientInfoBuilder<E, R, P>
where
    E: PwriEncryptor,
{
    /// Creates a `PasswordRecipientInfoBuilder`
    /// `key_derivation_alg`: (optional) Algorithm used to derive the
    ///     key-encryption key from the shared secret (password)
    /// `key_enc_alg`: Algorithm used to (symmetrically) encrypt the
    ///     content-encryption key
    /// `key_encryptor`: Provided encryptor, which is used to encrypt
    ///     the content-encryption key
    /// `rng`: Random number generator, required for padding values.
    pub fn new(key_encryptor: E) -> Result<Self> {
        Ok(PasswordRecipientInfoBuilder {
            key_derivation_alg: key_encryptor.key_derivation_algorithm()?,
            key_enc_alg: key_encryptor.key_encryption_algorithm()?,
            key_encryptor,
            _marker: PhantomData,
        })
    }
}

impl<E, R: ?Sized, P: Profile> PasswordRecipientInfoBuilder<E, R, P>
where
    E: PwriEncryptor,
    R: CryptoRng,
{
    /// Wrap the content-encryption key according to [RFC 3211, §2.3.1]:
    ///     ....
    ///     The formatted CEK block then looks as follows:
    ///     CEK byte count || check value || CEK || padding (if required)
    ///
    /// [RFC 3211, §2.3.1]: https://www.rfc-editor.org/rfc/rfc3211#section-2.3.1
    fn pad_content_encryption_key(
        &mut self,
        content_encryption_key: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let content_encryption_key_length = content_encryption_key.len();
        let padded_key_length_wo_padding = 1 + 3 + content_encryption_key_length;
        let key_enc_alg_blocklength_bytes = E::BLOCK_LENGTH_BITS / 8;
        let padding_length =
            (2 * key_enc_alg_blocklength_bytes).saturating_sub(padded_key_length_wo_padding);

        let cek_byte_count: u8 = content_encryption_key.len().try_into().map_err(|_| {
            Error::Builder("Content encryption key length must not exceed 255".to_string())
        })?;
        let mut padded_cek: Vec<u8> =
            Vec::with_capacity(4 + content_encryption_key_length + padding_length);
        padded_cek.push(cek_byte_count);
        padded_cek.push(0xff ^ content_encryption_key[0]);
        padded_cek.push(0xff ^ content_encryption_key[1]);
        padded_cek.push(0xff ^ content_encryption_key[2]);
        padded_cek.extend_from_slice(content_encryption_key);
        if padding_length > 0 {
            let mut padding = vec![0_u8; padding_length];
            rng.fill_bytes(padding.as_mut_slice());
            padded_cek.append(&mut padding);
        }
        Ok(padded_cek)
    }
}

impl<E, R, P: Profile> RecipientInfoBuilder<P> for PasswordRecipientInfoBuilder<E, R, P>
where
    E: PwriEncryptor,
    R: CryptoRng + ?Sized,
{
    type Rng = R;

    /// Returns the RecipientInfoType
    fn recipient_info_type(&self) -> RecipientInfoType {
        RecipientInfoType::Pwri
    }

    /// Returns the `CMSVersion` for this `RecipientInfo`
    fn recipient_info_version(&self) -> CmsVersion {
        CmsVersion::V0
    }

    /// Build a `PasswordRecipientInfoBuilder`. See RFC 5652 § 6.2.1
    fn build_with_rng(
        &mut self,
        content_encryption_key: &[u8],
        rng: &mut Self::Rng,
    ) -> Result<RecipientInfo<P>> {
        let padded_cek = self.pad_content_encryption_key(content_encryption_key, rng)?;
        let encrypted_key = self
            .key_encryptor
            .encrypt_rfc3211(padded_cek.as_slice(), rng)?;
        let enc_key = OctetString::new(encrypted_key)?;
        Ok(RecipientInfo::Pwri(PasswordRecipientInfo {
            version: self.recipient_info_version(),
            key_derivation_alg: self.key_derivation_alg.clone(),
            key_enc_alg: self.key_enc_alg.clone(),
            enc_key,
        }))
    }
}

/// Builds an `OtherRecipientInfo` according to RFC 5652 § 6.
/// This type makes no assumption about the encryption method or the needed information.
pub struct OtherRecipientInfoBuilder<R: ?Sized, P: Profile = Rfc5280> {
    /// Identifies the key management technique.
    pub ori_type: ObjectIdentifier,
    /// Contains the protocol data elements needed by a recipient using the identified key
    /// management technique
    pub ori_value: Any,

    _marker: PhantomData<(P, R)>,
}

impl<R, P: Profile> OtherRecipientInfoBuilder<R, P> {
    /// Creates a `OtherRecipientInfoBuilder`
    pub fn new(ori_type: ObjectIdentifier, ori_value: Any) -> Result<Self> {
        Ok(OtherRecipientInfoBuilder {
            ori_type,
            ori_value,
            _marker: PhantomData,
        })
    }
}

impl<R, P: Profile> RecipientInfoBuilder<P> for OtherRecipientInfoBuilder<R, P>
where
    R: CryptoRng + ?Sized,
{
    type Rng = R;

    /// Returns the RecipientInfoType
    fn recipient_info_type(&self) -> RecipientInfoType {
        RecipientInfoType::Ori
    }

    /// Returns the `CMSVersion` for this `RecipientInfo`
    fn recipient_info_version(&self) -> CmsVersion {
        panic!("Ori has no CMSVersion")
    }

    /// Build a `OtherRecipientInfoBuilder`. See RFC 5652 § 6.2.1
    fn build_with_rng(
        &mut self,
        _content_encryption_key: &[u8],
        _rng: &mut Self::Rng,
    ) -> Result<RecipientInfo<P>> {
        panic!("Ori has no common build method.")
    }
}

/// Builds CMS `EnvelopedData` according to RFC 5652 § 6.
pub struct EnvelopedDataBuilder<'c, R: ?Sized, P: Profile = Rfc5280> {
    originator_info: Option<OriginatorInfo<P>>,
    recipient_infos: Vec<Box<dyn RecipientInfoBuilder<P, Rng = R> + 'c>>,
    unencrypted_content: &'c [u8],
    content_encryptor: Box<dyn ContentEncryptor<R> + 'c>,
    unprotected_attributes: Option<Attributes>,
}

impl<'c, R, P: Profile> EnvelopedDataBuilder<'c, R, P> {
    /// Create a new builder for `EnvelopedData`.
    ///
    /// `content_encryptor` encrypts the content with a newly generated content-encryption key,
    /// which the recipient info builders then deliver; [`ContentEncryptionAlgorithm`] does so with
    /// RustCrypto AES-CBC.
    pub fn new(
        originator_info: Option<OriginatorInfo<P>>,
        unencrypted_content: &'c [u8],
        content_encryptor: impl ContentEncryptor<R> + 'c,
        unprotected_attributes: Option<Attributes>,
    ) -> Result<Self> {
        Ok(EnvelopedDataBuilder {
            originator_info,
            recipient_infos: Vec::new(),
            unencrypted_content,
            content_encryptor: Box::new(content_encryptor),
            unprotected_attributes,
        })
    }
}

impl<'c, R, P: Profile> EnvelopedDataBuilder<'c, R, P>
where
    R: CryptoRng + ?Sized,
{
    /// Add recipient info. A builder is used, which generates a `RecipientInfo` according to
    /// RFC 5652 § 6.2, when `EnvelopedData` is built.
    pub fn add_recipient_info(
        &mut self,
        recipient_info_builder: impl RecipientInfoBuilder<P, Rng = R> + 'c,
    ) -> Result<&mut Self> {
        self.recipient_infos.push(Box::new(recipient_info_builder));

        Ok(self)
    }

    /// Generate an `EnvelopedData` object according to RFC 5652 § 6 using a provided
    /// random number generator.
    pub fn build_with_rng(&mut self, rng: &mut R) -> Result<EnvelopedData<P>> {
        // Generate content encryption key
        // Encrypt content
        // Build recipient infos
        // Make sure, content encryption key is securely destroyed
        let ContentEncryptionOutput {
            ciphertext,
            key: content_encryption_key,
            algorithm: content_enc_alg,
            tag,
        } = self
            .content_encryptor
            .encrypt_content(None, self.unencrypted_content, None, rng)?;
        if tag.is_some() {
            return Err(Error::Builder(
                "EnvelopedData has no place for an authentication tag; use AuthEnvelopedData"
                    .to_string(),
            ));
        }
        if content_enc_alg.oid != self.content_encryptor.oid() {
            return Err(Error::Builder(
                "content encryptor output an algorithm other than its own".to_string(),
            ));
        }
        let encrypted_content_octetstring = OctetString::new(ciphertext)?;
        let encrypted_content_info = EncryptedContentInfo {
            content_type: const_oid::db::rfc5911::ID_DATA, // TODO bk should this be configurable?
            content_enc_alg,
            encrypted_content: Some(encrypted_content_octetstring), // TODO bk `None` (external content) should also be possible
        };

        let recipient_infos_vec = self
            .recipient_infos
            .iter_mut()
            .map(|ri| ri.build_with_rng(&content_encryption_key, rng))
            .collect::<Result<Vec<RecipientInfo<P>>>>()?;
        let recip_infos = RecipientInfos::try_from(recipient_infos_vec).unwrap();

        Ok(EnvelopedData {
            version: self.calculate_version(),
            originator_info: self.originator_info.clone(),
            recip_infos,
            encrypted_content: encrypted_content_info,
            unprotected_attrs: self.unprotected_attributes.clone(),
        })
    }

    /// Calculate the `CMSVersion` of the `EnvelopedData` according to RFC 5652 § 6.1
    fn calculate_version(&self) -> CmsVersion {
        // IF (originatorInfo is present) AND
        //    ((any certificates with a type of other are present) OR
        //    (any crls with a type of other are present))
        // THEN version is 4
        // ELSE
        //    IF ((originatorInfo is present) AND
        //       (any version 2 attribute certificates are present)) OR
        //       (any RecipientInfo structures include pwri) OR
        //       (any RecipientInfo structures include ori)
        //    THEN version is 3
        //    ELSE
        //       IF (originatorInfo is absent) AND
        //          (unprotectedAttrs is absent) AND
        //          (all RecipientInfo structures are version 0)
        //       THEN version is 0
        //       ELSE version is 2
        let originator_info_present = self.originator_info.is_some();
        let other_certificates_present = if let Some(originator_info) = &self.originator_info {
            if let Some(certificates) = &originator_info.certs {
                certificates
                    .0
                    .iter()
                    .any(|certificate| matches!(certificate, CertificateChoices::Other(_)))
            } else {
                false
            }
        } else {
            false
        };
        let other_crls_present = if let Some(originator_info) = &self.originator_info {
            if let Some(crls) = &originator_info.crls {
                crls.0
                    .iter()
                    .any(|crl| matches!(crl, RevocationInfoChoice::Other(_)))
            } else {
                false
            }
        } else {
            false
        };
        // v2 certificates currently not supported
        // let v2_certificates_present = if let Some(certificate_option) = &self.originator_info {
        //     if let Some(certificates) = certificate_option {
        //         certificates
        //             .iter()
        //             .any(|certificate| matches!(certificate, CertificateChoices::V2AttrCert))
        //     } else {
        //         false
        //     }
        // } else {
        //     false
        // };
        let v2_certificates_present = false;
        let pwri_recipient_info_present = self.recipient_infos.iter().any(|recipient_info| {
            matches!(
                recipient_info.recipient_info_type(),
                RecipientInfoType::Pwri
            )
        });
        let ori_recipient_info_present = self.recipient_infos.iter().any(|recipient_info| {
            matches!(recipient_info.recipient_info_type(), RecipientInfoType::Ori)
        });
        let unprotected_attributes_present = self.unprotected_attributes.is_some();
        let all_recipient_infos_are_v0 = self
            .recipient_infos
            .iter()
            .all(|ri| ri.recipient_info_version() == CmsVersion::V0);

        if originator_info_present && (other_certificates_present || other_crls_present) {
            CmsVersion::V4
        } else if (originator_info_present && v2_certificates_present)
            || pwri_recipient_info_present
            || ori_recipient_info_present
        {
            CmsVersion::V3
        } else if !originator_info_present
            && !unprotected_attributes_present
            && all_recipient_infos_are_v0
        {
            CmsVersion::V0
        } else {
            CmsVersion::V2
        }
    }
}

/// Create a content-type attribute according to
/// [RFC 5652 § 11.1](https://www.rfc-editor.org/info/rfc5652#section-11.1)
pub fn create_content_type_attribute(content_type: ObjectIdentifier) -> Result<Attribute> {
    let content_type_attribute_value =
        AttributeValue::new(Tag::ObjectIdentifier, content_type.as_bytes())?;
    let mut values = SetOfVec::new();
    values.insert(content_type_attribute_value)?;
    let attribute = Attribute {
        oid: const_oid::db::rfc5911::ID_CONTENT_TYPE,
        values,
    };
    Ok(attribute)
}

/// Create a message digest attribute according to
/// [RFC 5652 § 11.2](https://www.rfc-editor.org/info/rfc5652#section-11.2)
pub fn create_message_digest_attribute(message_digest: &[u8]) -> Result<Attribute> {
    let message_digest_der = OctetStringRef::new(message_digest)?;
    let message_digest_attribute_value =
        AttributeValue::new(Tag::OctetString, message_digest_der.as_bytes())?;
    let mut values = SetOfVec::new();
    values.insert(message_digest_attribute_value)?;
    let attribute = Attribute {
        oid: const_oid::db::rfc5911::ID_MESSAGE_DIGEST,
        values,
    };
    Ok(attribute)
}

/// Create a signing time attribute according to
/// [RFC 5652 § 11.3](https://www.rfc-editor.org/info/rfc5652#section-11.3)
/// Dates between 1 January 1950 and 31 December 2049 (inclusive) MUST be
/// encoded as UTCTime.  Any dates with year values before 1950 or after
/// 2049 MUST be encoded as GeneralizedTime.
pub fn create_signing_time_attribute() -> Result<Attribute> {
    let time_der = Time::now()?.to_der()?;
    let signing_time_attribute_value = AttributeValue::from_der(&time_der)?;
    let mut values = SetOfVec::<AttributeValue>::new();
    values.insert(signing_time_attribute_value)?;
    let attribute = Attribute {
        oid: const_oid::db::rfc5911::ID_SIGNING_TIME,
        values,
    };
    Ok(attribute)
}
