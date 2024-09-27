#![cfg(feature = "builder")]

//! CMS Builder

use crate::cert::CertificateChoices;
use crate::content_info::{CmsVersion, ContentInfo};
use crate::enveloped_data::{
    EncryptedContentInfo, EncryptedKey, EnvelopedData, KekIdentifier, KeyTransRecipientInfo,
    OriginatorIdentifierOrKey, OriginatorInfo, RecipientIdentifier, RecipientInfo, RecipientInfos,
    UserKeyingMaterial,
};
use crate::revocation::{RevocationInfoChoice, RevocationInfoChoices};
use crate::signed_data::{
    CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignatureValue,
    SignedAttributes, SignedData, SignerIdentifier, SignerInfo, SignerInfos, UnsignedAttributes,
};
use aes::{Aes128, Aes192, Aes256};
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use cipher::{
    block_padding::Pkcs7,
    rand_core::{self, CryptoRng, CryptoRngCore, RngCore},
    BlockModeEncrypt, Key, KeyIvInit, KeySizeUser,
};
use const_oid::ObjectIdentifier;
use core::cmp::Ordering;
use core::fmt;
use der::asn1::{BitString, OctetStringRef, SetOfVec};
use der::oid::db::DB;
use der::Tag::OctetString;
use der::{Any, AnyRef, DateTime, Decode, Encode, ErrorKind, Tag};
use digest::Digest;
use rsa::Pkcs1v15Encrypt;
use sha2::digest;
use signature::digest::DynDigest;
use signature::{Keypair, RandomizedSigner, Signer};
use spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
    SignatureBitStringEncoding,
};
use std::time::SystemTime;
use std::vec;
use x509_cert::attr::{Attribute, AttributeValue, Attributes};
use x509_cert::builder::{self, Builder};
use zeroize::Zeroize;

/// Error type
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// ASN.1 DER-related errors.
    Asn1(der::Error),

    /// Public key errors propagated from the [`spki::Error`] type.
    PublicKey(spki::Error),

    /// RNG error propagated for the [`rand_core::Error`] type.
    Rng(rand_core::Error),

    /// Signing error propagated for the [`signature::Signer`] type.
    Signature(signature::Error),

    /// Builder no table to build, because the struct is not properly configured
    Builder(String),
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Asn1(err) => write!(f, "ASN.1 error: {}", err),
            Error::PublicKey(err) => write!(f, "public key error: {}", err),
            Error::Rng(err) => write!(f, "rng error: {}", err),
            Error::Signature(err) => write!(f, "signature error: {}", err),
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

impl From<rand_core::Error> for Error {
    fn from(err: rand_core::Error) -> Error {
        Error::Rng(err)
    }
}

type Result<T> = core::result::Result<T, Error>;

/// Collect info needed for creating a `SignerInfo`.
/// Calling `build()` on this struct will
/// - calculate the correct `CMSVersion` (depends on `sid`)
/// - calculate the signature
/// - set the signing time attribute
/// - create a `SignerInfo` object
pub struct SignerInfoBuilder<'s> {
    sid: SignerIdentifier,
    digest_algorithm: AlgorithmIdentifierOwned,
    signed_attributes: Option<Vec<Attribute>>,
    unsigned_attributes: Option<Vec<Attribute>>,
    encapsulated_content_info: &'s EncapsulatedContentInfo,
    external_message_digest: Option<&'s [u8]>,
}

impl<'s> SignerInfoBuilder<'s> {
    /// Create a new `SignerInfoBuilder`. This is used for adding `SignerInfo`s to `SignedData`
    /// structures.
    /// The content to be signed can be stored externally. In this case `eContent` in
    /// `encapsulated_content_info` must be `None` and the message digest must be passed with
    /// `external_message_digest`. `digest_algorithm` must match the used digest algorithm.
    pub fn new(
        sid: SignerIdentifier,
        digest_algorithm: AlgorithmIdentifierOwned,
        encapsulated_content_info: &'s EncapsulatedContentInfo,
        external_message_digest: Option<&'s [u8]>,
    ) -> Result<Self> {
        Ok(SignerInfoBuilder {
            sid,
            digest_algorithm,
            signed_attributes: None,
            unsigned_attributes: None,
            encapsulated_content_info,
            external_message_digest,
        })
    }

    /// Add a "signed" attribute. The attribute will be signed together with the other "signed"
    /// attributes, when `build()` is called.
    pub fn add_signed_attribute(&mut self, signed_attribute: Attribute) -> Result<&mut Self> {
        if let Some(signed_attributes) = &mut self.signed_attributes {
            signed_attributes.push(signed_attribute);
        } else {
            self.signed_attributes = Some(vec![signed_attribute]);
        }
        Ok(self)
    }

    /// Add an unsigned attribute.
    pub fn add_unsigned_attribute(&mut self, unsigned_attribute: Attribute) -> Result<&mut Self> {
        if let Some(unsigned_attributes) = &mut self.unsigned_attributes {
            unsigned_attributes.push(unsigned_attribute);
        } else {
            self.unsigned_attributes = Some(vec![unsigned_attribute]);
        }
        Ok(self)
    }

    /// Calculate the CMSVersion of the signer info.
    /// Intended to be called during building the `SignerInfo`.
    /// RFC 5652 § 5.3: version is the syntax version number.  If the SignerIdentifier is
    /// the CHOICE issuerAndSerialNumber, then the version MUST be 1. If
    /// the SignerIdentifier is subjectKeyIdentifier, then the version MUST be 3.
    pub fn version(&self) -> CmsVersion {
        match self.sid {
            SignerIdentifier::IssuerAndSerialNumber(_) => CmsVersion::V1,
            SignerIdentifier::SubjectKeyIdentifier(_) => CmsVersion::V3,
        }
    }
}

impl<'s> Builder for SignerInfoBuilder<'s> {
    type Output = SignerInfo;

    /// Calculate the data to be signed
    /// [RFC 5652 § 5.4](https://datatracker.ietf.org/doc/html/rfc5652#section-5.4)
    /// If an `external_message_digest` is passed in, it is assumed, that we are signing external
    /// content (see RFC 5652 § 5.2). In this case, the `eContent` in `EncapsulatedContentInfo`
    /// must be `None`.
    fn finalize<S>(&mut self, _signer: &S) -> builder::Result<Vec<u8>>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        let message_digest = match self.external_message_digest {
            Some(external_content_digest) => {
                if self.encapsulated_content_info.econtent.is_some() {
                    // Encapsulated content must be empty, if external digest is given.
                    return Err(der::Error::from(ErrorKind::Failed).into());
                }
                Some(external_content_digest.to_vec())
            }
            None => match &self.encapsulated_content_info.econtent {
                None => {
                    // This case is allowed. E.g. for degenerate certificates-only messages.
                    // See RFC 5652 § 5.2 or RFC 8894 § 3.4.
                    None
                }
                Some(content) => {
                    let mut hasher = get_hasher(&self.digest_algorithm).ok_or_else(|| {
                        // Unsupported hash algorithm: {}, &self.digest_algorithm.oid.to_string()
                        builder::Error::from(der::Error::from(ErrorKind::Failed))
                    })?;
                    // Only the octets comprising the value of the eContent
                    // OCTET STRING are input to the message digest algorithm, not the tag
                    // or the length octets.
                    let content_value = content.value();
                    hasher.update(content_value);
                    Some(hasher.finalize_reset().to_vec())
                }
            },
        };

        // This implementation uses signed attributes to store the message digest.
        if self.signed_attributes.is_none() {
            self.signed_attributes = Some(vec![]);
        }

        let signed_attributes = self
            .signed_attributes
            .as_mut()
            .expect("Signed attributes must be present.");

        if let Some(message_digest) = message_digest {
            // Add digest attribute to (to be) signed attributes
            signed_attributes.push(
                create_message_digest_attribute(&message_digest)
                    .map_err(|_| der::Error::from(ErrorKind::Failed))?,
            );

            // The content-type attribute type specifies the content type of the
            // ContentInfo within signed-data or authenticated-data.  The content-
            // type attribute type MUST be present whenever signed attributes are
            // present in signed-data or authenticated attributes present in
            // authenticated-data.  The content-type attribute value MUST match the
            // encapContentInfo eContentType value in the signed-data or
            // authenticated-data.
            let econtent_type = self.encapsulated_content_info.econtent_type;
            let signed_attributes_content_type = signed_attributes.iter().find(|attr| {
                attr.oid.cmp(&const_oid::db::rfc5911::ID_CONTENT_TYPE) == Ordering::Equal
            });
            if let Some(signed_attributes_content_type) = signed_attributes_content_type {
                // Check against `eContentType`
                if signed_attributes_content_type.oid != econtent_type {
                    // Mismatch between content types: encapsulated content info <-> signed attributes.
                    return Err(der::Error::from(ErrorKind::Failed).into());
                }
            } else {
                signed_attributes.push(
                    create_content_type_attribute(econtent_type)
                        .map_err(|_| der::Error::from(ErrorKind::Failed))?,
                );
            }
        }

        // Now use `signer` to sign the DER encoded signed attributes
        let signed_attributes = SignedAttributes::try_from(signed_attributes.to_owned())
            .map_err(|_| der::Error::from(ErrorKind::Failed))?;
        let mut signed_attributes_der = Vec::new();
        signed_attributes.encode_to_vec(&mut signed_attributes_der)?;

        Ok(signed_attributes_der)
    }

    fn assemble<S>(self, signature: BitString, signer: &S) -> builder::Result<Self::Output>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        let signed_attrs = self.signed_attributes.as_ref().map(|signed_attributes| {
            SignedAttributes::try_from(signed_attributes.to_owned()).unwrap()
        });
        let unsigned_attrs = self
            .unsigned_attributes
            .as_ref()
            .map(|unsigned_attributes| {
                UnsignedAttributes::try_from(unsigned_attributes.to_owned()).unwrap()
            });

        let signature_value =
            SignatureValue::new(signature.raw_bytes()).map_err(builder::Error::from)?;

        let signature_algorithm = signer.signature_algorithm_identifier()?;

        Ok(SignerInfo {
            version: self.version(),
            sid: self.sid.clone(),
            digest_alg: self.digest_algorithm,
            signed_attrs,
            signature_algorithm,
            signature: signature_value,
            unsigned_attrs,
        })
    }
}

/// Builder for signedData (CMS and PKCS #7)
pub struct SignedDataBuilder<'s> {
    digest_algorithms: Vec<AlgorithmIdentifierOwned>,
    encapsulated_content_info: &'s EncapsulatedContentInfo,
    certificates: Option<Vec<CertificateChoices>>,
    crls: Option<Vec<RevocationInfoChoice>>,
    signer_infos: Vec<SignerInfo>,
}

impl<'s> SignedDataBuilder<'s> {
    /// Create a new builder for `SignedData`
    pub fn new(encapsulated_content_info: &'s EncapsulatedContentInfo) -> SignedDataBuilder<'s> {
        Self {
            digest_algorithms: Vec::new(),
            encapsulated_content_info,
            certificates: None,
            crls: None,
            signer_infos: Vec::new(),
        }
    }

    /// Add a digest algorithm to the collection of message digest algorithms.
    /// RFC 5652 § 5.1: digestAlgorithms is a collection of message digest algorithm
    /// identifiers.  There MAY be any number of elements in the
    /// collection, including zero.  Each element identifies the message
    /// digest algorithm, along with any associated parameters, used by
    /// one or more signer.  The collection is intended to list the
    /// message digest algorithms employed by all of the signers, in any
    /// order, to facilitate one-pass signature verification.
    pub fn add_digest_algorithm(
        &mut self,
        digest_algorithm: AlgorithmIdentifierOwned,
    ) -> Result<&mut Self> {
        self.digest_algorithms.push(digest_algorithm);
        Ok(self)
    }

    /// Add a certificate to the certificate collection.
    /// RFC 5652 § 5.1:
    /// certificates is a collection of certificates.  It is intended that
    /// the set of certificates be sufficient to contain certification
    /// paths from a recognized "root" or "top-level certification
    /// authority" to all of the signers in the signerInfos field.  There
    /// may be more certificates than necessary, and there may be
    /// certificates sufficient to contain certification paths from two or
    /// more independent top-level certification authorities.  There may
    /// also be fewer certificates than necessary, if it is expected that
    /// recipients have an alternate means of obtaining necessary
    /// certificates (e.g., from a previous set of certificates).  The
    /// signer's certificate MAY be included.  The use of version 1
    /// attribute certificates is strongly discouraged.
    pub fn add_certificate(&mut self, certificate: CertificateChoices) -> Result<&mut Self> {
        if self.certificates.is_none() {
            self.certificates = Some(Vec::new());
        }
        if let Some(certificates) = &mut self.certificates {
            certificates.push(certificate);
        }
        Ok(self)
    }

    /// Add a CRL to the collection of CRLs.
    /// RFC 5652 § 5.1:
    /// crls is a collection of revocation status information.  It is
    /// intended that the collection contain information sufficient to
    /// determine whether the certificates in the certificates field are
    /// valid, but such correspondence is not necessary.  Certificate
    /// revocation lists (CRLs) are the primary source of revocation
    /// status information.  There MAY be more CRLs than necessary, and
    /// there MAY also be fewer CRLs than necessary.
    pub fn add_crl(&mut self, crl: RevocationInfoChoice) -> Result<&mut Self> {
        if self.crls.is_none() {
            self.crls = Some(Vec::new());
        }
        if let Some(crls) = &mut self.crls {
            crls.push(crl);
        }
        Ok(self)
    }

    /// Add a signer info. The signature will be calculated. Note that the encapsulated content
    /// must not be changed after the first signer info was added.
    pub fn add_signer_info<S, Signature>(
        &mut self,
        signer_info_builder: SignerInfoBuilder<'_>,
        signer: &S,
    ) -> Result<&mut Self>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S: Signer<Signature>,
        S::VerifyingKey: EncodePublicKey,
        Signature: SignatureBitStringEncoding,
    {
        let signer_info = signer_info_builder
            .build::<S, Signature>(signer)
            .map_err(|_| der::Error::from(ErrorKind::Failed))?;
        self.signer_infos.push(signer_info);

        Ok(self)
    }

    /// Add a signer info. The signature will be calculated. Note that the encapsulated content
    /// must not be changed after the first signer info was added.
    pub fn add_signer_info_with_rng<S, Signature>(
        &mut self,
        signer_info_builder: SignerInfoBuilder<'_>,
        signer: &S,
        rng: &mut impl CryptoRngCore,
    ) -> Result<&mut Self>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S: RandomizedSigner<Signature>,
        S::VerifyingKey: EncodePublicKey,
        Signature: SignatureBitStringEncoding,
    {
        let signer_info = signer_info_builder
            .build_with_rng::<S, Signature>(signer, rng)
            .map_err(|_| der::Error::from(ErrorKind::Failed))?;
        self.signer_infos.push(signer_info);

        Ok(self)
    }

    /// This method returns a `ContentInfo` of type `signedData`.
    pub fn build(&mut self) -> Result<ContentInfo> {
        let digest_algorithms =
            DigestAlgorithmIdentifiers::try_from(self.digest_algorithms.to_owned()).unwrap();

        let encap_content_info = self.encapsulated_content_info.clone();

        let certificates = self
            .certificates
            .as_mut()
            .map(|certificates| CertificateSet::try_from(certificates.to_owned()).unwrap());

        let crls = self
            .crls
            .as_mut()
            .map(|crls| RevocationInfoChoices::try_from(crls.to_owned()).unwrap());

        let signer_infos = SignerInfos::try_from(self.signer_infos.clone()).unwrap();

        let signed_data = SignedData {
            version: self.calculate_version(),
            digest_algorithms,
            encap_content_info,
            certificates,
            crls,
            signer_infos,
        };

        let signed_data_der = signed_data.to_der()?;
        let content = AnyRef::try_from(signed_data_der.as_slice())?;

        let signed_data = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: Any::from(content),
        };

        Ok(signed_data)
    }

    fn calculate_version(&self) -> CmsVersion {
        // RFC 5652, 5.1.  SignedData Type
        // IF ((certificates is present) AND
        //             (any certificates with a type of other are present)) OR
        //             ((crls is present) AND
        //             (any crls with a type of other are present))
        //          THEN version MUST be 5
        //          ELSE
        //             IF (certificates is present) AND
        //                (any version 2 attribute certificates are present)
        //             THEN version MUST be 4
        //             ELSE
        //                IF ((certificates is present) AND
        //                   (any version 1 attribute certificates are present)) OR
        //                   (any SignerInfo structures are version 3) OR
        //                   (encapContentInfo eContentType is other than id-data)
        //                THEN version MUST be 3
        //                ELSE version MUST be 1
        let other_certificates_are_present = if let Some(certificates) = &self.certificates {
            certificates
                .iter()
                .any(|certificate| matches!(certificate, CertificateChoices::Other(_)))
        } else {
            false
        };
        // v1 and v2 currently not supported
        // let v2_certificates_are_present = if let Some(certificates) = &self.certificates {
        //     certificates.iter().any(|certificate| match certificate {
        //         CertificateChoices::V2AttrCert(_) => true,
        //         _ => false,
        //     })
        // } else {
        //     false
        // };
        // let v1_certificates_are_present = if let Some(certificates) = &self.certificates {
        //     certificates.iter().any(|certificate| match certificate {
        //         CertificateChoices::V1AttrCert(_) => true,
        //         _ => false,
        //     })
        // } else {
        //     false
        // };
        let v2_certificates_are_present = false;
        let v1_certificates_are_present = false;
        let other_crls_are_present = if let Some(crls) = &self.crls {
            crls.iter().any(|revocation_info_choice| {
                matches!(revocation_info_choice, RevocationInfoChoice::Other(_))
            })
        } else {
            false
        };
        let v3_signer_infos_present = self
            .signer_infos
            .iter()
            .any(|signer_info| signer_info.version == CmsVersion::V3);
        let content_not_data =
            self.encapsulated_content_info.econtent_type != const_oid::db::rfc5911::ID_DATA;

        if other_certificates_are_present || other_crls_are_present {
            CmsVersion::V5
        } else if v2_certificates_are_present {
            CmsVersion::V4
        } else if v1_certificates_are_present || v3_signer_infos_present || content_not_data {
            CmsVersion::V3
        } else {
            CmsVersion::V1
        }
    }
}

/// Trait for builders of a `RecipientInfo`. RFC 5652 § 6 defines 5 different `RecipientInfo`
/// formats. All implementations must implement this trait.
pub trait RecipientInfoBuilder {
    /// Return the recipient info type
    fn recipient_info_type(&self) -> RecipientInfoType;

    /// Return the recipient info version
    fn recipient_info_version(&self) -> CmsVersion;

    /// Encrypt the `content_encryption_key` using a method, that is specific for the implementing
    /// builder type. Finally return a `RecipientInfo`.
    fn build(&mut self, content_encryption_key: &[u8]) -> Result<RecipientInfo>;
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
    Rsa(rsa::RsaPublicKey),
    // to be extended here with other asymmetric encryption algorithms
}

/// Builds a `KeyTransRecipientInfo` according to RFC 5652 § 6.
/// This type uses the recipient's public key to encrypt the content-encryption key.
pub struct KeyTransRecipientInfoBuilder<'a, R>
where
    R: CryptoRngCore,
{
    /// Identifies the recipient
    pub rid: RecipientIdentifier,
    /// Info for key encryption
    pub key_encryption_info: KeyEncryptionInfo,
    /// Rng
    rng: &'a mut R,
}

impl<'a, R> KeyTransRecipientInfoBuilder<'a, R>
where
    R: CryptoRngCore,
{
    /// Creates a `KeyTransRecipientInfoBuilder`
    pub fn new(
        rid: RecipientIdentifier,
        key_encryption_info: KeyEncryptionInfo,
        rng: &'a mut R,
    ) -> Result<KeyTransRecipientInfoBuilder<'a, R>> {
        Ok(KeyTransRecipientInfoBuilder {
            rid,
            key_encryption_info,
            rng,
        })
    }
}

impl<'a, R> RecipientInfoBuilder for KeyTransRecipientInfoBuilder<'a, R>
where
    R: CryptoRngCore,
{
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
    fn build(&mut self, content_encryption_key: &[u8]) -> Result<RecipientInfo> {
        // Encrypt key
        let (encrypted_key, key_enc_alg) = match &self.key_encryption_info {
            // RSA encryption
            KeyEncryptionInfo::Rsa(recipient_public_key) => (
                recipient_public_key
                    .encrypt(self.rng, Pkcs1v15Encrypt, content_encryption_key)
                    .map_err(|_| Error::Builder(String::from("Could not encrypt key")))?,
                AlgorithmIdentifierOwned {
                    oid: const_oid::db::rfc5912::RSA_ENCRYPTION,
                    parameters: None,
                },
            ),
        };
        let enc_key = EncryptedKey::new(encrypted_key)?;

        Ok(RecipientInfo::Ktri(KeyTransRecipientInfo {
            version: self.recipient_info_version(),
            rid: self.rid.clone(),
            key_enc_alg,
            enc_key,
        }))
    }
}

/// Builds a `KeyAgreeRecipientInfo` according to RFC 5652 § 6.
/// This type uses key agreement:  the recipient's public key and the sender's
/// private key are used to generate a pairwise symmetric key, then
/// the content-encryption key is encrypted in the pairwise symmetric key.
pub struct KeyAgreeRecipientInfoBuilder {
    /// A CHOICE with three alternatives specifying the sender's key agreement public key.
    pub originator: OriginatorIdentifierOrKey,
    /// Optional information which helps generating different keys every time.
    pub ukm: Option<UserKeyingMaterial>,
    /// Encryption algorithm to be used for key encryption
    pub key_enc_alg: AlgorithmIdentifierOwned,
}

impl KeyAgreeRecipientInfoBuilder {
    /// Creates a `KeyAgreeRecipientInfoBuilder`
    pub fn new(
        originator: OriginatorIdentifierOrKey,
        ukm: Option<UserKeyingMaterial>,
        key_enc_alg: AlgorithmIdentifierOwned,
    ) -> Result<KeyAgreeRecipientInfoBuilder> {
        Ok(KeyAgreeRecipientInfoBuilder {
            originator,
            ukm,
            key_enc_alg,
        })
    }
}

impl RecipientInfoBuilder for KeyAgreeRecipientInfoBuilder {
    /// Returns the RecipientInfoType
    fn recipient_info_type(&self) -> RecipientInfoType {
        RecipientInfoType::Kari
    }

    /// Returns the `CMSVersion` for this `RecipientInfo`
    fn recipient_info_version(&self) -> CmsVersion {
        CmsVersion::V3
    }

    /// Build a `KeyAgreeRecipientInfoBuilder`. See RFC 5652 § 6.2.1
    fn build(&mut self, _content_encryption_key: &[u8]) -> Result<RecipientInfo> {
        Err(Error::Builder(String::from(
            "Building KeyAgreeRecipientInfo is not implemented, yet.",
        )))
    }
}

/// Builds a `KekRecipientInfo` according to RFC 5652 § 6.
/// Uses symmetric key-encryption keys: the content-encryption key is
/// encrypted in a previously distributed symmetric key-encryption key.
pub struct KekRecipientInfoBuilder {
    /// Specifies a symmetric key-encryption key that was previously distributed to the sender and
    /// one or more recipients.
    pub kek_id: KekIdentifier,
    /// Encryption algorithm to be used for key encryption
    pub key_enc_alg: AlgorithmIdentifierOwned,
}

impl KekRecipientInfoBuilder {
    /// Creates a `KekRecipientInfoBuilder`
    pub fn new(
        kek_id: KekIdentifier,
        key_enc_alg: AlgorithmIdentifierOwned,
    ) -> Result<KekRecipientInfoBuilder> {
        Ok(KekRecipientInfoBuilder {
            kek_id,
            key_enc_alg,
        })
    }
}

impl RecipientInfoBuilder for KekRecipientInfoBuilder {
    /// Returns the RecipientInfoType
    fn recipient_info_type(&self) -> RecipientInfoType {
        RecipientInfoType::Kekri
    }

    /// Returns the `CMSVersion` for this `RecipientInfo`
    fn recipient_info_version(&self) -> CmsVersion {
        CmsVersion::V4
    }

    /// Build a `KekRecipientInfoBuilder`. See RFC 5652 § 6.2.1
    fn build(&mut self, _content_encryption_key: &[u8]) -> Result<RecipientInfo> {
        Err(Error::Builder(String::from(
            "Building KekRecipientInfo is not implemented, yet.",
        )))
    }
}

/// Builds a `PasswordRecipientInfo` according to RFC 5652 § 6.
/// Uses a password or shared secret value to encrypt the content-encryption key.
pub struct PasswordRecipientInfoBuilder {
    /// Identifies the key-derivation algorithm, and any associated parameters, used to derive the
    /// key-encryption key from the password or shared secret value. If this field is `None`,
    /// the key-encryption key is supplied from an external source, for example a hardware crypto
    /// token such as a smart card.
    pub key_derivation_alg: Option<AlgorithmIdentifierOwned>,
    /// Encryption algorithm to be used for key encryption
    pub key_enc_alg: AlgorithmIdentifierOwned,
}

impl PasswordRecipientInfoBuilder {
    /// Creates a `PasswordRecipientInfoBuilder`
    pub fn new(
        key_derivation_alg: Option<AlgorithmIdentifierOwned>,
        key_enc_alg: AlgorithmIdentifierOwned,
    ) -> Result<PasswordRecipientInfoBuilder> {
        Ok(PasswordRecipientInfoBuilder {
            key_derivation_alg,
            key_enc_alg,
        })
    }
}

impl RecipientInfoBuilder for PasswordRecipientInfoBuilder {
    /// Returns the RecipientInfoType
    fn recipient_info_type(&self) -> RecipientInfoType {
        RecipientInfoType::Pwri
    }

    /// Returns the `CMSVersion` for this `RecipientInfo`
    fn recipient_info_version(&self) -> CmsVersion {
        CmsVersion::V0
    }

    /// Build a `PasswordRecipientInfoBuilder`. See RFC 5652 § 6.2.1
    fn build(&mut self, _content_encryption_key: &[u8]) -> Result<RecipientInfo> {
        Err(Error::Builder(String::from(
            "Building PasswordRecipientInfo is not implemented, yet.",
        )))
    }
}

/// Builds an `OtherRecipientInfo` according to RFC 5652 § 6.
/// This type makes no assumption about the encryption method or the needed information.
pub struct OtherRecipientInfoBuilder {
    /// Identifies the key management technique.
    pub ori_type: ObjectIdentifier,
    /// Contains the protocol data elements needed by a recipient using the identified key
    /// management technique
    pub ori_value: Any,
}

impl OtherRecipientInfoBuilder {
    /// Creates a `OtherRecipientInfoBuilder`
    pub fn new(ori_type: ObjectIdentifier, ori_value: Any) -> Result<OtherRecipientInfoBuilder> {
        Ok(OtherRecipientInfoBuilder {
            ori_type,
            ori_value,
        })
    }
}

impl RecipientInfoBuilder for OtherRecipientInfoBuilder {
    /// Returns the RecipientInfoType
    fn recipient_info_type(&self) -> RecipientInfoType {
        RecipientInfoType::Ori
    }

    /// Returns the `CMSVersion` for this `RecipientInfo`
    fn recipient_info_version(&self) -> CmsVersion {
        panic!("Ori has no CMSVersion")
    }

    /// Build a `OtherRecipientInfoBuilder`. See RFC 5652 § 6.2.1
    fn build(&mut self, _content_encryption_key: &[u8]) -> Result<RecipientInfo> {
        panic!("Ori has no common build method.")
    }
}

/// Supported content encryption algorithms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentEncryptionAlgorithm {
    /// AES-128 CBC
    Aes128Cbc,
    /// AES-192 CBC
    Aes192Cbc,
    /// AES-256 CBC
    Aes256Cbc,
}

impl ContentEncryptionAlgorithm {
    /// Return the OID of the algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            ContentEncryptionAlgorithm::Aes128Cbc => const_oid::db::rfc5911::ID_AES_128_CBC,
            ContentEncryptionAlgorithm::Aes192Cbc => const_oid::db::rfc5911::ID_AES_192_CBC,
            ContentEncryptionAlgorithm::Aes256Cbc => const_oid::db::rfc5911::ID_AES_256_CBC,
        }
    }
}

/// Builds CMS `EnvelopedData` according to RFC 5652 § 6.
pub struct EnvelopedDataBuilder<'c> {
    originator_info: Option<OriginatorInfo>,
    recipient_infos: Vec<Box<dyn RecipientInfoBuilder + 'c>>,
    unencrypted_content: &'c [u8],
    // TODO bk Not good to offer both, `content_encryptor` and `content_encryption_algorithm`.
    // We should
    // (1) either derive `content_encryption_algorithm` from `content_encryptor` (but this is not
    //            yet supported by RustCrypto),
    // (2) or     pass `content_encryption_algorithm` and create an encryptor for it.
    // In the first case, we might need a new trait here, e.g. `DynEncryptionAlgorithmIdentifier` in
    // analogy to `DynSignatureAlgorithmIdentifier`.
    // Going for (2)
    //  content_encryptor: E,
    content_encryption_algorithm: ContentEncryptionAlgorithm,
    unprotected_attributes: Option<Attributes>,
}

impl<'c> EnvelopedDataBuilder<'c> {
    /// Create a new builder for `EnvelopedData`
    pub fn new(
        originator_info: Option<OriginatorInfo>,
        unencrypted_content: &'c [u8],
        content_encryption_algorithm: ContentEncryptionAlgorithm,
        unprotected_attributes: Option<Attributes>,
    ) -> Result<EnvelopedDataBuilder<'c>> {
        Ok(EnvelopedDataBuilder {
            originator_info,
            recipient_infos: Vec::new(),
            unencrypted_content,
            content_encryption_algorithm,
            unprotected_attributes,
        })
    }

    /// Add recipient info. A builder is used, which generates a `RecipientInfo` according to
    /// RFC 5652 § 6.2, when `EnvelopedData` is built.
    pub fn add_recipient_info(
        &mut self,
        recipient_info_builder: impl RecipientInfoBuilder + 'c,
    ) -> Result<&mut Self> {
        self.recipient_infos.push(Box::new(recipient_info_builder));

        Ok(self)
    }

    /// Generate an `EnvelopedData` object according to RFC 5652 § 6 using a provided
    /// random number generator.
    pub fn build_with_rng(&mut self, rng: &mut impl CryptoRngCore) -> Result<EnvelopedData> {
        // Generate content encryption key
        // Encrypt content
        // Build recipient infos
        // Make sure, content encryption key is securely destroyed
        let (encrypted_content, mut content_encryption_key, content_enc_alg) = encrypt_data(
            self.unencrypted_content,
            &self.content_encryption_algorithm,
            None,
            rng,
        )?;
        let encrypted_content_octetstring = der::asn1::OctetString::new(encrypted_content)?;
        let encrypted_content_info = EncryptedContentInfo {
            content_type: const_oid::db::rfc5911::ID_DATA, // TODO bk should this be configurable?
            content_enc_alg,
            encrypted_content: Some(encrypted_content_octetstring), // TODO bk `None` (external content) should also be possible
        };

        let recipient_infos_vec = self
            .recipient_infos
            .iter_mut()
            .map(|ri| ri.build(&content_encryption_key))
            .collect::<Result<Vec<RecipientInfo>>>()?;
        content_encryption_key.zeroize();
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

/// Get a hasher for a given digest algorithm
fn get_hasher(
    digest_algorithm_identifier: &AlgorithmIdentifierOwned,
) -> Option<Box<dyn DynDigest>> {
    let digest_name = DB.by_oid(&digest_algorithm_identifier.oid)?;
    match digest_name {
        "id-sha1" => Some(Box::new(sha1::Sha1::new())),
        "id-sha256" => Some(Box::new(sha2::Sha256::new())),
        "id-sha384" => Some(Box::new(sha2::Sha384::new())),
        "id-sha512" => Some(Box::new(sha2::Sha512::new())),
        "id-sha224" => Some(Box::new(sha2::Sha224::new())),
        "id-sha-3-224" => Some(Box::new(sha3::Sha3_224::new())),
        "id-sha-3-256" => Some(Box::new(sha3::Sha3_256::new())),
        "id-sha-3-384" => Some(Box::new(sha3::Sha3_384::new())),
        "id-sha-3-512" => Some(Box::new(sha3::Sha3_512::new())),
        _ => None,
    }
}

/// Helps encrypting.
macro_rules! encrypt_block_mode {
    ($data:expr, $block_mode:ident::$typ:ident<$alg:ident>, $key:expr, $rng:expr, $oid:expr) => {{
        let (key, iv) = match $key {
            None => $block_mode::$typ::<$alg>::generate_key_iv_with_rng($rng)?,
            Some(key) => {
                if key.len() != $alg::key_size() {
                    return Err(Error::Builder(String::from(
                        "Invalid key size for chosen algorithm",
                    )));
                }
                (
                    Key::<$block_mode::$typ<$alg>>::try_from(key)
                        .expect("size invariants violation"),
                    $block_mode::$typ::<$alg>::generate_iv_with_rng($rng)?,
                )
            }
        };
        let encryptor = $block_mode::$typ::<$alg>::new(&key.into(), &iv.into());
        Ok((
            encryptor.encrypt_padded_vec::<Pkcs7>($data),
            key.to_vec(),
            AlgorithmIdentifierOwned {
                oid: $oid,
                parameters: Some(Any::new(OctetString, iv.to_vec())?),
            },
        ))
    }};
}

/// Symmetrically encrypt data.
/// Returns encrypted content, content-encryption key and the used algorithm identifier (including
/// the used algorithm parameters).
///
/// TODO Which encryption algorithms shall also be supported?
fn encrypt_data<R>(
    data: &[u8],
    encryption_algorithm_identifier: &ContentEncryptionAlgorithm,
    key: Option<&[u8]>,
    rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>, AlgorithmIdentifierOwned)>
where
    R: CryptoRng + RngCore,
{
    match encryption_algorithm_identifier {
        ContentEncryptionAlgorithm::Aes128Cbc => encrypt_block_mode!(
            data,
            cbc::Encryptor<Aes128>,
            key,
            rng,
            encryption_algorithm_identifier.oid()
        ),
        ContentEncryptionAlgorithm::Aes192Cbc => encrypt_block_mode!(
            data,
            cbc::Encryptor<Aes192>,
            key,
            rng,
            encryption_algorithm_identifier.oid()
        ),
        ContentEncryptionAlgorithm::Aes256Cbc => encrypt_block_mode!(
            data,
            cbc::Encryptor<Aes256>,
            key,
            rng,
            encryption_algorithm_identifier.oid()
        ),
    }
}

/// Create a content-type attribute according to
/// [RFC 5652 § 11.1](https://datatracker.ietf.org/doc/html/rfc5652#section-11.1)
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
/// [RFC 5652 § 11.2](https://datatracker.ietf.org/doc/html/rfc5652#section-11.2)
pub fn create_message_digest_attribute(message_digest: &[u8]) -> Result<Attribute> {
    let message_digest_der = OctetStringRef::new(message_digest)?;
    let message_digest_attribute_value =
        AttributeValue::new(OctetString, message_digest_der.as_bytes())?;
    let mut values = SetOfVec::new();
    values.insert(message_digest_attribute_value)?;
    let attribute = Attribute {
        oid: const_oid::db::rfc5911::ID_MESSAGE_DIGEST,
        values,
    };
    Ok(attribute)
}

/// Create a signing time attribute according to
/// [RFC 5652 § 11.3](https://datatracker.ietf.org/doc/html/rfc5652#section-11.3)
/// Dates between 1 January 1950 and 31 December 2049 (inclusive) MUST be
/// encoded as UTCTime.  Any dates with year values before 1950 or after
/// 2049 MUST be encoded as GeneralizedTime.
pub fn create_signing_time_attribute() -> Result<Attribute> {
    let now = DateTime::from_system_time(SystemTime::now())?;
    let tag = if now.year() < 1950 || now.year() > 2049 {
        Tag::GeneralizedTime
    } else {
        Tag::UtcTime
    };
    // let mut signing_time_buf = Vec::new();
    let time_der = if tag == Tag::GeneralizedTime {
        // der::asn1::GeneralizedTime::from_date_time(now).encode_to_vec(&mut signing_time_buf)?;
        der::asn1::GeneralizedTime::from_date_time(now).to_der()?
    } else {
        // der::asn1::UtcTime::from_date_time(now)?.encode_to_vec(&mut signing_time_buf)?;
        der::asn1::UtcTime::from_date_time(now)?.to_der()?
    };
    let signing_time_attribute_value = AttributeValue::from_der(&time_der)?;
    let mut values = SetOfVec::<AttributeValue>::new();
    values.insert(signing_time_attribute_value)?;
    let attribute = Attribute {
        oid: const_oid::db::rfc5911::ID_SIGNING_TIME,
        values,
    };
    Ok(attribute)
}
