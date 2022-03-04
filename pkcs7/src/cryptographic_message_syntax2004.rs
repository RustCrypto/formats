//! Selected structures from RFC5652

use core::cmp::Ordering;
use der::asn1::{BitString, OctetString, SetOf, SetOfVec, UIntBytes};
use der::{Any, Choice, Decodable, Sequence, ValueOrd};
use spki::{AlgorithmIdentifier, ObjectIdentifier};
use x509::attr::AttributeTypeAndValue;
use x509::ext::pkix::SubjectKeyIdentifier;
use x509::name::Name;

// Use 2004 suffix to distinguish from the enum in content_type.rs
/// ContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   content \[0\] EXPLICIT ANY DEFINED BY contentType }
#[derive(Clone, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ContentInfo2004<'a> {
    pub content_type: ObjectIdentifier,

    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub content: Any<'a>,
}

/// SignedData ::= SEQUENCE {
///   version CMSVersion,
///   digestAlgorithms DigestAlgorithmIdentifiers,
///   encapContentInfo EncapsulatedContentInfo,
///   certificates \[0\] IMPLICIT CertificateSet OPTIONAL,
///   crls \[1\] IMPLICIT RevocationInfoChoices OPTIONAL,
///   signerInfos SignerInfos }
#[derive(Clone, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct SignedData<'a> {
    pub version: u8,
    pub digest_algorithms: DigestAlgorithmIdentifiers<'a>,
    pub encap_content_info: EncapsulatedContentInfo<'a>,

    // Using Any as a means of deferring most of the decoding of the certificates (will still need
    // to call to_vec on the resulting Any to restore tag and length values).
    ///   certificates \[0\] IMPLICIT CertificateSet OPTIONAL,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub certificates: Option<alloc::vec::Vec<Any<'a>>>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub crls: Option<alloc::vec::Vec<Any<'a>>>,

    pub signer_infos: SetOfVec<SignerInfo<'a>>,
}

/// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
pub type DigestAlgorithmIdentifiers<'a> = SetOfVec<ObjectIdentifier>;

/// EncapsulatedContentInfo ::= SEQUENCE {
///   eContentType ContentType,
///   eContent \[0\] EXPLICIT OCTET STRING OPTIONAL }
#[derive(Clone, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EncapsulatedContentInfo<'a> {
    pub econtent_type: ObjectIdentifier,

    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub econtent: Option<OctetString<'a>>,
}

// ContentType ::= OBJECT IDENTIFIER

/// SignerInfo ::= SEQUENCE {
///   version CMSVersion,
///   sid SignerIdentifier,
///   digestAlgorithm DigestAlgorithmIdentifier,
///   signedAttrs \[0\] IMPLICIT SignedAttributes OPTIONAL,
///   signatureAlgorithm SignatureAlgorithmIdentifier,
///   signature SignatureValue,
///   unsignedAttrs \[1\] IMPLICIT UnsignedAttributes OPTIONAL }
#[derive(Clone, Eq, PartialEq, PartialOrd, Sequence)]
#[allow(missing_docs)]
pub struct SignerInfo<'a> {
    pub version: u8,
    pub sid: SignerIdentifier<'a>,
    pub digest_algorithm: AlgorithmIdentifier<'a>,
    pub signed_attrs: SignedAttributes<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature: BitString<'a>,
    pub unsigned_attrs: UnsignedAttributes<'a>,
}
impl ValueOrd for SignerInfo<'_> {
    fn value_cmp(&self, _other: &Self) -> der::Result<Ordering> {
        todo!()
    }
}

/// SignerIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier \[0\] SubjectKeyIdentifier }
#[derive(Clone, Eq, PartialEq, PartialOrd, Choice)]
#[allow(missing_docs)]
pub enum SignerIdentifier<'a> {
    IssuerAndSerialNumber(IssuerAndSerialNumber<'a>),

    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    SubjectKeyIdentifier(SubjectKeyIdentifier<'a>),
}

/// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
pub type SignedAttributes<'a> = SetOf<AttributeTypeAndValue<'a>, 10>;

/// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
pub type UnsignedAttributes<'a> = SetOf<AttributeTypeAndValue<'a>, 10>;

/*
   Attribute ::= SEQUENCE {
     attrType OBJECT IDENTIFIER,
     attrValues SET OF AttributeValue }

   AttributeValue ::= ANY

   SignatureValue ::= OCTET STRING

   EnvelopedData ::= SEQUENCE {
     version CMSVersion,
     originatorInfo \[0\] IMPLICIT OriginatorInfo OPTIONAL,
     recipientInfos RecipientInfos,
     encryptedContentInfo EncryptedContentInfo,
     unprotectedAttrs \[1\] IMPLICIT UnprotectedAttributes OPTIONAL }

   OriginatorInfo ::= SEQUENCE {
     certs \[0\] IMPLICIT CertificateSet OPTIONAL,
     crls \[1\] IMPLICIT RevocationInfoChoices OPTIONAL }

   RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

   EncryptedContentInfo ::= SEQUENCE {
     contentType ContentType,
     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
     encryptedContent \[0\] IMPLICIT EncryptedContent OPTIONAL }

   EncryptedContent ::= OCTET STRING

   UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute

   RecipientInfo ::= CHOICE {
     ktri KeyTransRecipientInfo,
     kari \[1\] KeyAgreeRecipientInfo,
     kekri \[2\] KEKRecipientInfo,
     pwri \[3\] PasswordRecipientInfo,
     ori \[4\] OtherRecipientInfo }

   EncryptedKey ::= OCTET STRING

   KeyTransRecipientInfo ::= SEQUENCE {
     version CMSVersion,  -- always set to 0 or 2
     rid RecipientIdentifier,
     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
     encryptedKey EncryptedKey }

   RecipientIdentifier ::= CHOICE {
     issuerAndSerialNumber IssuerAndSerialNumber,
     subjectKeyIdentifier \[0\] SubjectKeyIdentifier }

   KeyAgreeRecipientInfo ::= SEQUENCE {
     version CMSVersion,  -- always set to 3
     originator \[0\] EXPLICIT OriginatorIdentifierOrKey,
     ukm \[1\] EXPLICIT UserKeyingMaterial OPTIONAL,
     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
     recipientEncryptedKeys RecipientEncryptedKeys }

   OriginatorIdentifierOrKey ::= CHOICE {
     issuerAndSerialNumber IssuerAndSerialNumber,
     subjectKeyIdentifier \[0\] SubjectKeyIdentifier,
     originatorKey \[1\] OriginatorPublicKey }

   OriginatorPublicKey ::= SEQUENCE {
     algorithm AlgorithmIdentifier,
     publicKey BIT STRING }

   RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey

   RecipientEncryptedKey ::= SEQUENCE {
     rid KeyAgreeRecipientIdentifier,
     encryptedKey EncryptedKey }

   KeyAgreeRecipientIdentifier ::= CHOICE {
     issuerAndSerialNumber IssuerAndSerialNumber,
     rKeyId \[0\] IMPLICIT RecipientKeyIdentifier }

   RecipientKeyIdentifier ::= SEQUENCE {
     subjectKeyIdentifier SubjectKeyIdentifier,
     date GeneralizedTime OPTIONAL,
     other OtherKeyAttribute OPTIONAL }

   SubjectKeyIdentifier ::= OCTET STRING

   KEKRecipientInfo ::= SEQUENCE {
     version CMSVersion,  -- always set to 4
     kekid KEKIdentifier,
     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
     encryptedKey EncryptedKey }

   KEKIdentifier ::= SEQUENCE {
     keyIdentifier OCTET STRING,
     date GeneralizedTime OPTIONAL,
     other OtherKeyAttribute OPTIONAL }

   PasswordRecipientInfo ::= SEQUENCE {
     version CMSVersion,   -- always set to 0
     keyDerivationAlgorithm \[0\] KeyDerivationAlgorithmIdentifier
                                OPTIONAL,
     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
     encryptedKey EncryptedKey }

   OtherRecipientInfo ::= SEQUENCE {
     oriType OBJECT IDENTIFIER,
     oriValue ANY DEFINED BY oriType }

   DigestedData ::= SEQUENCE {
     version CMSVersion,
     digestAlgorithm DigestAlgorithmIdentifier,
     encapContentInfo EncapsulatedContentInfo,
     digest Digest }

   Digest ::= OCTET STRING

   EncryptedData ::= SEQUENCE {
     version CMSVersion,
     encryptedContentInfo EncryptedContentInfo,
     unprotectedAttrs \[1\] IMPLICIT UnprotectedAttributes OPTIONAL }

   AuthenticatedData ::= SEQUENCE {
     version CMSVersion,
     originatorInfo \[0\] IMPLICIT OriginatorInfo OPTIONAL,
     recipientInfos RecipientInfos,
     macAlgorithm MessageAuthenticationCodeAlgorithm,
     digestAlgorithm \[1\] DigestAlgorithmIdentifier OPTIONAL,
     encapContentInfo EncapsulatedContentInfo,
     authAttrs \[2\] IMPLICIT AuthAttributes OPTIONAL,
     mac MessageAuthenticationCode,
     unauthAttrs \[3\] IMPLICIT UnauthAttributes OPTIONAL }

   AuthAttributes ::= SET SIZE (1..MAX) OF Attribute

   UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute

   MessageAuthenticationCode ::= OCTET STRING

   DigestAlgorithmIdentifier ::= AlgorithmIdentifier

   SignatureAlgorithmIdentifier ::= AlgorithmIdentifier

   KeyEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier

   ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier

   MessageAuthenticationCodeAlgorithm ::= AlgorithmIdentifier

   KeyDerivationAlgorithmIdentifier ::= AlgorithmIdentifier

   RevocationInfoChoices ::= SET OF RevocationInfoChoice

   RevocationInfoChoice ::= CHOICE {
     crl CertificateList,
     other \[1\] IMPLICIT OtherRevocationInfoFormat }

   OtherRevocationInfoFormat ::= SEQUENCE {
     otherRevInfoFormat OBJECT IDENTIFIER,
     otherRevInfo ANY DEFINED BY otherRevInfoFormat }

   CertificateChoices ::= CHOICE {
     certificate Certificate,
     extendedCertificate \[0\] IMPLICIT ExtendedCertificate,  -- Obsolete
     v1AttrCert \[1\] IMPLICIT AttributeCertificateV1,        -- Obsolete
     v2AttrCert \[2\] IMPLICIT AttributeCertificateV2,
     other \[3\] IMPLICIT OtherCertificateFormat }

   AttributeCertificateV2 ::= AttributeCertificate

   OtherCertificateFormat ::= SEQUENCE {
     otherCertFormat OBJECT IDENTIFIER,
     otherCert ANY DEFINED BY otherCertFormat }

   CertificateSet ::= SET OF CertificateChoices
*/

/// IssuerAndSerialNumber ::= SEQUENCE {
///   issuer Name,
///   serialNumber CertificateSerialNumber }
#[derive(Clone, Eq, PartialEq, PartialOrd, Sequence)]
pub struct IssuerAndSerialNumber<'a> {
    ///   issuer Name,
    pub issuer: Name<'a>,
    ///   serialNumber CertificateSerialNumber }
    pub serial_number: UIntBytes<'a>,
}

/*
  CMSVersion ::= INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }

  UserKeyingMaterial ::= OCTET STRING

  OtherKeyAttribute ::= SEQUENCE {
    keyAttrId OBJECT IDENTIFIER,
    keyAttr ANY DEFINED BY keyAttrId OPTIONAL }

  -- Content Type Object Identifiers

  id-ct-contentInfo OBJECT IDENTIFIER ::= { iso(1) member-body(2)
      us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-ct(1) 6 }

  id-data OBJECT IDENTIFIER ::= { iso(1) member-body(2)
      us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1 }

  id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
      us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }

  id-envelopedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
      us(840) rsadsi(113549) pkcs(1) pkcs7(7) 3 }

  id-digestedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
      us(840) rsadsi(113549) pkcs(1) pkcs7(7) 5 }

  id-encryptedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
      us(840) rsadsi(113549) pkcs(1) pkcs7(7) 6 }

  id-ct-authData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
      us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-ct(1) 2 }

  -- The CMS Attributes

  MessageDigest ::= OCTET STRING

  SigningTime  ::= Time

  Time ::= CHOICE {
    utcTime UTCTime,
    generalTime GeneralizedTime }

  Countersignature ::= SignerInfo

  -- Attribute Object Identifiers

  id-contentType OBJECT IDENTIFIER ::= { iso(1) member-body(2)
      us(840) rsadsi(113549) pkcs(1) pkcs-9(9) 3 }

  id-messageDigest OBJECT IDENTIFIER ::= { iso(1) member-body(2)
      us(840) rsadsi(113549) pkcs(1) pkcs-9(9) 4 }

  id-signingTime OBJECT IDENTIFIER ::= { iso(1) member-body(2)
      us(840) rsadsi(113549) pkcs(1) pkcs-9(9) 5 }

  id-countersignature OBJECT IDENTIFIER ::= { iso(1) member-body(2)
      us(840) rsadsi(113549) pkcs(1) pkcs-9(9) 6 }

  -- Obsolete Extended Certificate syntax from PKCS #6

  ExtendedCertificateOrCertificate ::= CHOICE {
    certificate Certificate,
    extendedCertificate \[0\] IMPLICIT ExtendedCertificate }

  ExtendedCertificate ::= SEQUENCE {
    extendedCertificateInfo ExtendedCertificateInfo,
    signatureAlgorithm SignatureAlgorithmIdentifier,
    signature Signature }

  ExtendedCertificateInfo ::= SEQUENCE {
    version CMSVersion,
    certificate Certificate,
    attributes UnauthAttributes }

  Signature ::= BIT STRING

  END -- of CryptographicMessageSyntax2004
*/
