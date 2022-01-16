//! Selected structures from RFC5652

use der::asn1::{BitString, ContextSpecific, SetOf, UIntBytes};
use der::{
    Any, DecodeValue, Decoder, Encodable, EncodeValue, ErrorKind, FixedTag, Length, Tag, TagMode,
    TagNumber,
};
use der::{OrdIsValueOrd, Sequence};
use spki::{AlgorithmIdentifier, ObjectIdentifier};
use x509::{AttributeTypeAndValue, Name, SubjectKeyIdentifier};

/// ContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   content [0] EXPLICIT ANY DEFINED BY contentType }
#[derive(Clone, Eq, PartialEq)]
pub struct ContentInfo2004<'a> {
    ///   contentType ContentType,
    pub content_type: ObjectIdentifier,
    ///   content [0] EXPLICIT ANY DEFINED BY contentType }
    pub content: Option<Any<'a>>,
}

const CONTENT_TAG: TagNumber = TagNumber::new(0);

impl<'a> ::der::Decodable<'a> for ContentInfo2004<'a> {
    fn decode(decoder: &mut ::der::Decoder<'a>) -> ::der::Result<Self> {
        decoder.sequence(|decoder| {
            let content_type = decoder.decode()?;
            //let content = decoder.decode()?;
            let content =
                ::der::asn1::ContextSpecific::decode_explicit(decoder, ::der::TagNumber::N0)?
                    .map(|cs| cs.value);
            Ok(Self {
                content_type,
                content,
            })
        })
    }
}
impl<'a> ::der::Sequence<'a> for ContentInfo2004<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        f(&[
            &self.content_type,
            &self.content.as_ref().map(|content| ContextSpecific {
                tag_number: CONTENT_TAG,
                tag_mode: TagMode::Explicit,
                value: *content,
            }),
        ])
    }
}

/// ContentType ::= OBJECT IDENTIFIER
pub type ContentType = ObjectIdentifier;

/// SignedData ::= SEQUENCE {
///   version CMSVersion,
///   digestAlgorithms DigestAlgorithmIdentifiers,
///   encapContentInfo EncapsulatedContentInfo,
///   certificates [0] IMPLICIT CertificateSet OPTIONAL,
///   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///   signerInfos SignerInfos }
#[derive(Clone, Eq, PartialEq)]
pub struct SignedData<'a> {
    ///   version CMSVersion,
    pub version: u8,
    ///   digestAlgorithms DigestAlgorithmIdentifiers,
    pub digest_algorithms: DigestAlgorithmIdentifiers<'a>,
    ///   encapContentInfo EncapsulatedContentInfo,
    pub encap_content_info: EncapsulatedContentInfo<'a>,
    // Using Any as a means of deferring most of the decoding of the certificates (will still need
    // to call to_vec on the resulting Any to restore tag and length values).
    ///   certificates [0] IMPLICIT CertificateSet OPTIONAL,
    pub certificates: Option<alloc::vec::Vec<Any<'a>>>,
    // TODO support CRLs
    //   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
    //pub crls: SetOf<RevocationInfoChoices<'a>, 10>,
    ///   signerInfos SignerInfos }
    pub signer_infos: SetOf<SignerInfo<'a>, 10>,
}
const CERTIFICATES_TAG: TagNumber = TagNumber::new(0);

impl<'a> ::der::Decodable<'a> for SignedData<'a> {
    fn decode(decoder: &mut ::der::Decoder<'a>) -> ::der::Result<Self> {
        decoder.sequence(|decoder| {
            let version = decoder.decode()?;
            let digest_algorithms = decoder.decode()?;
            let encap_content_info = decoder.decode()?;
            //let certificates = decoder.decode()?;
            let certificates =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N0)?
                    .map(|cs| cs.value);
            let signer_infos = decoder.decode()?;
            Ok(Self {
                version,
                digest_algorithms,
                encap_content_info,
                certificates,
                signer_infos,
            })
        })
    }
}

impl<'a> ::der::Sequence<'a> for SignedData<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        f(&[
            &self.version,
            &self.digest_algorithms,
            &self.encap_content_info,
            &self
                .certificates
                .as_ref()
                .map(|certificates| ContextSpecific {
                    tag_number: CERTIFICATES_TAG,
                    tag_mode: TagMode::Implicit,
                    value: certificates.clone(),
                }),
            &self.signer_infos,
        ])
    }
}

/// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
pub type DigestAlgorithmIdentifiers<'a> = SetOf<ObjectIdentifier, 3>;
// TODO - make dynamic

/*
   SignerInfos ::= SET OF SignerInfo
*/

/// EncapsulatedContentInfo ::= SEQUENCE {
///   eContentType ContentType,
///   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
#[derive(Clone, Eq, PartialEq)]
pub struct EncapsulatedContentInfo<'a> {
    ///   eContentType ContentType,
    pub econtent_type: ObjectIdentifier,
    ///   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
    pub econtent: Option<Any<'a>>,
}
const ECONTENT_TAG: TagNumber = TagNumber::new(0);

impl<'a> ::der::Decodable<'a> for EncapsulatedContentInfo<'a> {
    fn decode(decoder: &mut ::der::Decoder<'a>) -> ::der::Result<Self> {
        decoder.sequence(|decoder| {
            let econtent_type = decoder.decode()?;
            // let econtent = decoder.decode()?;
            let econtent =
                ::der::asn1::ContextSpecific::decode_explicit(decoder, ::der::TagNumber::N0)?
                    .map(|cs| cs.value);
            Ok(Self {
                econtent_type,
                econtent,
            })
        })
    }
}
impl<'a> ::der::Sequence<'a> for EncapsulatedContentInfo<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        f(&[
            &self.econtent_type,
            &self.econtent.as_ref().map(|econtent| ContextSpecific {
                tag_number: ECONTENT_TAG,
                tag_mode: TagMode::Explicit,
                value: *econtent,
            }),
        ])
    }
}

/// SignerInfo ::= SEQUENCE {
///   version CMSVersion,
///   sid SignerIdentifier,
///   digestAlgorithm DigestAlgorithmIdentifier,
///   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///   signatureAlgorithm SignatureAlgorithmIdentifier,
///   signature SignatureValue,
///   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Sequence)]
pub struct SignerInfo<'a> {
    ///   version CMSVersion,
    pub version: u8,
    ///   sid SignerIdentifier,
    pub sid: SignerIdentifier<'a>,
    ///   digestAlgorithm DigestAlgorithmIdentifier,
    pub digest_algorithm: AlgorithmIdentifier<'a>,
    ///   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
    pub signed_attrs: SignedAttributes<'a>,
    ///   signatureAlgorithm SignatureAlgorithmIdentifier,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    ///   signature SignatureValue,
    pub signature: BitString<'a>,
    ///   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
    pub unsigned_attrs: UnsignedAttributes<'a>,
}
impl OrdIsValueOrd for SignerInfo<'_> {}

/// SignerIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier [0] SubjectKeyIdentifier }
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum SignerIdentifier<'a> {
    ///   issuerAndSerialNumber IssuerAndSerialNumber,
    IssuerAndSerialNumber(IssuerAndSerialNumber<'a>),
    ///   subjectKeyIdentifier [0] SubjectKeyIdentifier }
    SubjectKeyIdentifier(SubjectKeyIdentifier<'a>),
}

const SKID_TAG: TagNumber = TagNumber::new(0);
const IASN_TAG: TagNumber = TagNumber::new(30);

impl<'a> DecodeValue<'a> for SignerIdentifier<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, _length: Length) -> der::Result<Self> {
        let t = decoder.peek_tag()?;
        let o = t.octet();
        // Context specific support always returns an Option<>, just ignore since OPTIONAL does not apply here
        match o {
            //TODO FIX
            // 0x30 => {
            //     let on = decoder
            //         .context_specific::<IssuerAndSerialNumber<'a>>(IASN_TAG, TagMode::Implicit)?;
            //     match on {
            //         Some(on) => Ok(SignerIdentifier::IssuerAndSerialNumber(on)),
            //         _ => Err(ErrorKind::Failed.into()),
            //     }
            // }
            0xA0 => {
                let on = decoder
                    .context_specific::<SubjectKeyIdentifier<'a>>(SKID_TAG, TagMode::Implicit)?;
                match on {
                    Some(on) => Ok(SignerIdentifier::SubjectKeyIdentifier(on)),
                    _ => Err(ErrorKind::Failed.into()),
                }
            }
            _ => Err(ErrorKind::TagUnknown { byte: o }.into()),
        }
    }
}

impl<'a> EncodeValue for SignerIdentifier<'a> {
    fn encode_value(&self, encoder: &mut ::der::Encoder<'_>) -> ::der::Result<()> {
        match self {
            Self::IssuerAndSerialNumber(variant) => ContextSpecific {
                tag_number: IASN_TAG,
                tag_mode: TagMode::Implicit,
                value: variant.clone(),
            }
            .encode(encoder),
            Self::SubjectKeyIdentifier(variant) => ContextSpecific {
                tag_number: SKID_TAG,
                tag_mode: TagMode::Implicit,
                value: *variant,
            }
            .encode(encoder),
        }
    }
    fn value_len(&self) -> ::der::Result<::der::Length> {
        match self {
            Self::IssuerAndSerialNumber(variant) => ContextSpecific {
                tag_number: IASN_TAG,
                tag_mode: TagMode::Implicit,
                value: variant.clone(),
            }
            .encoded_len(),
            Self::SubjectKeyIdentifier(variant) => ContextSpecific {
                tag_number: SKID_TAG,
                tag_mode: TagMode::Implicit,
                value: *variant,
            }
            .encoded_len(),
        }
    }
}

//TODO - see why this is necessary to avoid problem at line 78 in context_specific.rs due to mismatched tag
impl<'a> FixedTag for SignerIdentifier<'a> {
    const TAG: Tag = ::der::Tag::Sequence;
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
     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
     recipientInfos RecipientInfos,
     encryptedContentInfo EncryptedContentInfo,
     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

   OriginatorInfo ::= SEQUENCE {
     certs [0] IMPLICIT CertificateSet OPTIONAL,
     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }

   RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

   EncryptedContentInfo ::= SEQUENCE {
     contentType ContentType,
     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
     encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }

   EncryptedContent ::= OCTET STRING

   UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute

   RecipientInfo ::= CHOICE {
     ktri KeyTransRecipientInfo,
     kari [1] KeyAgreeRecipientInfo,
     kekri [2] KEKRecipientInfo,
     pwri [3] PasswordRecipientInfo,
     ori [4] OtherRecipientInfo }

   EncryptedKey ::= OCTET STRING

   KeyTransRecipientInfo ::= SEQUENCE {
     version CMSVersion,  -- always set to 0 or 2
     rid RecipientIdentifier,
     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
     encryptedKey EncryptedKey }

   RecipientIdentifier ::= CHOICE {
     issuerAndSerialNumber IssuerAndSerialNumber,
     subjectKeyIdentifier [0] SubjectKeyIdentifier }

   KeyAgreeRecipientInfo ::= SEQUENCE {
     version CMSVersion,  -- always set to 3
     originator [0] EXPLICIT OriginatorIdentifierOrKey,
     ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
     recipientEncryptedKeys RecipientEncryptedKeys }

   OriginatorIdentifierOrKey ::= CHOICE {
     issuerAndSerialNumber IssuerAndSerialNumber,
     subjectKeyIdentifier [0] SubjectKeyIdentifier,
     originatorKey [1] OriginatorPublicKey }

   OriginatorPublicKey ::= SEQUENCE {
     algorithm AlgorithmIdentifier,
     publicKey BIT STRING }

   RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey

   RecipientEncryptedKey ::= SEQUENCE {
     rid KeyAgreeRecipientIdentifier,
     encryptedKey EncryptedKey }

   KeyAgreeRecipientIdentifier ::= CHOICE {
     issuerAndSerialNumber IssuerAndSerialNumber,
     rKeyId [0] IMPLICIT RecipientKeyIdentifier }

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
     keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
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
     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

   AuthenticatedData ::= SEQUENCE {
     version CMSVersion,
     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
     recipientInfos RecipientInfos,
     macAlgorithm MessageAuthenticationCodeAlgorithm,
     digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
     encapContentInfo EncapsulatedContentInfo,
     authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
     mac MessageAuthenticationCode,
     unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }

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
     other [1] IMPLICIT OtherRevocationInfoFormat }

   OtherRevocationInfoFormat ::= SEQUENCE {
     otherRevInfoFormat OBJECT IDENTIFIER,
     otherRevInfo ANY DEFINED BY otherRevInfoFormat }

   CertificateChoices ::= CHOICE {
     certificate Certificate,
     extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
     v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
     v2AttrCert [2] IMPLICIT AttributeCertificateV2,
     other [3] IMPLICIT OtherCertificateFormat }

   AttributeCertificateV2 ::= AttributeCertificate

   OtherCertificateFormat ::= SEQUENCE {
     otherCertFormat OBJECT IDENTIFIER,
     otherCert ANY DEFINED BY otherCertFormat }

   CertificateSet ::= SET OF CertificateChoices
*/

/// IssuerAndSerialNumber ::= SEQUENCE {
///   issuer Name,
///   serialNumber CertificateSerialNumber }
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Sequence)]
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
    extendedCertificate [0] IMPLICIT ExtendedCertificate }

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
