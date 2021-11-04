//! Extensions [`Extensions`] as defined in RFC 5280

//TODO refactor static sized SEQUENCE OF
//TODO handle all DEFAULT FALSE fields to return Some(false) vs None

use crate::AttributeTypeAndValue;
use crate::Name;
use crate::RelativeDistinguishedName;
use alloc::prelude::v1::Box;
use core::fmt;
use der::asn1::{
    Any, BitString, GeneralizedTime, Ia5String, Null, ObjectIdentifier, OctetString, SequenceOf,
    UIntBytes, Utf8String,
};
use der::{
    Decodable, DecodeValue, Decoder, Header, Length, Sequence, Tag, TagMode, TagNumber, Tagged,
};

///    DisplayText ::= CHOICE {
///         ia5String        IA5String      (SIZE (1..200)),
///         visibleString    VisibleString  (SIZE (1..200)),
///         bmpString        BMPString      (SIZE (1..200)),
///         utf8String       UTF8String     (SIZE (1..200)) }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisplayText<'a> {
    /// ia5String        IA5String      (SIZE (1..200))
    Ia5String(Ia5String<'a>),

    /// visibleString    VisibleString  (SIZE (1..200)),
    // TODO: support VisibleString if desired

    /// bmpString        BMPString      (SIZE (1..200)),
    // TODO: support BMPString if desired

    /// utf8String       UTF8String     (SIZE (1..200))
    Utf8String(Utf8String<'a>),
}

// Custom Decodable to handle implicit context specific fields (this may move to derived later).
impl<'a> Decodable<'a> for DisplayText<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        let t = decoder.peek_tag()?;
        match t {
            Ia5String::TAG => {
                let ia5 =
                    decoder.context_specific::<Ia5String<'_>>(t.number(), TagMode::Implicit)?;
                Ok(DisplayText::Ia5String(ia5.unwrap()))
            }
            Utf8String::TAG => {
                let ia5 =
                    decoder.context_specific::<Utf8String<'_>>(t.number(), TagMode::Implicit)?;
                Ok(DisplayText::Utf8String(ia5.unwrap()))
            }
            _ => panic!("TODO - error handling"),
        }
    }
}

// TODO confirm this is necessary
impl<'a> ::der::Sequence<'a> for DisplayText<'a> {
    fn fields<F, T>(&self, _f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        unimplemented!()
    }
}

///    Extension  ::=  SEQUENCE  {
///         extnID      OBJECT IDENTIFIER,
///         critical    BOOLEAN DEFAULT FALSE,
///         extnValue   OCTET STRING
///                     -- contains the DER encoding of an ASN.1 value
///                     -- corresponding to the extension type identified
///                     -- by extnID
///         }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Extension<'a> {
    /// extnID      OBJECT IDENTIFIER,
    pub extn_id: ObjectIdentifier,

    /// critical    BOOLEAN DEFAULT FALSE,
    pub critical: Option<bool>,

    /// extnValue   OCTET STRING
    pub extn_value: OctetString<'a>,
}

///    Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
//pub type Extensions<'a> = SequenceOf<Extension<'a>, 10>;
pub type Extensions<'a> = alloc::vec::Vec<Extension<'a>>;

/// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
pub type ExtendedKeyUsage<'a> = alloc::vec::Vec<ObjectIdentifier>;

/// SubjectAltName ::= GeneralNames
pub type SubjectAltName<'a> = GeneralNames<'a>;

/// IssuerAltName ::= GeneralNames
pub type IssuerAltName<'a> = GeneralNames<'a>;

/// OCSP noCheck
pub type OcspNoCheck = Null;

/// SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF AttributeSet
pub type SubjectDirectoryAttributes<'a> = alloc::vec::Vec<AttributeTypeAndValue<'a>>;

/// PIV NACI indicator extension
pub type PivNaciIndicator = bool;

///    BasicConstraints ::= SEQUENCE {
///         cA                      BOOLEAN DEFAULT FALSE,
///         pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct BasicConstraints {
    /// cA                      BOOLEAN DEFAULT FALSE,
    pub ca: Option<bool>,

    /// pathLenConstraint       INTEGER (0..MAX) OPTIONAL
    pub path_len_constraint: Option<u8>,
}

///    OtherName ::= SEQUENCE {
//         type-id    OBJECT IDENTIFIER,
//         value      [0] EXPLICIT ANY DEFINED BY type-id }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtherName<'a> {
    /// type-id    OBJECT IDENTIFIER,
    pub type_id: ObjectIdentifier,

    /// value      [0] EXPLICIT ANY DEFINED BY type-id }
    pub value: Any<'a>,
}
impl<'a> DecodeValue<'a> for OtherName<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, _length: Length) -> der::Result<Self> {
        let type_id = decoder.decode()?;
        let value = decoder.decode()?;
        Ok(Self { type_id, value })
    }
}

// impl<'a> Decodable<'a> for OtherName<'a> {
//     fn decode(decoder: &mut ::der::Decoder<'a>) -> ::der::Result<Self> {
//         decoder.sequence(|decoder| {
//             let type_id = decoder.decode()?;
//             let value = decoder.decode()?;
//             Ok(Self { type_id, value })
//         })
//     }
// }
impl<'a> Sequence<'a> for OtherName<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        f(&[&self.type_id, &self.value])
    }
}

/// Typedef for SubjectKeyIdentifier values
pub type SubjectKeyIdentifier<'a> = OctetString<'a>;

/// KeyUsage ::= BIT STRING {
///      digitalSignature        (0),
///      nonRepudiation          (1),  -- recent editions of X.509 have
///                                 -- renamed this bit to contentCommitment
///      keyEncipherment         (2),
///      dataEncipherment        (3),
///      keyAgreement            (4),
///      keyCertSign             (5),
///      cRLSign                 (6),
///      encipherOnly            (7),
///      decipherOnly            (8) }
pub type KeyUsage<'a> = BitString<'a>;

///CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
//pub type CertificatePolicies<'a> = SequenceOf<PolicyInformation<'a>, 10>;
pub type CertificatePolicies<'a> = alloc::vec::Vec<PolicyInformation<'a>>;

/// PolicyInformation ::= SEQUENCE {
///      policyIdentifier   CertPolicyId,
///      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
///              PolicyQualifierInfo OPTIONAL }
///
/// CertPolicyId ::= OBJECT IDENTIFIER
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PolicyInformation<'a> {
    /// policyIdentifier   CertPolicyId,
    pub policy_identifier: ObjectIdentifier,

    /// policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL
    pub policy_qualifiers: Option<SequenceOf<PolicyQualifierInfo<'a>, 10>>,
    // TODO make dynamic
}

/// PolicyQualifierInfo ::= SEQUENCE {
///      policyQualifierId  PolicyQualifierId,
///      qualifier          ANY DEFINED BY policyQualifierId }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PolicyQualifierInfo<'a> {
    /// policyQualifierId  PolicyQualifierId,
    pub policy_qualifier_id: ObjectIdentifier,

    /// qualifier          ANY DEFINED BY policyQualifierId
    pub qualifier: Option<Any<'a>>,
}

/// PrivateKeyUsagePeriod ::= SEQUENCE {
//      notBefore       [0]     GeneralizedTime OPTIONAL,
//      notAfter        [1]     GeneralizedTime OPTIONAL }
//      -- either notBefore or notAfter MUST be present
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateKeyUsagePeriod {
    /// notBefore       [0]     GeneralizedTime OPTIONAL,
    not_before: Option<GeneralizedTime>,

    /// notAfter        [1]     GeneralizedTime OPTIONAL
    not_after: Option<GeneralizedTime>,
}

const NOT_BEFORE_TAG: TagNumber = TagNumber::new(0);
const NOT_AFTER_TAG: TagNumber = TagNumber::new(1);

impl<'a> Decodable<'a> for PrivateKeyUsagePeriod {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let not_before =
                decoder.context_specific::<GeneralizedTime>(NOT_BEFORE_TAG, TagMode::Implicit)?;
            let not_after =
                decoder.context_specific::<GeneralizedTime>(NOT_AFTER_TAG, TagMode::Implicit)?;
            Ok(PrivateKeyUsagePeriod {
                not_before,
                not_after,
            })
        })
    }
}

/// NoticeReference ::= SEQUENCE {
//      organization     DisplayText,
//      noticeNumbers    SEQUENCE OF INTEGER }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct NoticeReference<'a> {
    /// organization     DisplayText,
    organization: DisplayText<'a>,

    /// noticeNumbers    SEQUENCE OF INTEGER
    notice_numbers: SequenceOf<UIntBytes<'a>, 10>,
}

/// UserNotice ::= SEQUENCE {
//      noticeRef        NoticeReference OPTIONAL,
//      explicitText     DisplayText OPTIONAL }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct UserNotice<'a> {
    /// noticeRef        NoticeReference OPTIONAL,
    notice_ref: Option<GeneralizedTime>,

    /// explicitText     DisplayText OPTIONAL }
    explicit_text: Option<DisplayText<'a>>,
}

/// PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
pub type PolicyMappings<'a> = alloc::vec::Vec<PolicyMapping>;

/// PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
///      issuerDomainPolicy      CertPolicyId,
///      subjectDomainPolicy     CertPolicyId }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PolicyMapping {
    /// issuerDomainPolicy      CertPolicyId,
    pub issuer_domain_policy: ObjectIdentifier,

    /// subjectDomainPolicy     CertPolicyId }
    pub subject_domain_policy: ObjectIdentifier,
}

/// NameConstraints ::= SEQUENCE {
///      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
///      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameConstraints<'a> {
    /// permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
    permitted_subtrees: Option<GeneralSubtrees<'a>>,

    /// excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
    excluded_subtrees: Option<GeneralSubtrees<'a>>,
}

const PERMITTED_SUBTREES_TAG: TagNumber = TagNumber::new(0);
const EXCLUDED_SUBTREES_TAG: TagNumber = TagNumber::new(1);

impl<'a> Decodable<'a> for NameConstraints<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let permitted_subtrees = decoder.context_specific::<GeneralSubtrees<'a>>(
                PERMITTED_SUBTREES_TAG,
                TagMode::Implicit,
            )?;
            let excluded_subtrees = decoder.context_specific::<GeneralSubtrees<'a>>(
                EXCLUDED_SUBTREES_TAG,
                TagMode::Implicit,
            )?;
            Ok(NameConstraints {
                permitted_subtrees,
                excluded_subtrees,
            })
        })
    }
}

/// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
pub type GeneralSubtrees<'a> = alloc::vec::Vec<GeneralSubtree<'a>>;

/// GeneralSubtree ::= SEQUENCE {
///      base                    GeneralName,
///      minimum         [0]     BaseDistance DEFAULT 0,
///      maximum         [1]     BaseDistance OPTIONAL }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneralSubtree<'a> {
    /// base                    GeneralName,
    base: GeneralName<'a>,

    /// minimum         [0]     BaseDistance DEFAULT 0,
    minimum: Option<u32>,

    /// maximum         [1]     BaseDistance OPTIONAL }
    maximum: Option<u32>,
}

impl<'a> ::der::Decodable<'a> for GeneralSubtree<'a> {
    fn decode(decoder: &mut ::der::Decoder<'a>) -> ::der::Result<Self> {
        decoder.sequence(|decoder| {
            let base = decoder.decode()?;
            let mut minimum: Option<u32> = decoder.decode()?;
            if minimum.is_none() {
                minimum = Some(0);
            }
            let maximum = decoder.decode()?;
            Ok(Self {
                base,
                minimum,
                maximum,
            })
        })
    }
}
impl<'a> ::der::Sequence<'a> for GeneralSubtree<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        f(&[&self.base, &self.minimum, &self.maximum])
    }
}

/// PolicyConstraints ::= SEQUENCE {
///      requireExplicitPolicy   [0]     SkipCerts OPTIONAL,
///      inhibitPolicyMapping    [1]     SkipCerts OPTIONAL }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyConstraints {
    /// requireExplicitPolicy   [0]     SkipCerts OPTIONAL,
    require_explicit_policy: Option<u32>,

    /// inhibitPolicyMapping    [1]     SkipCerts OPTIONAL }
    inhibit_policy_mapping: Option<u32>,
}

const REQUIRE_EXPLICIT_POLICY_TAG: TagNumber = TagNumber::new(0);
const INHIBIT_EXPLICIT_MAPPING_TAG: TagNumber = TagNumber::new(1);

impl<'a> Decodable<'a> for PolicyConstraints {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let require_explicit_policy =
                decoder.context_specific::<u32>(REQUIRE_EXPLICIT_POLICY_TAG, TagMode::Implicit)?;
            let inhibit_policy_mapping =
                decoder.context_specific::<u32>(INHIBIT_EXPLICIT_MAPPING_TAG, TagMode::Implicit)?;
            Ok(PolicyConstraints {
                require_explicit_policy,
                inhibit_policy_mapping,
            })
        })
    }
}

/// ReasonFlags ::= BIT STRING {
///      unused                  (0),
///      keyCompromise           (1),
///      cACompromise            (2),
///      affiliationChanged      (3),
///      superseded              (4),
///      cessationOfOperation    (5),
///      certificateHold         (6),
///      privilegeWithdrawn      (7),
///      aACompromise            (8) }
pub type ReasonFlags<'a> = BitString<'a>;

/// InhibitAnyPolicy ::= SkipCerts
pub type InhibitAnyPolicy = u32;

/// AuthorityInfoAccessSyntax  ::=
///         SEQUENCE SIZE (1..MAX) OF AccessDescription
pub type AuthorityInfoAccessSyntax<'a> = alloc::vec::Vec<AccessDescription<'a>>;

/// AccessDescription  ::=  SEQUENCE {
///         accessMethod          OBJECT IDENTIFIER,
///         accessLocation        GeneralName  }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AccessDescription<'a> {
    /// accessMethod          OBJECT IDENTIFIER,
    pub access_method: ObjectIdentifier,

    /// accessLocation        GeneralName
    pub access_location: GeneralName<'a>,
}

/// SubjectInfoAccessSyntax  ::=
///         SEQUENCE SIZE (1..MAX) OF AccessDescription
pub type SubjectInfoAccessSyntax<'a> = alloc::vec::Vec<AccessDescription<'a>>;

/// CRLNumber ::= INTEGER (0..MAX)
pub type CRLNumber<'a> = UIntBytes<'a>;

/// BaseCRLNumber ::= CRLNumber
pub type BaseCRLNumber<'a> = CRLNumber<'a>;

/// CRLReason ::= ENUMERATED {
///      unspecified             (0),
///      keyCompromise           (1),
///      cACompromise            (2),
///      affiliationChanged      (3),
///      superseded              (4),
///      cessationOfOperation    (5),
///      certificateHold         (6),
///      removeFromCRL           (8),
///      privilegeWithdrawn      (9),
///      aACompromise           (10) }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CRLReason {
    /// unspecified             (0),
    Unspecified,
    /// keyCompromise           (1),
    KeyCompromise,
    /// cACompromise            (2),
    CaCompromise,
    /// affiliationChanged      (3),
    AffiliationChanged,
    /// superseded              (4),
    Superseded,
    /// cessationOfOperation    (5),
    CessationOfOperation,
    /// certificateHold         (6),
    CertificateHold,
    /// removeFromCRL           (8),
    RemoveFromCRL,
    /// privilegeWithdrawn      (9),
    PrivilegeWithdrawn,
    /// aACompromise           (10)
    AaCompromise,
}
//TODO refactor using repr(u32)
impl Decodable<'_> for CRLReason {
    fn decode(decoder: &mut Decoder<'_>) -> der::Result<Self> {
        //CRLReason::try_from(u32::decode(decoder)?).map_err(|_| Self::TAG.value_error())
        let header = Header::decode(decoder)?;
        header.tag.assert_eq(Tag::Enumerated)?;
        let v = u32::decode_value(decoder, header.length)?;
        match v {
            0 => Ok(CRLReason::Unspecified),
            1 => Ok(CRLReason::KeyCompromise),
            2 => Ok(CRLReason::CaCompromise),
            3 => Ok(CRLReason::AffiliationChanged),
            4 => Ok(CRLReason::Superseded),
            5 => Ok(CRLReason::CessationOfOperation),
            6 => Ok(CRLReason::CertificateHold),
            7 => Ok(CRLReason::RemoveFromCRL),
            8 => Ok(CRLReason::PrivilegeWithdrawn),
            9 => Ok(CRLReason::AaCompromise),
            _ => panic!("TODO - fix Err"), // Err(Error::Failed),
        }
    }
}

impl<'a> Tagged for CRLReason {
    const TAG: Tag = Tag::Enumerated;
}

impl fmt::Display for CRLReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CRLReason::Unspecified => "Unspecified",
            CRLReason::KeyCompromise => "KeyCompromise",
            CRLReason::CaCompromise => "CaCompromise",
            CRLReason::AffiliationChanged => "AffiliationChanged",
            CRLReason::Superseded => "Superseded",
            CRLReason::CessationOfOperation => "CessationOfOperation",
            CRLReason::CertificateHold => "CertificateHold",
            CRLReason::RemoveFromCRL => "RemoveFromCRL",
            CRLReason::PrivilegeWithdrawn => "PrivilegeWithdrawn",
            CRLReason::AaCompromise => "AaCompromise",
        })
    }
}

/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
pub type GeneralNames<'a> = alloc::vec::Vec<GeneralName<'a>>;

///    GeneralName ::= CHOICE {
///         otherName                       [0]     OtherName,
///         rfc822Name                      [1]     IA5String,
///         dNSName                         [2]     IA5String,
///         x400Address                     [3]     ORAddress,
///         directoryName                   [4]     Name,
///         ediPartyName                    [5]     EDIPartyName,
///         uniformResourceIdentifier       [6]     IA5String,
///         iPAddress                       [7]     OCTET STRING,
///         registeredID                    [8]     OBJECT IDENTIFIER }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneralName<'a> {
    /// otherName                       [0]     OtherName,
    OtherName(OtherName<'a>),

    /// rfc822Name                      [1]     IA5String,
    Rfc822Name(Ia5String<'a>),

    /// dNSName                         [2]     IA5String,
    DnsName(Ia5String<'a>),

    /// x400Address                     [3]     ORAddress,
    /// Not supporting x400Address

    /// directoryName                   [4]     Name,
    DirectoryName(Name<'a>),

    /// ediPartyName                    [5]     EDIPartyName,
    /// Not supporting ediPartyName

    /// uniformResourceIdentifier       [6]     IA5String,
    UniformResourceIdentifier(Ia5String<'a>),

    /// iPAddress                       [7]     OCTET STRING,
    IpAddress(OctetString<'a>),

    /// registeredID                    [8]     OBJECT IDENTIFIER
    RegisteredId(ObjectIdentifier),
}

const OTHER_NAME_TAG: TagNumber = TagNumber::new(0);
const RFC822_NAME_TAG: TagNumber = TagNumber::new(1);
const DNS_NAME_TAG: TagNumber = TagNumber::new(2);
const DIRECTORY_NAME_TAG: TagNumber = TagNumber::new(4);
const URI_TAG: TagNumber = TagNumber::new(6);
//TODO - implement these
//const IP_ADDRESS_TAG: TagNumber = TagNumber::new(7);
//const REGISTERED_ID_TAG: TagNumber = TagNumber::new(8);

// Custom Decodable to handle implicit context specific fields (this may move to derived later).
impl<'a> Decodable<'a> for GeneralName<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        let t = decoder.peek_tag()?;
        match t.octet() {
            0xA0 => {
                let on =
                    decoder.context_specific::<OtherName<'_>>(OTHER_NAME_TAG, TagMode::Implicit)?;
                Ok(GeneralName::OtherName(on.unwrap()))
            }
            0x81 => {
                let ia5 = decoder
                    .context_specific::<Ia5String<'_>>(RFC822_NAME_TAG, TagMode::Implicit)?;
                Ok(GeneralName::Rfc822Name(ia5.unwrap()))
            }
            0x82 => {
                let ia5 =
                    decoder.context_specific::<Ia5String<'_>>(DNS_NAME_TAG, TagMode::Implicit)?;
                Ok(GeneralName::DnsName(ia5.unwrap()))
            }
            0xA3 => unimplemented!(),
            0xA4 => {
                let ia5 =
                    decoder.context_specific::<Name<'_>>(DIRECTORY_NAME_TAG, TagMode::Explicit)?;
                Ok(GeneralName::DirectoryName(ia5.unwrap()))
            }
            0xA5 => unimplemented!(),
            0x86 => {
                let ia5 = decoder.context_specific::<Ia5String<'_>>(URI_TAG, TagMode::Implicit)?;
                Ok(GeneralName::UniformResourceIdentifier(ia5.unwrap()))
            }
            0x87 => unimplemented!(),
            0x88 => unimplemented!(),
            _ => unimplemented!(),
        }
    }
}

// This stub is required to satisfy use of this type in context-specific fields, i.e., in the
// definition of AuthorityKeyIdentifier
impl<'a> ::der::Sequence<'a> for GeneralName<'a> {
    fn fields<F, T>(&self, _f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        unimplemented!()
    }
}

///   AuthorityKeyIdentifier ::= SEQUENCE {
///       keyIdentifier             [0] KeyIdentifier           OPTIONAL,
///       authorityCertIssuer       [1] GeneralNames            OPTIONAL,
///       authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
///
///    KeyIdentifier ::= OCTET STRING
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityKeyIdentifier<'a> {
    /// keyIdentifier             [0] KeyIdentifier           OPTIONAL,
    pub key_identifier: Option<OctetString<'a>>,

    /// authorityCertIssuer       [1] GeneralNames            OPTIONAL,
    pub authority_cert_issuer: Option<GeneralNames<'a>>,

    /// authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
    pub authority_cert_serial_number: Option<UIntBytes<'a>>,
}

const KEUY_IDENTIFIER_TAG: TagNumber = TagNumber::new(0);
const AUTHORITY_CERT_ISSUER_TAG: TagNumber = TagNumber::new(1);
const AUTHORITY_CERT_SERIAL_NUMBER_TAG: TagNumber = TagNumber::new(2);

impl<'a> DecodeValue<'a> for AuthorityKeyIdentifier<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, _length: Length) -> der::Result<Self> {
        let key_identifier =
            decoder.context_specific::<OctetString<'_>>(KEUY_IDENTIFIER_TAG, TagMode::Implicit)?;
        let authority_cert_issuer = decoder
            .context_specific::<GeneralNames<'_>>(AUTHORITY_CERT_ISSUER_TAG, TagMode::Implicit)?;
        let authority_cert_serial_number = decoder.context_specific::<UIntBytes<'_>>(
            AUTHORITY_CERT_SERIAL_NUMBER_TAG,
            TagMode::Implicit,
        )?;
        Ok(AuthorityKeyIdentifier {
            key_identifier,
            authority_cert_issuer,
            authority_cert_serial_number,
        })
    }
}

impl<'a> ::der::Sequence<'a> for AuthorityKeyIdentifier<'a> {
    fn fields<F, T>(&self, _f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        #[allow(unused_imports)]
        use core::convert::TryFrom;
        unimplemented!();
    }
}

/// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
pub type CRLDistributionPoints<'a> = alloc::vec::Vec<DistributionPoint<'a>>;

/// DistributionPoint ::= SEQUENCE {
///      distributionPoint       [0]     DistributionPointName OPTIONAL,
///      reasons                 [1]     ReasonFlags OPTIONAL,
///      cRLIssuer               [2]     GeneralNames OPTIONAL }
//#[derive(Sequence)]
pub struct DistributionPoint<'a> {
    /// distributionPoint       [0]     DistributionPointName OPTIONAL,
    pub distribution_point: Option<DistributionPointName<'a>>,

    /// reasons                 [1]     ReasonFlags OPTIONAL,
    pub reasons: Option<ReasonFlags<'a>>,

    /// cRLIssuer               [2]     GeneralNames OPTIONAL }
    pub crl_issuer: Option<GeneralNames<'a>>,
}

const DISTRIBUTION_POINT_NAME_TAG: TagNumber = TagNumber::new(0);
const REASONS_TAG: TagNumber = TagNumber::new(1);
const CRL_ISSUER_TAG: TagNumber = TagNumber::new(2);

impl<'a> DecodeValue<'a> for DistributionPoint<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, _length: Length) -> der::Result<Self> {
        let distribution_point = decoder.context_specific::<DistributionPointName<'_>>(
            DISTRIBUTION_POINT_NAME_TAG,
            TagMode::Implicit,
        )?;
        let reasons =
            decoder.context_specific::<ReasonFlags<'_>>(REASONS_TAG, TagMode::Implicit)?;
        let crl_issuer =
            decoder.context_specific::<GeneralNames<'_>>(CRL_ISSUER_TAG, TagMode::Implicit)?;
        Ok(DistributionPoint {
            distribution_point,
            reasons,
            crl_issuer,
        })
    }
}

impl<'a> ::der::Sequence<'a> for DistributionPoint<'a> {
    fn fields<F, T>(&self, _f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        #[allow(unused_imports)]
        use core::convert::TryFrom;
        unimplemented!();
    }
}

/// DistributionPointName ::= CHOICE {
///      fullName                [0]     GeneralNames,
///      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
pub enum DistributionPointName<'a> {
    /// fullName                [0]     GeneralNames,
    FullName(GeneralNames<'a>),

    /// nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
    NameRelativeToCRLIssuer(Box<RelativeDistinguishedName<'a>>),
}

const FULL_NAME_TAG: TagNumber = TagNumber::new(0);
const NAME_RELATIVE_TO_ISSUER_TAG: TagNumber = TagNumber::new(1);

impl<'a> DecodeValue<'a> for DistributionPointName<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, _length: Length) -> der::Result<Self> {
        let t = decoder.peek_tag()?;
        let o = t.octet();
        match o {
            0xA0 => {
                let on = decoder
                    .context_specific::<GeneralNames<'a>>(FULL_NAME_TAG, TagMode::Implicit)?;
                let dpn = DistributionPointName::FullName(on.unwrap());
                Ok(dpn)
            }
            0xA1 => {
                let on = decoder.context_specific::<RelativeDistinguishedName<'a>>(
                    NAME_RELATIVE_TO_ISSUER_TAG,
                    TagMode::Implicit,
                )?;
                //TODO review unwraps
                Ok(DistributionPointName::NameRelativeToCRLIssuer(Box::new(
                    on.unwrap(),
                )))
            }
            _ => {
                panic!("TODO");
            }
        }
    }
}

// This stub is required to satisfy use of this type in context-specific fields, i.e., in the
// definition of IssuingDistributionPoint
impl<'a> ::der::Sequence<'a> for DistributionPointName<'a> {
    fn fields<F, T>(&self, _f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        unimplemented!();
    }
}

/// FreshestCRL ::= CRLDistributionPoints
pub type FreshestCRL<'a> = CRLDistributionPoints<'a>;

/// IssuingDistributionPoint ::= SEQUENCE {
///      distributionPoint          [0] DistributionPointName OPTIONAL,
///      onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
///      onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
///      onlySomeReasons            [3] ReasonFlags OPTIONAL,
///      indirectCRL                [4] BOOLEAN DEFAULT FALSE,
///      onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
///      -- at most one of onlyContainsUserCerts, onlyContainsCACerts,
///      -- and onlyContainsAttributeCerts may be set to TRUE.
//TODO enable derive bits here and for DistributionPointName and friends
//#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuingDistributionPoint<'a> {
    /// distributionPoint          [0] DistributionPointName OPTIONAL,
    pub distribution_point: Option<DistributionPointName<'a>>,

    /// onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
    pub only_contains_user_certs: Option<bool>,

    /// onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
    pub only_contains_cacerts: Option<bool>,

    /// onlySomeReasons            [3] ReasonFlags OPTIONAL,
    pub only_some_reasons: Option<ReasonFlags<'a>>,

    /// indirectCRL                [4] BOOLEAN DEFAULT FALSE,
    pub indirect_crl: Option<bool>,

    /// onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE
    pub only_contains_attribute_certs: Option<bool>,
}

const DISTRIBUTION_POINT_TAG: TagNumber = TagNumber::new(0);
const ONLY_CONTAINS_USER_CERTS_TAG: TagNumber = TagNumber::new(1);
const ONLY_CONTAINS_CA_CERTS_TAG: TagNumber = TagNumber::new(2);
const ONLY_SOME_REASONS_TAG: TagNumber = TagNumber::new(3);
const INDIRECT_TAG: TagNumber = TagNumber::new(4);
const ONLY_CONTAINS_ATTRIBUTE_CERTS_TAG: TagNumber = TagNumber::new(5);

impl<'a> Decodable<'a> for IssuingDistributionPoint<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let distribution_point = decoder.context_specific::<DistributionPointName<'_>>(
                DISTRIBUTION_POINT_TAG,
                TagMode::Implicit,
            )?;

            // for each of the BOOLEAN fields, assign the DEFAULT value upon None
            let mut only_contains_user_certs = decoder
                .context_specific::<bool>(ONLY_CONTAINS_USER_CERTS_TAG, TagMode::Implicit)?;
            if None == only_contains_user_certs {
                only_contains_user_certs = Some(false);
            }

            let mut only_contains_cacerts =
                decoder.context_specific::<bool>(ONLY_CONTAINS_CA_CERTS_TAG, TagMode::Implicit)?;
            if None == only_contains_cacerts {
                only_contains_cacerts = Some(false);
            }

            let only_some_reasons = decoder
                .context_specific::<ReasonFlags<'_>>(ONLY_SOME_REASONS_TAG, TagMode::Implicit)?;

            let mut indirect_crl =
                decoder.context_specific::<bool>(INDIRECT_TAG, TagMode::Implicit)?;
            if None == indirect_crl {
                indirect_crl = Some(false);
            }

            let mut only_contains_attribute_certs = decoder
                .context_specific::<bool>(ONLY_CONTAINS_ATTRIBUTE_CERTS_TAG, TagMode::Implicit)?;
            if None == only_contains_attribute_certs {
                only_contains_attribute_certs = Some(false);
            }
            Ok(IssuingDistributionPoint {
                distribution_point,
                only_contains_user_certs,
                only_contains_cacerts,
                only_some_reasons,
                indirect_crl,
                only_contains_attribute_certs,
            })
        })
    }
}
