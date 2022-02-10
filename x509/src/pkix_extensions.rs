//! Extensions [`Extensions`] as defined in RFC 5280

use crate::general_name::GeneralName;
use crate::general_name::GeneralNames;

use alloc::vec::Vec;
use der::asn1::{
    Any, BitString, ContextSpecific, GeneralizedTime, Ia5String, Null, ObjectIdentifier,
    OctetString, UIntBytes, Utf8String,
};
use der::Header;
use der::{
    Choice, Decodable, DecodeValue, Decoder, Encodable, EncodeValue, Enumerated, ErrorKind,
    FixedTag, Sequence, Tag, TagMode, TagNumber,
};
use x501::attr::AttributeTypeAndValue;
use x501::name::RelativeDistinguishedName;

/// DisplayText as defined in [RFC 5280 Section 4.2.1.4] in support of the Certificate Policies extension.
///
/// ASN.1 structure for DisplayText is below. At present, only the ia5String and utf8String options are supported.
///
/// ```text
///    DisplayText ::= CHOICE {
///         ia5String        IA5String      (SIZE (1..200)),
///         visibleString    VisibleString  (SIZE (1..200)),
///         bmpString        BMPString      (SIZE (1..200)),
///         utf8String       UTF8String     (SIZE (1..200)) }
/// ```
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
#[derive(Choice, Clone, Debug, Eq, PartialEq)]
pub enum DisplayText<'a> {
    /// ia5String        IA5String      (SIZE (1..200))
    #[asn1(type = "IA5String")]
    Ia5String(Ia5String<'a>),

    /// visibleString    VisibleString  (SIZE (1..200)),
    // TODO: support VisibleString if desired

    /// bmpString        BMPString      (SIZE (1..200)),
    // TODO: support BMPString if desired

    /// utf8String       UTF8String     (SIZE (1..200))
    #[asn1(type = "UTF8String")]
    Utf8String(Utf8String<'a>),
}

/// Extended key usage extension as defined in [RFC 5280 Section 4.2.1.12] and as identified by the [`PKIX_CE_EXTKEYUSAGE`](constant.PKIX_CE_EXTKEYUSAGE.html) OID.
///
/// Many extended key usage values include:
/// - [`PKIX_CE_ANYEXTENDEDKEYUSAGE`](constant.PKIX_CE_ANYEXTENDEDKEYUSAGE.html),
/// - [`PKIX_KP_SERVERAUTH`](constant.PKIX_KP_SERVERAUTH.html),
/// - [`PKIX_KP_CLIENTAUTH`](constant.PKIX_KP_CLIENTAUTH.html),
/// - [`PKIX_KP_CODESIGNING`](constant.PKIX_KP_CODESIGNING.html),
/// - [`PKIX_KP_EMAILPROTECTION`](constant.PKIX_KP_EMAILPROTECTION.html),
/// - [`PKIX_KP_TIMESTAMPING`](constant.PKIX_KP_TIMESTAMPING.html),
///
/// ```text
/// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
/// ```
///
/// [RFC 5280 Section 4.2.1.12]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12
pub type ExtendedKeyUsage<'a> = Vec<ObjectIdentifier>;

/// Subject alternative name extension as defined in [RFC 5280 Section 4.2.1.6] and as identified by the [`PKIX_CE_SUBJECT_ALT_NAME`](constant.PKIX_CE_SUBJECT_ALT_NAME.html) OID.
///
/// ```text
/// SubjectAltName ::= GeneralNames
/// ```
///
/// [RFC 5280 Section 4.2.1.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
pub type SubjectAltName<'a> = GeneralNames<'a>;

/// Issuer alternative name extension as defined in [RFC 5280 Section 4.2.1.7] and as identified by the [`PKIX_CE_ISSUER_ALT_NAME`](constant.PKIX_CE_ISSUER_ALT_NAME.html) OID.
///
/// ```text
/// IssuerAltName ::= GeneralNames
/// ```
///
/// [RFC 5280 Section 4.2.1.7]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.7
pub type IssuerAltName<'a> = GeneralNames<'a>;

/// OCSP noCheck extension as defined in [RFC 6960 Section 4.2.2.2.1] and as idenfied by the [`PKIX_OCSP_NOCHECK`](constant.PKIX_OCSP_NOCHECK.html) OID.
///
/// ```text
/// OcspNoCheck ::= NULL
/// ```
///
/// [RFC 6960 Section 4.2.2.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.2.2.1
pub type OcspNoCheck = Null;

/// Subject directory attributes extension as defined in [RFC 5280 Section 4.2.1.8] and as identified by the [`PKIX_CE_SUBJECT_DIRECTORY_ATTRIBUTES`](constant.PKIX_CE_SUBJECT_DIRECTORY_ATTRIBUTES.html) OID.
///
/// ```text
/// SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF AttributeSet
/// ```
///
/// [RFC 5280 Section 4.2.1.8]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.8
pub type SubjectDirectoryAttributes<'a> = Vec<AttributeTypeAndValue<'a>>;

/// Basic constraints extension as defined in [RFC 5280 Section 4.2.1.9] and as identified by the [`PKIX_CE_BASIC_CONSTRAINTS`](constant.PKIX_CE_BASIC_CONSTRAINTS.html) OID.
///
/// ```text
///    BasicConstraints ::= SEQUENCE {
///         cA                      BOOLEAN DEFAULT FALSE,
///         pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
/// ```
///
/// [RFC 5280 Section 4.2.1.9]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct BasicConstraints {
    /// cA                      BOOLEAN DEFAULT FALSE,
    #[asn1(default = "Default::default")]
    pub ca: bool,

    /// pathLenConstraint       INTEGER (0..MAX) OPTIONAL
    pub path_len_constraint: Option<u8>,
}

/// Subject key identifier extension as defined in [RFC 5280 Section 4.2.1.2] and as identified by the [`PKIX_CE_SUBJECT_KEY_IDENTIFIER`](constant.PKIX_CE_SUBJECT_KEY_IDENTIFIER.html) OID.
///
/// ```text
/// SubjectKeyIdentifier ::= KeyIdentifier
/// ```
///
/// [RFC 5280 Section 4.2.1.2]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
pub type SubjectKeyIdentifier<'a> = OctetString<'a>;

/// Key usage extension as defined in [RFC 5280 Section 4.2.1.3] and as identified by the [`PKIX_CE_KEY_USAGE`](constant.PKIX_CE_KEY_USAGE.html) OID.
///
/// ```text
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
/// ```
///
/// [RFC 5280 Section 4.2.1.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
pub type KeyUsage<'a> = BitString<'a>;

/// Certificate policies extension as defined in [RFC 5280 Section 4.2.1.4] and as identified by the [`PKIX_CE_CERTIFICATE_POLICIES`](constant.PKIX_CE_CERTIFICATE_POLICIES.html) OID.
///
/// ```text
///CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
/// ```
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
pub type CertificatePolicies<'a> = Vec<PolicyInformation<'a>>;

/// PolicyInformation as defined in [RFC 5280 Section 4.2.1.4] in support of the Certificate Policies extension.
///
/// ```text
/// PolicyInformation ::= SEQUENCE {
///      policyIdentifier   CertPolicyId,
///      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
///              PolicyQualifierInfo OPTIONAL }
///
/// CertPolicyId ::= OBJECT IDENTIFIER
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PolicyInformation<'a> {
    /// policyIdentifier   CertPolicyId,
    pub policy_identifier: ObjectIdentifier,

    /// policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL
    pub policy_qualifiers: Option<Vec<PolicyQualifierInfo<'a>>>,
}

/// PolicyQualifierInfo as defined in [RFC 5280 Section 4.2.1.4] in support of the Certificate Policies extension.
///
/// ```text
/// PolicyQualifierInfo ::= SEQUENCE {
///      policyQualifierId  PolicyQualifierId,
///      qualifier          ANY DEFINED BY policyQualifierId }
/// ```
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PolicyQualifierInfo<'a> {
    /// policyQualifierId  PolicyQualifierId,
    pub policy_qualifier_id: ObjectIdentifier,

    /// qualifier          ANY DEFINED BY policyQualifierId
    pub qualifier: Option<Any<'a>>,
}

/// Private key usage extension as defined in [RFC 3280 Section 4.2.1.4] and as identified by the [`PKIX_CE_PRIVATE_KEY_USAGE_PERIOD`](constant.PKIX_CE_PRIVATE_KEY_USAGE_PERIOD.html) OID.
///
/// RFC 5280 states "use of this ISO standard extension is neither deprecated nor recommended for use in the Internet PKI."
///
/// ```text
/// PrivateKeyUsagePeriod ::= SEQUENCE {
///      notBefore       [0]     GeneralizedTime OPTIONAL,
///      notAfter        [1]     GeneralizedTime OPTIONAL }
///      -- either notBefore or notAfter MUST be present
/// ```
///
/// [RFC 3280 Section 4.2.1.12]: https://datatracker.ietf.org/doc/html/rfc3280#section-4.2.1.4
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateKeyUsagePeriod {
    /// notBefore       [0]     GeneralizedTime OPTIONAL,
    pub not_before: Option<GeneralizedTime>,

    /// notAfter        [1]     GeneralizedTime OPTIONAL
    pub not_after: Option<GeneralizedTime>,
}

impl<'a> ::der::Decodable<'a> for PrivateKeyUsagePeriod {
    fn decode(decoder: &mut ::der::Decoder<'a>) -> ::der::Result<Self> {
        decoder.sequence(|decoder| {
            let not_before =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N0)?
                    .map(|cs| cs.value);
            let not_after =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N1)?
                    .map(|cs| cs.value);
            Ok(Self {
                not_before,
                not_after,
            })
        })
    }
}

const NOT_BEFORE_TAG: TagNumber = TagNumber::new(0);
const NOT_AFTER_TAG: TagNumber = TagNumber::new(1);

impl<'a> ::der::Sequence<'a> for PrivateKeyUsagePeriod {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        f(&[
            &self.not_before.as_ref().map(|elem| ContextSpecific {
                tag_number: NOT_BEFORE_TAG,
                tag_mode: TagMode::Implicit,
                value: *elem,
            }),
            &self.not_after.as_ref().map(|elem| ContextSpecific {
                tag_number: NOT_AFTER_TAG,
                tag_mode: TagMode::Implicit,
                value: *elem,
            }),
        ])
    }
}

/// NoticeReference as defined in [RFC 5280 Section 4.2.1.4] in support of the Certificate Policies extension.
///
/// ```text
/// NoticeReference ::= SEQUENCE {
///      organization     DisplayText,
///      noticeNumbers    SEQUENCE OF INTEGER }
/// ```
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct NoticeReference<'a> {
    /// organization     DisplayText,
    pub organization: DisplayText<'a>,

    /// noticeNumbers    SEQUENCE OF INTEGER
    pub notice_numbers: Option<Vec<UIntBytes<'a>>>,
}

/// UserNotice as defined in [RFC 5280 Section 4.2.1.4] in support of the Certificate Policies extension.
///
/// ```text
/// UserNotice ::= SEQUENCE {
///      noticeRef        NoticeReference OPTIONAL,
///      explicitText     DisplayText OPTIONAL }
/// ```
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct UserNotice<'a> {
    /// noticeRef        NoticeReference OPTIONAL,
    pub notice_ref: Option<GeneralizedTime>,

    /// explicitText     DisplayText OPTIONAL }
    pub explicit_text: Option<DisplayText<'a>>,
}

/// Policy mappings extension as defined in [RFC 5280 Section 4.2.1.5] and as identified by the [`PKIX_CE_POLICY_MAPPINGS`](constant.PKIX_CE_POLICY_MAPPINGS.html) OID.
///
/// ```text
/// PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
/// ```
///
/// [RFC 5280 Section 4.2.1.5]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.5
pub type PolicyMappings<'a> = Vec<PolicyMapping>;

/// PolicyMapping represents the inner portion of the PolicyMapping definition in [RFC 5280 Section 4.2.1.5].
///
/// ```text
/// PolicyMapping ::= SEQUENCE {
///      issuerDomainPolicy      CertPolicyId,
///      subjectDomainPolicy     CertPolicyId }
/// ```
///
/// [RFC 5280 Section 4.2.1.5]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.5
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PolicyMapping {
    /// issuerDomainPolicy      CertPolicyId,
    pub issuer_domain_policy: ObjectIdentifier,

    /// subjectDomainPolicy     CertPolicyId }
    pub subject_domain_policy: ObjectIdentifier,
}

/// Name constraints extension as defined in [RFC 5280 Section 4.2.1.10] and as identified by the [`PKIX_CE_NAME_CONSTRAINTS`](constant.PKIX_CE_NAME_CONSTRAINTS.html) OID.
///
/// ```text
/// NameConstraints ::= SEQUENCE {
///      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
///      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
/// ```
///
/// [RFC 5280 Section 4.2.1.10]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct NameConstraints<'a> {
    /// permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
    #[asn1(context_specific = "0", optional = "true", tag_mode = "IMPLICIT")]
    pub permitted_subtrees: Option<GeneralSubtrees<'a>>,

    /// excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    pub excluded_subtrees: Option<GeneralSubtrees<'a>>,
}

/// GeneralSubtrees as defined in [RFC 5280 Section 4.2.1.10] in support of the Name Constraints extension.
///
/// ```text
/// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
/// ```
///
/// [RFC 5280 Section 4.2.1.10]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
pub type GeneralSubtrees<'a> = Vec<GeneralSubtree<'a>>;

/// GeneralSubtree as defined in [RFC 5280 Section 4.2.1.10] in support of the Name Constraints extension.
///
/// ```text
/// GeneralSubtree ::= SEQUENCE {
///      base                    GeneralName,
///      minimum         [0]     BaseDistance DEFAULT 0,
///      maximum         [1]     BaseDistance OPTIONAL }
/// ```
///
/// [RFC 5280 Section 4.2.1.10]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneralSubtree<'a> {
    /// base                    GeneralName,
    pub base: GeneralName<'a>,

    /// minimum         [0]     BaseDistance DEFAULT 0,
    pub minimum: u32,

    /// maximum         [1]     BaseDistance OPTIONAL }
    pub maximum: Option<u32>,
}

impl<'a> ::der::Decodable<'a> for GeneralSubtree<'a> {
    fn decode(decoder: &mut ::der::Decoder<'a>) -> ::der::Result<Self> {
        decoder.sequence(|decoder| {
            let base = decoder.decode()?;

            let minimum =
                match decoder.context_specific::<u32>(GS_MINIMUM_TAG, TagMode::Implicit)? {
                    Some(v) => v,
                    _ => 0,
                };

            let maximum = decoder.context_specific::<u32>(GS_MAXIMUM_TAG, TagMode::Implicit)?;

            Ok(Self {
                base,
                minimum,
                maximum,
            })
        })
    }
}
const GS_MINIMUM_TAG: TagNumber = TagNumber::new(0);
const GS_MAXIMUM_TAG: TagNumber = TagNumber::new(1);

impl<'a> ::der::Sequence<'a> for GeneralSubtree<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        //f(&[&self.base, &self.minimum, &self.maximum])
        let cs_min = ContextSpecific {
            tag_number: GS_MINIMUM_TAG,
            tag_mode: TagMode::Implicit,
            value: self.minimum,
        };

        f(&[
            &self.base,
            &::der::asn1::OptionalRef(if self.minimum == Default::default() {
                None
            } else {
                Some(&cs_min)
            }),
            &self.maximum.as_ref().map(|exts| ContextSpecific {
                tag_number: GS_MAXIMUM_TAG,
                tag_mode: TagMode::Implicit,
                value: *exts,
            }),
        ])
    }
}

/// Policy constraints extension as defined in [RFC 5280 Section 4.2.1.11] and as identified by the [`PKIX_CE_POLICY_CONSTRAINTS`](constant.PKIX_CE_POLICY_CONSTRAINTS.html) OID.
///
/// ```text
/// PolicyConstraints ::= SEQUENCE {
///      requireExplicitPolicy   [0]     SkipCerts OPTIONAL,
///      inhibitPolicyMapping    [1]     SkipCerts OPTIONAL }
/// ```
///
/// [RFC 5280 Section 4.2.1.11]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.11
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyConstraints {
    /// requireExplicitPolicy   [0]     SkipCerts OPTIONAL,
    pub require_explicit_policy: Option<u32>,

    /// inhibitPolicyMapping    [1]     SkipCerts OPTIONAL }
    pub inhibit_policy_mapping: Option<u32>,
}

impl<'a> ::der::Decodable<'a> for PolicyConstraints {
    fn decode(decoder: &mut ::der::Decoder<'a>) -> ::der::Result<Self> {
        decoder.sequence(|decoder| {
            let require_explicit_policy =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N0)?
                    .map(|cs| cs.value);
            let inhibit_policy_mapping =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N1)?
                    .map(|cs| cs.value);
            Ok(Self {
                require_explicit_policy,
                inhibit_policy_mapping,
            })
        })
    }
}

const REQUIRE_EXPLICIT_POLICY_TAG: TagNumber = TagNumber::new(0);
const INHIBIT_POLICY_MAPPING_TAG: TagNumber = TagNumber::new(1);

impl<'a> ::der::Sequence<'a> for PolicyConstraints {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        f(&[
            &self
                .require_explicit_policy
                .as_ref()
                .map(|elem| ContextSpecific {
                    tag_number: REQUIRE_EXPLICIT_POLICY_TAG,
                    tag_mode: TagMode::Implicit,
                    value: *elem,
                }),
            &self
                .inhibit_policy_mapping
                .as_ref()
                .map(|elem| ContextSpecific {
                    tag_number: INHIBIT_POLICY_MAPPING_TAG,
                    tag_mode: TagMode::Implicit,
                    value: *elem,
                }),
        ])
    }
}

/// Inhibit any policy extension as defined in [RFC 5280 Section 4.2.1.14] and as identified by the [`PKIX_CE_INHIBIT_ANY_POLICY`](constant.PKIX_CE_INHIBIT_ANY_POLICY.html) OID.
///
/// ```text
/// InhibitAnyPolicy ::= SkipCerts
/// ```
///
/// [RFC 5280 Section 4.2.1.14]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.14
pub type InhibitAnyPolicy = u32;

/// Authority information access extension as defined in [RFC 5280 Section 4.2.2.1] and as identified by the [`PKIX_PE_AUTHORITYINFOACCESS`](constant.PKIX_PE_AUTHORITYINFOACCESS.html) OID.
///
/// ```text
/// AuthorityInfoAccessSyntax  ::=
///         SEQUENCE SIZE (1..MAX) OF AccessDescription
/// ```
///
/// [RFC 5280 Section 4.2.2.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1
pub type AuthorityInfoAccessSyntax<'a> = Vec<AccessDescription<'a>>;

/// AccessDescription as defined in [RFC 5280 Section 4.2.2.1] in support of the Authority Information Access extension (and referenced by Subject Information Access extension).
///
/// ```text
/// AccessDescription  ::=  SEQUENCE {
///         accessMethod          OBJECT IDENTIFIER,
///         accessLocation        GeneralName  }
/// ```
///
/// [RFC 5280 Section 4.2.2.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessDescription<'a> {
    /// accessMethod          OBJECT IDENTIFIER,
    pub access_method: ObjectIdentifier,

    /// accessLocation        GeneralName
    pub access_location: GeneralName<'a>,
}

impl<'a> ::der::Decodable<'a> for AccessDescription<'a> {
    fn decode(decoder: &mut ::der::Decoder<'a>) -> ::der::Result<Self> {
        decoder.sequence(|decoder| {
            let access_method = decoder.decode()?;
            let access_location = decoder.decode()?;
            Ok(Self {
                access_method,
                access_location,
            })
        })
    }
}

impl<'a> ::der::Sequence<'a> for AccessDescription<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        f(&[&self.access_method, &self.access_location])
    }
}

/// Subject information access extension as defined in [RFC 5280 Section 4.2.2.2] and as identified by the [`PKIX_PE_SUBJECTINFOACCESS`](constant.PKIX_PE_SUBJECTINFOACCESS.html) OID.
///
/// ```text
/// SubjectInfoAccessSyntax  ::=
///         SEQUENCE SIZE (1..MAX) OF AccessDescription
/// ```
///
/// [RFC 5280 Section 4.2.2.2]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.2
pub type SubjectInfoAccessSyntax<'a> = Vec<AccessDescription<'a>>;

/// CRL number extension as defined in [RFC 5280 Section 5.2.3] and as identified by the [`PKIX_CE_CRLNUMBER`](constant.PKIX_CE_CRLNUMBER.html) OID.
///
/// ```text
/// CRLNumber ::= INTEGER (0..MAX)
/// ```
///
/// [RFC 5280 Section 5.2.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.3
pub type CRLNumber<'a> = UIntBytes<'a>;

/// Delta CRL indicator extension as defined in [RFC 5280 Section 5.2.4] and as identified by the [`PKIX_CE_DELTACRLINDICATOR`](constant.PKIX_CE_DELTACRLINDICATOR.html) OID.
///
/// ```text
/// BaseCRLNumber ::= CRLNumber
/// ```
///
/// [RFC 5280 Section 5.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.4
pub type BaseCRLNumber<'a> = CRLNumber<'a>;

/// Reason code extension as defined in [RFC 5280 Section 5.3.1] and as identified by the [`PKIX_CE_CRLREASONS`](constant.PKIX_CE_CRLREASONS.html) OID.
///
/// ```text
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
/// ```
///
/// [RFC 5280 Section 5.3.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1
#[derive(Enumerated, Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CRLReason {
    /// unspecified             (0),
    Unspecified = 0,
    /// keyCompromise           (1),
    KeyCompromise = 1,
    /// cACompromise            (2),
    CaCompromise = 2,
    /// affiliationChanged      (3),
    AffiliationChanged = 3,
    /// superseded              (4),
    Superseded = 4,
    /// cessationOfOperation    (5),
    CessationOfOperation = 5,
    /// certificateHold         (6),
    CertificateHold = 6,
    /// removeFromCRL           (8),
    RemoveFromCRL = 8,
    /// privilegeWithdrawn      (9),
    PrivilegeWithdrawn = 9,
    /// aACompromise           (10)
    AaCompromise = 10,
}

/// Authority key identifier extension as defined in [RFC 5280 Section 4.2.1.1] and as identified by the [`PKIX_CE_AUTHORITY_KEY_IDENTIFIER`](constant.PKIX_CE_AUTHORITY_KEY_IDENTIFIER.html) OID.
///
/// ```text
///   AuthorityKeyIdentifier ::= SEQUENCE {
///       keyIdentifier             [0] KeyIdentifier           OPTIONAL,
///       authorityCertIssuer       [1] GeneralNames            OPTIONAL,
///       authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
///
///    KeyIdentifier ::= OCTET STRING
/// ```
///
/// [RFC 5280 Section 4.2.1.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1
//#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityKeyIdentifier<'a> {
    /// keyIdentifier             [0] KeyIdentifier           OPTIONAL,
    //#[asn1(context_specific = "0", optional = "true", tag_mode = "IMPLICIT")]
    pub key_identifier: Option<OctetString<'a>>,

    /// authorityCertIssuer       [1] GeneralNames            OPTIONAL,
    //#[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    pub authority_cert_issuer: Option<GeneralNames<'a>>,

    /// authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
    //#[asn1(context_specific = "2", optional = "true", tag_mode = "IMPLICIT")]
    pub authority_cert_serial_number: Option<UIntBytes<'a>>,
}
impl<'a> ::der::Decodable<'a> for AuthorityKeyIdentifier<'a> {
    fn decode(decoder: &mut ::der::Decoder<'a>) -> ::der::Result<Self> {
        decoder.sequence(|decoder| {
            let key_identifier =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N0)?
                    .map(|cs| cs.value);
            let authority_cert_issuer =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N1)?
                    .map(|cs| cs.value);
            let authority_cert_serial_number =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N2)?
                    .map(|cs| cs.value);
            Ok(Self {
                key_identifier,
                authority_cert_issuer,
                authority_cert_serial_number,
            })
        })
    }
}

const KEY_IDENTIFIER_TAG: TagNumber = TagNumber::new(0);
const AUTHORITY_CERT_ISSUER_TAG: TagNumber = TagNumber::new(1);
const AUTHORITY_CERT_SERIAL_NUMBER: TagNumber = TagNumber::new(2);

impl<'a> ::der::Sequence<'a> for AuthorityKeyIdentifier<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        f(&[
            &self.key_identifier.as_ref().map(|elem| ContextSpecific {
                tag_number: KEY_IDENTIFIER_TAG,
                tag_mode: TagMode::Implicit,
                value: *elem,
            }),
            &self
                .authority_cert_issuer
                .as_ref()
                .map(|elem| ContextSpecific {
                    tag_number: AUTHORITY_CERT_ISSUER_TAG,
                    tag_mode: TagMode::Implicit,
                    value: elem.clone(),
                }),
            &self
                .authority_cert_serial_number
                .as_ref()
                .map(|elem| ContextSpecific {
                    tag_number: AUTHORITY_CERT_SERIAL_NUMBER,
                    tag_mode: TagMode::Implicit,
                    value: *elem,
                }),
        ])
    }
}

/// ReasonFlags as defined in [RFC 5280 Section 4.2.1.13] in support of the CRL distribution points extension.
///
/// ```text
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
/// ```
///
/// [RFC 5280 Section 4.2.1.13]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
pub type ReasonFlags<'a> = BitString<'a>;

/// CRL distribution points extension as defined in [RFC 5280 Section 4.2.1.13] and as identified by the [`PKIX_CE_CRL_DISTRIBUTION_POINTS`](constant.PKIX_CE_CRL_DISTRIBUTION_POINTS.html) OID.
///
/// ```text
/// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
/// ```
///
/// [RFC 5280 Section 4.2.1.13]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
pub type CRLDistributionPoints<'a> = Vec<DistributionPoint<'a>>;

/// DistributionPoint as defined in [RFC 5280 Section 4.2.1.13] in support of the CRL distribution points extension.
///
/// ```text
/// DistributionPoint ::= SEQUENCE {
///      distributionPoint       [0]     DistributionPointName OPTIONAL,
///      reasons                 [1]     ReasonFlags OPTIONAL,
///      cRLIssuer               [2]     GeneralNames OPTIONAL }
/// ```
///
/// [RFC 5280 Section 4.2.1.13]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
//#[derive(Sequence)]
pub struct DistributionPoint<'a> {
    /// distributionPoint       [0]     DistributionPointName OPTIONAL,
    //#[asn1(context_specific = "0", optional = "true", tag_mode = "IMPLICIT")]
    pub distribution_point: Option<DistributionPointName<'a>>,

    /// reasons                 [1]     ReasonFlags OPTIONAL,
    //#[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    pub reasons: Option<ReasonFlags<'a>>,

    /// cRLIssuer               [2]     GeneralNames OPTIONAL }
    //#[asn1(context_specific = "2", optional = "true", tag_mode = "IMPLICIT")]
    pub crl_issuer: Option<GeneralNames<'a>>,
}

const CRLDP_DISTRIBUTION_POINT_TAG: TagNumber = TagNumber::new(0);
const REASONS_TAG: TagNumber = TagNumber::new(1);
const CRL_ISSUER_TAG: TagNumber = TagNumber::new(2);

impl<'a> ::der::Decodable<'a> for DistributionPoint<'a> {
    fn decode(decoder: &mut ::der::Decoder<'a>) -> ::der::Result<Self> {
        decoder.sequence(|decoder| {
            let distribution_point =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N0)?
                    .map(|cs| cs.value);
            let reasons =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N1)?
                    .map(|cs| cs.value);
            let crl_issuer =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N2)?
                    .map(|cs| cs.value);
            Ok(Self {
                distribution_point,
                reasons,
                crl_issuer,
            })
        })
    }
}

impl<'a> ::der::Sequence<'a> for DistributionPoint<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        f(&[
            &self
                .distribution_point
                .as_ref()
                .map(|elem| ContextSpecific {
                    tag_number: CRLDP_DISTRIBUTION_POINT_TAG,
                    tag_mode: TagMode::Implicit,
                    value: elem.clone(),
                }),
            &self.reasons.as_ref().map(|elem| ContextSpecific {
                tag_number: REASONS_TAG,
                tag_mode: TagMode::Implicit,
                value: *elem,
            }),
            &self.crl_issuer.as_ref().map(|elem| ContextSpecific {
                tag_number: CRL_ISSUER_TAG,
                tag_mode: TagMode::Implicit,
                value: elem.clone(),
            }),
        ])
    }
}

/// DistributionPointName as defined in [RFC 5280 Section 4.2.1.13] in support of the CRL distribution points extension.
///
/// ```text
/// DistributionPointName ::= CHOICE {
///      fullName                [0]     GeneralNames,
///      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
/// ```
///
/// [RFC 5280 Section 4.2.1.13]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DistributionPointName<'a> {
    /// fullName                [0]     GeneralNames,
    FullName(GeneralNames<'a>),

    /// nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
    NameRelativeToCRLIssuer(RelativeDistinguishedName<'a>),
}

const FULL_NAME_TAG: TagNumber = TagNumber::new(0);
const NAME_RELATIVE_TO_ISSUER_TAG: TagNumber = TagNumber::new(1);

impl<'a> DecodeValue<'a> for DistributionPointName<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, _header: Header) -> der::Result<Self> {
        let t = decoder.peek_tag()?;
        let o = t.octet();
        // Context specific support always returns an Option<>, just ignore since OPTIONAL does not apply here
        match o {
            0xA0 => {
                let on = decoder
                    .context_specific::<GeneralNames<'a>>(FULL_NAME_TAG, TagMode::Implicit)?;
                match on {
                    Some(on) => Ok(DistributionPointName::FullName(on)),
                    _ => Err(ErrorKind::Failed.into()),
                }
            }
            0xA1 => {
                let on = decoder.context_specific::<RelativeDistinguishedName<'a>>(
                    NAME_RELATIVE_TO_ISSUER_TAG,
                    TagMode::Implicit,
                )?;
                match on {
                    Some(on) => Ok(DistributionPointName::NameRelativeToCRLIssuer(on)),
                    _ => Err(ErrorKind::Failed.into()),
                }
            }
            _ => Err(ErrorKind::TagUnknown { byte: o }.into()),
        }
    }
}

impl<'a> EncodeValue for DistributionPointName<'a> {
    fn encode_value(&self, encoder: &mut ::der::Encoder<'_>) -> ::der::Result<()> {
        match self {
            Self::FullName(variant) => ContextSpecific {
                tag_number: FULL_NAME_TAG,
                tag_mode: TagMode::Implicit,
                value: variant.clone(),
            }
            .encode(encoder),
            Self::NameRelativeToCRLIssuer(variant) => ContextSpecific {
                tag_number: NAME_RELATIVE_TO_ISSUER_TAG,
                tag_mode: TagMode::Implicit,
                value: (*variant).clone(),
            }
            .encode(encoder),
        }
    }
    fn value_len(&self) -> ::der::Result<::der::Length> {
        match self {
            Self::FullName(variant) => ContextSpecific {
                tag_number: FULL_NAME_TAG,
                tag_mode: TagMode::Implicit,
                value: variant.clone(),
            }
            .encoded_len(),
            Self::NameRelativeToCRLIssuer(variant) => ContextSpecific {
                tag_number: NAME_RELATIVE_TO_ISSUER_TAG,
                tag_mode: TagMode::Implicit,
                value: variant.clone(),
            }
            .encoded_len(),
        }
    }
}

//TODO - see why this is necessary to avoid problem at line 78 in context_specific.rs due to mismatched tag
impl<'a> FixedTag for DistributionPointName<'a> {
    const TAG: Tag = ::der::Tag::Sequence;
}

/// Freshest CRL extension as defined in [RFC 5280 Section 5.2.6] and as identified by the [`PKIX_CE_FRESHEST_CRL`](constant.PKIX_CE_FRESHEST_CRL.html) OID.
///
/// ```text
/// FreshestCRL ::= CRLDistributionPoints
/// ```
///
/// [RFC 5280 Section 5.2.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.6
pub type FreshestCRL<'a> = CRLDistributionPoints<'a>;

/// Issuing distribution point extension as defined in [RFC 5280 Section 5.2.5] and as identified by the [`PKIX_PE_SUBJECTINFOACCESS`](constant.PKIX_PE_SUBJECTINFOACCESS.html) OID.
///
/// ```text
/// IssuingDistributionPoint ::= SEQUENCE {
///      distributionPoint          [0] DistributionPointName OPTIONAL,
///      onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
///      onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
///      onlySomeReasons            [3] ReasonFlags OPTIONAL,
///      indirectCRL                [4] BOOLEAN DEFAULT FALSE,
///      onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
///      -- at most one of onlyContainsUserCerts, onlyContainsCACerts,
///      -- and onlyContainsAttributeCerts may be set to TRUE.
/// ```
///
/// [RFC 5280 Section 5.2.5]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.5
//#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuingDistributionPoint<'a> {
    /// distributionPoint          [0] DistributionPointName OPTIONAL,
    pub distribution_point: Option<DistributionPointName<'a>>,

    /// onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
    pub only_contains_user_certs: bool,

    /// onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
    pub only_contains_cacerts: bool,

    /// onlySomeReasons            [3] ReasonFlags OPTIONAL,
    pub only_some_reasons: Option<ReasonFlags<'a>>,

    /// indirectCRL                [4] BOOLEAN DEFAULT FALSE,
    pub indirect_crl: bool,

    /// onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE
    pub only_contains_attribute_certs: bool,
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
                only_contains_user_certs: only_contains_user_certs.unwrap(),
                only_contains_cacerts: only_contains_cacerts.unwrap(),
                only_some_reasons,
                indirect_crl: indirect_crl.unwrap(),
                only_contains_attribute_certs: only_contains_attribute_certs.unwrap(),
            })
        })
    }
}

/// The PIV NACI extension is defined in [FIPS 201-2 Appendix B] and is identified by the [`PIV_NACI_INDICATOR`](constant.PIV_NACI_INDICATOR.html) OID.
///
/// ```text
/// NACI-indicator ::= BOOLEAN
/// ```
///
/// [FIPS 201-2 Appendix B]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.201-2.pdf
pub type PivNaciIndicator = bool;
