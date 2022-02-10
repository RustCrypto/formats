//! Extensions [`Extensions`] as defined in RFC 5280

use crate::ext::pkix::name::{DistributionPointName, GeneralName, GeneralNames};

use alloc::vec::Vec;

use der::asn1::*;
use der::{Choice, Enumerated, Sequence};
use flagset::{flags, FlagSet};
use x501::attr::AttributeTypeAndValue;

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

flags! {
    /// Key usage flags as defined in [RFC 5280 Section 4.2.1.3].
    ///
    /// ```text
    /// KeyUsage ::= BIT STRING {
    ///      digitalSignature        (0),
    ///      nonRepudiation          (1),  -- recent editions of X.509 have
    ///                                    -- renamed this bit to contentCommitment
    ///      keyEncipherment         (2),
    ///      dataEncipherment        (3),
    ///      keyAgreement            (4),
    ///      keyCertSign             (5),
    ///      cRLSign                 (6),
    ///      encipherOnly            (7),
    ///      decipherOnly            (8)
    /// }
    /// ```
    ///
    /// [RFC 5280 Section 4.2.1.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
    #[allow(missing_docs)]
    pub enum KeyUsages: u16 {
        DigitalSignature = 1 << 0,
        NonRepudiation = 1 << 1,
        KeyEncipherment = 1 << 2,
        DataEncipherment = 1 << 3,
        KeyAgreement = 1 << 4,
        KeyCertSign = 1 << 5,
        CRLSign = 1 << 6,
        EncipherOnly = 1 << 7,
        DecipherOnly = 1 << 8,
    }
}

/// KeyUsage as defined in [RFC 5280 Section 4.2.1.3] and as identified by the [`PKIX_CE_KEY_USAGE`](constant.PKIX_CE_KEY_USAGE.html) OID.
///
/// [RFC 5280 Section 4.2.1.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
pub type KeyUsage<'a> = FlagSet<KeyUsages>;

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

/// PrivateKeyUsagePeriod as defined in [RFC 3280 Section 4.2.1.4].
///
/// This extension is by the [`PKIX_CE_PRIVATE_KEY_USAGE_PERIOD`](constant.PKIX_CE_PRIVATE_KEY_USAGE_PERIOD.html) OID.
///
/// RFC 5280 states "use of this ISO standard extension is neither deprecated nor recommended for use in the Internet PKI."
///
/// ```text
/// PrivateKeyUsagePeriod ::= SEQUENCE {
///     notBefore       [0]     GeneralizedTime OPTIONAL,
///     notAfter        [1]     GeneralizedTime OPTIONAL
///     -- either notBefore or notAfter MUST be present
/// }
/// ```
///
/// [RFC 3280 Section 4.2.1.12]: https://datatracker.ietf.org/doc/html/rfc3280#section-4.2.1.4
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct PrivateKeyUsagePeriod {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub not_before: Option<GeneralizedTime>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub not_after: Option<GeneralizedTime>,
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

/// GeneralSubtree as defined in [RFC 5280 Section 4.2.1.10].
///
/// ```text
/// GeneralSubtree ::= SEQUENCE {
///     base                    GeneralName,
///     minimum         [0]     BaseDistance DEFAULT 0,
///     maximum         [1]     BaseDistance OPTIONAL
/// }
/// ```
///
/// [RFC 5280 Section 4.2.1.10]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct GeneralSubtree<'a> {
    pub base: GeneralName<'a>,

    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        default = "Default::default"
    )]
    pub minimum: u32,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub maximum: Option<u32>,
}

/// Policy constraints extension as defined in [RFC 5280 Section 4.2.1.11].
///
/// This extension is identified by the [`PKIX_CE_POLICY_CONSTRAINTS`](constant.PKIX_CE_POLICY_CONSTRAINTS.html) OID.
///
/// ```text
/// PolicyConstraints ::= SEQUENCE {
///      requireExplicitPolicy   [0]     SkipCerts OPTIONAL,
///      inhibitPolicyMapping    [1]     SkipCerts OPTIONAL
/// }
/// ```
///
/// [RFC 5280 Section 4.2.1.11]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.11
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PolicyConstraints {
    #[asn1(context_specific = "0", optional = "true", tag_mode = "IMPLICIT")]
    pub require_explicit_policy: Option<u32>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    pub inhibit_policy_mapping: Option<u32>,
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

/// AccessDescription as defined in [RFC 5280 Section 4.2.2.1].
///
/// ```text
/// AccessDescription  ::=  SEQUENCE {
///     accessMethod          OBJECT IDENTIFIER,
///     accessLocation        GeneralName
/// }
/// ```
///
/// [RFC 5280 Section 4.2.2.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct AccessDescription<'a> {
    pub access_method: ObjectIdentifier,

    pub access_location: GeneralName<'a>,
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

flags! {
    /// Reason flags as defined in [RFC 5280 Section 4.2.1.13].
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
    #[allow(missing_docs)]
    pub enum Reasons: u16 {
        Unused = 1 << 0,
        KeyCompromise = 1 << 1,
        CaCompromise = 1 << 2,
        AffiliationChanged = 1 << 3,
        Superseded = 1 << 4,
        CessationOfOperation = 1 << 5,
        CertificateHold = 1 << 6,
        PrivilegeWithdrawn = 1 << 7,
        AaCompromise = 1 << 8,
    }
}

/// `ReasonFlags` as defined in [RFC 5280 Section 4.2.1.13] in support of the CRL distribution points extension.
///
/// [RFC 5280 Section 4.2.1.13]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
pub type ReasonFlags = FlagSet<Reasons>;

/// CRL distribution points extension as defined in [RFC 5280 Section 4.2.1.13] and as identified by the [`PKIX_CE_CRL_DISTRIBUTION_POINTS`](constant.PKIX_CE_CRL_DISTRIBUTION_POINTS.html) OID.
///
/// ```text
/// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
/// ```
///
/// [RFC 5280 Section 4.2.1.13]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
pub type CRLDistributionPoints<'a> = Vec<DistributionPoint<'a>>;

/// DistributionPoint as defined in [RFC 5280 Section 4.2.1.13].
///
/// ```text
/// DistributionPoint ::= SEQUENCE {
///     distributionPoint       [0]     DistributionPointName OPTIONAL,
///     reasons                 [1]     ReasonFlags OPTIONAL,
///     cRLIssuer               [2]     GeneralNames OPTIONAL
/// }
/// ```
///
/// [RFC 5280 Section 4.2.1.13]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct DistributionPoint<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub distribution_point: Option<DistributionPointName<'a>>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub reasons: Option<ReasonFlags>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub crl_issuer: Option<GeneralNames<'a>>,
}

/// Freshest CRL extension as defined in [RFC 5280 Section 5.2.6] and as identified by the [`PKIX_CE_FRESHEST_CRL`](constant.PKIX_CE_FRESHEST_CRL.html) OID.
///
/// ```text
/// FreshestCRL ::= CRLDistributionPoints
/// ```
///
/// [RFC 5280 Section 5.2.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.6
pub type FreshestCRL<'a> = CRLDistributionPoints<'a>;

/// IssuingDistributionPoint as defined in [RFC 5280 Section 5.2.5].
///
/// This extension is identified by the [`PKIX_PE_SUBJECTINFOACCESS`](constant.PKIX_PE_SUBJECTINFOACCESS.html) OID.
///
/// ```text
/// IssuingDistributionPoint ::= SEQUENCE {
///     distributionPoint          [0] DistributionPointName OPTIONAL,
///     onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
///     onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
///     onlySomeReasons            [3] ReasonFlags OPTIONAL,
///     indirectCRL                [4] BOOLEAN DEFAULT FALSE,
///     onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE
///     -- at most one of onlyContainsUserCerts, onlyContainsCACerts,
///     -- and onlyContainsAttributeCerts may be set to TRUE.
/// }
/// ```
///
/// [RFC 5280 Section 5.2.5]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.5
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct IssuingDistributionPoint<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub distribution_point: Option<DistributionPointName<'a>>,

    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        default = "Default::default"
    )]
    pub only_contains_user_certs: bool,

    #[asn1(
        context_specific = "2",
        tag_mode = "IMPLICIT",
        default = "Default::default"
    )]
    pub only_contains_ca_certs: bool,

    #[asn1(context_specific = "3", tag_mode = "IMPLICIT", optional = "true")]
    pub only_some_reasons: Option<ReasonFlags>,

    #[asn1(
        context_specific = "4",
        tag_mode = "IMPLICIT",
        default = "Default::default"
    )]
    pub indirect_crl: bool,

    #[asn1(
        context_specific = "5",
        tag_mode = "IMPLICIT",
        default = "Default::default"
    )]
    pub only_contains_attribute_certs: bool,
}

/// The PIV NACI extension is defined in [FIPS 201-2 Appendix B] and is identified by the [`PIV_NACI_INDICATOR`](constant.PIV_NACI_INDICATOR.html) OID.
///
/// ```text
/// NACI-indicator ::= BOOLEAN
/// ```
///
/// [FIPS 201-2 Appendix B]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.201-2.pdf
pub type PivNaciIndicator = bool;
