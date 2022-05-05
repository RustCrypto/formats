//! PKIX Certificate Policies extension

use alloc::vec::Vec;

use const_oid::db::rfc5912::ID_CE_CERTIFICATE_POLICIES;
use const_oid::AssociatedOid;
use der::asn1::{GeneralizedTime, Ia5StringRef, ObjectIdentifier, UIntRef, Utf8StringRef};
use der::{AnyRef, Choice, Sequence};

/// CertificatePolicies as defined in [RFC 5280 Section 4.2.1.4].
///
/// ```text
/// CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
/// ```
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificatePolicies<'a>(pub Vec<PolicyInformation<'a>>);

impl<'a> AssociatedOid for CertificatePolicies<'a> {
    const OID: ObjectIdentifier = ID_CE_CERTIFICATE_POLICIES;
}

impl_newtype!(CertificatePolicies<'a>, Vec<PolicyInformation<'a>>);

/// PolicyInformation as defined in [RFC 5280 Section 4.2.1.4].
///
/// ```text
/// PolicyInformation ::= SEQUENCE {
///     policyIdentifier   CertPolicyId,
///     policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL
/// }
///
/// CertPolicyId ::= OBJECT IDENTIFIER
/// ```
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PolicyInformation<'a> {
    pub policy_identifier: ObjectIdentifier,
    pub policy_qualifiers: Option<Vec<PolicyQualifierInfo<'a>>>,
}

/// PolicyQualifierInfo as defined in [RFC 5280 Section 4.2.1.4].
///
/// ```text
/// PolicyQualifierInfo ::= SEQUENCE {
///     policyQualifierId  PolicyQualifierId,
///     qualifier          ANY DEFINED BY policyQualifierId
/// }
/// ```
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct PolicyQualifierInfo<'a> {
    pub policy_qualifier_id: ObjectIdentifier,
    pub qualifier: Option<AnyRef<'a>>,
}

/// CpsUri as defined in [RFC 5280 Section 4.2.1.4].
///
/// ```text
/// CPSuri ::= IA5String
/// ```
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
pub type CpsUri<'a> = Ia5StringRef<'a>;

/// UserNotice as defined in [RFC 5280 Section 4.2.1.4].
///
/// ```text
/// UserNotice ::= SEQUENCE {
///     noticeRef        NoticeReference OPTIONAL,
///     explicitText     DisplayText OPTIONAL
/// }
/// ```
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct UserNotice<'a> {
    pub notice_ref: Option<GeneralizedTime>,
    pub explicit_text: Option<DisplayText<'a>>,
}

/// NoticeReference as defined in [RFC 5280 Section 4.2.1.4].
///
/// ```text
/// NoticeReference ::= SEQUENCE {
///      organization     DisplayText,
///      noticeNumbers    SEQUENCE OF INTEGER }
/// ```
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct NoticeReference<'a> {
    pub organization: DisplayText<'a>,
    pub notice_numbers: Option<Vec<UIntRef<'a>>>,
}

/// DisplayText as defined in [RFC 5280 Section 4.2.1.4].
///
/// ```text
/// DisplayText ::= CHOICE {
///     ia5String        IA5String      (SIZE (1..200)),
///     visibleString    VisibleString  (SIZE (1..200)),
///     bmpString        BMPString      (SIZE (1..200)),
///     utf8String       UTF8String     (SIZE (1..200))
/// }
/// ```
///
/// Only the ia5String and utf8String options are currently supported.
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
#[derive(Choice, Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum DisplayText<'a> {
    #[asn1(type = "IA5String")]
    Ia5String(Ia5StringRef<'a>),

    #[asn1(type = "UTF8String")]
    Utf8String(Utf8StringRef<'a>),
}
