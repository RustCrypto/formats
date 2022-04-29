//! PKIX X.509 Certificate Extensions (RFC 5280)

pub mod certpolicy;
pub mod constraints;
pub mod crl;
pub mod name;

mod access;
mod authkeyid;
mod keyusage;
mod policymap;

use crate::attr::AttributeTypeAndValue;

pub use access::{AccessDescription, AuthorityInfoAccessSyntax, SubjectInfoAccessSyntax};
pub use authkeyid::AuthorityKeyIdentifier;
pub use certpolicy::CertificatePolicies;
use const_oid::{AssociatedOid, ObjectIdentifier};
pub use constraints::{BasicConstraints, NameConstraints, PolicyConstraints};
pub use crl::{
    BaseCrlNumber, CrlDistributionPoints, CrlNumber, CrlReason, FreshestCrl,
    IssuingDistributionPoint,
};
pub use keyusage::{ExtendedKeyUsage, KeyUsage, KeyUsages, PrivateKeyUsagePeriod};
pub use policymap::{PolicyMapping, PolicyMappings};

pub use const_oid::db::rfc5280::{
    ID_CE_INHIBIT_ANY_POLICY, ID_CE_ISSUER_ALT_NAME, ID_CE_SUBJECT_ALT_NAME,
    ID_CE_SUBJECT_DIRECTORY_ATTRIBUTES, ID_CE_SUBJECT_KEY_IDENTIFIER,
};

use alloc::vec::Vec;

use der::asn1::OctetString;

/// SubjectKeyIdentifier as defined in [RFC 5280 Section 4.2.1.2].
///
/// ```text
/// SubjectKeyIdentifier ::= KeyIdentifier
/// ```
///
/// [RFC 5280 Section 4.2.1.2]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SubjectKeyIdentifier<'a>(pub OctetString<'a>);

impl<'a> AssociatedOid for SubjectKeyIdentifier<'a> {
    const OID: ObjectIdentifier = ID_CE_SUBJECT_KEY_IDENTIFIER;
}

impl_newtype!(SubjectKeyIdentifier<'a>, OctetString<'a>);

/// SubjectAltName as defined in [RFC 5280 Section 4.2.1.6].
///
/// ```text
/// SubjectAltName ::= GeneralNames
/// ```
///
/// [RFC 5280 Section 4.2.1.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubjectAltName<'a>(pub name::GeneralNames<'a>);

impl<'a> AssociatedOid for SubjectAltName<'a> {
    const OID: ObjectIdentifier = ID_CE_SUBJECT_ALT_NAME;
}

impl_newtype!(SubjectAltName<'a>, name::GeneralNames<'a>);

/// IssuerAltName as defined in [RFC 5280 Section 4.2.1.7].
///
/// ```text
/// IssuerAltName ::= GeneralNames
/// ```
///
/// [RFC 5280 Section 4.2.1.7]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.7
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssuerAltName<'a>(pub name::GeneralNames<'a>);

impl<'a> AssociatedOid for IssuerAltName<'a> {
    const OID: ObjectIdentifier = ID_CE_ISSUER_ALT_NAME;
}

impl_newtype!(IssuerAltName<'a>, name::GeneralNames<'a>);

/// SubjectDirectoryAttributes as defined in [RFC 5280 Section 4.2.1.8].
///
/// ```text
/// SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF AttributeSet
/// ```
///
/// [RFC 5280 Section 4.2.1.8]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.8
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubjectDirectoryAttributes<'a>(pub Vec<AttributeTypeAndValue<'a>>);

impl<'a> AssociatedOid for SubjectDirectoryAttributes<'a> {
    const OID: ObjectIdentifier = ID_CE_SUBJECT_DIRECTORY_ATTRIBUTES;
}

impl_newtype!(
    SubjectDirectoryAttributes<'a>,
    Vec<AttributeTypeAndValue<'a>>
);

/// InhibitAnyPolicy as defined in [RFC 5280 Section 4.2.1.14].
///
/// ```text
/// InhibitAnyPolicy ::= SkipCerts
/// ```
///
/// [RFC 5280 Section 4.2.1.14]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.14
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct InhibitAnyPolicy(pub u32);

impl AssociatedOid for InhibitAnyPolicy {
    const OID: ObjectIdentifier = ID_CE_INHIBIT_ANY_POLICY;
}

impl_newtype!(InhibitAnyPolicy, u32);
