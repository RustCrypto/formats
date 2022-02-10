//! PKIX X.509 Certificate Extensions (RFC 5280)

pub mod certpolicy;
pub mod constraints;
pub mod name;
pub mod oids;

mod access;
mod authkeyid;
mod keyusage;
mod policymap;

pub use access::{AccessDescription, AuthorityInfoAccessSyntax, SubjectInfoAccessSyntax};
pub use authkeyid::AuthorityKeyIdentifier;
pub use certpolicy::CertificatePolicies;
pub use constraints::{BasicConstraints, NameConstraints, PolicyConstraints};
pub use keyusage::{ExtendedKeyUsage, KeyUsage, KeyUsages};
pub use policymap::{PolicyMapping, PolicyMappings};

use alloc::vec::Vec;

use der::asn1::OctetString;
use x501::attr::AttributeTypeAndValue;

/// SubjectKeyIdentifier as defined in [RFC 5280 Section 4.2.1.2].
///
/// This extension is identified by the [`PKIX_CE_SUBJECT_KEY_IDENTIFIER`](constant.PKIX_CE_SUBJECT_KEY_IDENTIFIER.html) OID.
///
/// ```text
/// SubjectKeyIdentifier ::= KeyIdentifier
/// ```
///
/// [RFC 5280 Section 4.2.1.2]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
pub type SubjectKeyIdentifier<'a> = OctetString<'a>;

/// SubjectAltName as defined in [RFC 5280 Section 4.2.1.6].
///
/// This extension is identified by the [`PKIX_CE_SUBJECT_ALT_NAME`](constant.PKIX_CE_SUBJECT_ALT_NAME.html) OID.
///
/// ```text
/// SubjectAltName ::= GeneralNames
/// ```
///
/// [RFC 5280 Section 4.2.1.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
pub type SubjectAltName<'a> = name::GeneralNames<'a>;

/// IssuerAltName as defined in [RFC 5280 Section 4.2.1.7].
///
/// This extension is identified by the [`PKIX_CE_ISSUER_ALT_NAME`](constant.PKIX_CE_ISSUER_ALT_NAME.html) OID.
///
/// ```text
/// IssuerAltName ::= GeneralNames
/// ```
///
/// [RFC 5280 Section 4.2.1.7]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.7
pub type IssuerAltName<'a> = name::GeneralNames<'a>;

/// SubjectDirectoryAttributes as defined in [RFC 5280 Section 4.2.1.8].
///
/// This extension is identified by the [`PKIX_CE_SUBJECT_DIRECTORY_ATTRIBUTES`](constant.PKIX_CE_SUBJECT_DIRECTORY_ATTRIBUTES.html) OID.
///
/// ```text
/// SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF AttributeSet
/// ```
///
/// [RFC 5280 Section 4.2.1.8]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.8
pub type SubjectDirectoryAttributes<'a> = Vec<AttributeTypeAndValue<'a>>;

/// InhibitAnyPolicy as defined in [RFC 5280 Section 4.2.1.14].
///
/// This extension is identified by the [`PKIX_CE_INHIBIT_ANY_POLICY`](constant.PKIX_CE_INHIBIT_ANY_POLICY.html) OID.
///
/// ```text
/// InhibitAnyPolicy ::= SkipCerts
/// ```
///
/// [RFC 5280 Section 4.2.1.14]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.14
pub type InhibitAnyPolicy = u32;
