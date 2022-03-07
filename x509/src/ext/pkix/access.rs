use super::name::GeneralName;

use alloc::vec::Vec;

use der::{asn1::ObjectIdentifier, Sequence};

/// AuthorityInfoAccessSyntax as defined in [RFC 5280 Section 4.2.2.1].
///
/// This extension is identified by the [`PKIX_PE_AUTHORITYINFOACCESS`](constant.PKIX_PE_AUTHORITYINFOACCESS.html) OID.
///
/// ```text
/// AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
/// ```
///
/// [RFC 5280 Section 4.2.2.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1
pub type AuthorityInfoAccessSyntax<'a> = Vec<AccessDescription<'a>>;

/// SubjectInfoAccessSyntax as defined in [RFC 5280 Section 4.2.2.2].
///
/// This extension is identified by the [`PKIX_PE_SUBJECTINFOACCESS`](constant.PKIX_PE_SUBJECTINFOACCESS.html) OID.
///
/// ```text
/// SubjectInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
/// ```
///
/// [RFC 5280 Section 4.2.2.2]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.2
pub type SubjectInfoAccessSyntax<'a> = Vec<AccessDescription<'a>>;

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
