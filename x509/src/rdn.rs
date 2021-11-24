//! Name-related definitions as defined in RFC 5280.

use crate::AttributeTypeAndValue;
use der::asn1::SetOf;

/// RelativeDistinguishedName as defined in [RFC 5280 Section 4.1.2.4].
///
/// ```text
/// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
pub type RelativeDistinguishedName<'a> = SetOf<AttributeTypeAndValue<'a>, 3>;
// TODO - make dynamic
//pub type RelativeDistinguishedName<'a> = alloc::vec::Vec<AttributeTypeAndValue<'a>>;

/// RDNSequence as defined in [RFC 5280 Section 4.1.2.4].
///
/// ```text
/// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
pub type RDNSequence<'a> = alloc::vec::Vec<RelativeDistinguishedName<'a>>;

/// X.501 Name as defined in [RFC 5280 Section 4.1.2.4]. X.501 Name is used to represent distinguished names.
///
/// ```text
/// Name ::= CHOICE { rdnSequence  RDNSequence }
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
pub type Name<'a> = RDNSequence<'a>;

//TODO - Name to string function
