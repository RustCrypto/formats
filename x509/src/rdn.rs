//! Relative Distinguished Names

use crate::AttributeTypeAndValue;
use der::asn1::SetOf;

/// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
pub type RelativeDistinguishedName<'a> = SetOf<AttributeTypeAndValue<'a>, 3>;
// TODO - make dynamic
//pub type RelativeDistinguishedName<'a> = alloc::vec::Vec<AttributeTypeAndValue<'a>>;

// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
pub type RDNSequence<'a> = alloc::vec::Vec<RelativeDistinguishedName<'a>>;

/// Name ::= CHOICE { rdnSequence  RDNSequence }
pub type Name<'a> = RDNSequence<'a>;

//TODO - Name to string function
