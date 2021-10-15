//! Relative Distinguished Names

use crate::AttributeTypeAndValue;
use der::asn1::{SequenceOf, SetOf};

// Name ::= CHOICE { rdnSequence  RDNSequence }
// DistinguishedName ::=   RDNSequence
// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue

/// Relative Distinguished Name
pub type RelativeDistinguishedName<'a> = SetOf<AttributeTypeAndValue<'a>, 3>;

/// RDNSequence
pub type RDNSequence<'a> = SequenceOf<RelativeDistinguishedName<'a>, 10>;
