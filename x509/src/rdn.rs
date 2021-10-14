//! Relative Distinguished Names

use crate::AttributeTypeAndValue;
use der::asn1::Sequence;

// Name ::= CHOICE { rdnSequence  RDNSequence }
// DistinguishedName ::=   RDNSequence
// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue

/// Relative Distinguished Name
//pub type RelativeDistinguishedName<'a> = SetOfRef<'a, AttributeTypeAndValue<'a>>;
// tmp definition
pub type RelativeDistinguishedName<'a> = Sequence<'a>;
