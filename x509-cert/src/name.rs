//! Name-related definitions as defined in X.501 (and updated by RFC 5280).

use crate::attr::AttributeTypeAndValue;
use alloc::vec::Vec;
use core::fmt;
use der::{asn1::SetOfVec, Decode, Encode};

/// X.501 Name as defined in [RFC 5280 Section 4.1.2.4]. X.501 Name is used to represent distinguished names.
///
/// ```text
/// Name ::= CHOICE { rdnSequence  RDNSequence }
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
pub type Name = RdnSequence;

/// X.501 RDNSequence as defined in [RFC 5280 Section 4.1.2.4].
///
/// ```text
/// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RdnSequence(pub Vec<RelativeDistinguishedName>);

impl RdnSequence {
    /// Converts an RDNSequence string into an encoded RDNSequence
    ///
    /// This function follows the rules in [RFC 4514].
    ///
    /// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
    pub fn encode_from_string(s: &str) -> Result<Vec<u8>, der::Error> {
        let ders = split(s, b',')
            .map(RelativeDistinguishedName::encode_from_string)
            .collect::<Result<Vec<_>, der::Error>>()?;

        let mut out = Vec::new();
        for der in ders.iter() {
            out.push(RelativeDistinguishedName::from_der(der)?);
        }

        RdnSequence(out).to_vec()
    }
}

/// Serializes the structure according to the rules in [RFC 4514].
///
/// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
impl fmt::Display for RdnSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, atv) in self.0.iter().enumerate() {
            match i {
                0 => write!(f, "{}", atv)?,
                _ => write!(f, ",{}", atv)?,
            }
        }

        Ok(())
    }
}

impl_newtype!(RdnSequence, Vec<RelativeDistinguishedName>);

/// Find the indices of all non-escaped separators.
fn find(s: &str, b: u8) -> impl '_ + Iterator<Item = usize> {
    (0..s.len())
        .filter(move |i| s.as_bytes()[*i] == b)
        .filter(|i| {
            let x = i
                .checked_sub(2)
                .map(|i| s.as_bytes()[i])
                .unwrap_or_default();

            let y = i
                .checked_sub(1)
                .map(|i| s.as_bytes()[i])
                .unwrap_or_default();

            y != b'\\' || x == b'\\'
        })
}

/// Split a string at all non-escaped separators.
fn split(s: &str, b: u8) -> impl '_ + Iterator<Item = &'_ str> {
    let mut prev = 0;
    find(s, b).chain([s.len()].into_iter()).map(move |i| {
        let x = &s[prev..i];
        prev = i + 1;
        x
    })
}

/// X.501 DistinguishedName as defined in [RFC 5280 Section 4.1.2.4].
///
/// ```text
/// DistinguishedName ::=   RDNSequence
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
pub type DistinguishedName = RdnSequence;

/// RelativeDistinguishedName as defined in [RFC 5280 Section 4.1.2.4].
///
/// ```text
/// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
/// ```
///
/// Note that we follow the more common definition above. This technically
/// differs from the definition in X.501, which is:
///
/// ```text
/// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndDistinguishedValue
///
/// AttributeTypeAndDistinguishedValue ::= SEQUENCE {
///     type ATTRIBUTE.&id ({SupportedAttributes}),
///     value ATTRIBUTE.&Type({SupportedAttributes}{@type}),
///     primaryDistinguished BOOLEAN DEFAULT TRUE,
///     valuesWithContext SET SIZE (1..MAX) OF SEQUENCE {
///         distingAttrValue [0] ATTRIBUTE.&Type ({SupportedAttributes}{@type}) OPTIONAL,
///         contextList SET SIZE (1..MAX) OF Context
///     } OPTIONAL
/// }
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelativeDistinguishedName(pub SetOfVec<AttributeTypeAndValue>);

impl RelativeDistinguishedName {
    /// Converts an RelativeDistinguishedName string into an encoded RelativeDistinguishedName
    ///
    /// This function follows the rules in [RFC 4514].
    ///
    /// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
    pub fn encode_from_string(s: &str) -> Result<Vec<u8>, der::Error> {
        let ders = split(s, b'+')
            .map(AttributeTypeAndValue::encode_from_string)
            .collect::<Result<Vec<_>, der::Error>>()?;

        let atvs = ders
            .iter()
            .map(|der| AttributeTypeAndValue::from_der(der))
            .collect::<Result<Vec<_>, der::Error>>()?;

        RelativeDistinguishedName(atvs.try_into()?).to_vec()
    }
}

/// Serializes the structure according to the rules in [RFC 4514].
///
/// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
impl fmt::Display for RelativeDistinguishedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, atv) in self.0.iter().enumerate() {
            match i {
                0 => write!(f, "{}", atv)?,
                _ => write!(f, "+{}", atv)?,
            }
        }

        Ok(())
    }
}

impl_newtype!(RelativeDistinguishedName, SetOfVec<AttributeTypeAndValue>);
