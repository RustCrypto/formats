//! Attribute-related definitions as defined in X.501 (and updated by RFC 5280).

use der::asn1::{Any, ObjectIdentifier, SetOfVec};
use der::{Decodable, Sequence, ValueOrd};

/// X.501 `AttributeType` as defined in [RFC 5280 Appendix A.1].
///
/// ```text
/// AttributeType           ::= OBJECT IDENTIFIER
/// ```
///
/// [RFC 5280 Appendix A.1]: https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1
pub type AttributeType = ObjectIdentifier;

/// X.501 `AttributeValue` as defined in [RFC 5280 Appendix A.1].
///
/// ```text
/// AttributeValue          ::= ANY
/// ```
///
/// [RFC 5280 Appendix A.1]: https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1
pub type AttributeValue<'a> = Any<'a>;

/// X.501 `Attribute` as defined in [RFC 5280 Appendix A.1].
///
/// ```text
/// Attribute               ::= SEQUENCE {
///     type             AttributeType,
///     values    SET OF AttributeValue -- at least one value is required
/// }
/// ```
///
/// Note that [RFC 2986 Section 4] defines a constrained version of this type:
///
/// ```text
/// Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
///     type   ATTRIBUTE.&id({IOSet}),
///     values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
/// }
/// ```
///
/// The unconstrained version should be preferred.
///
/// [RFC 2986 Section 4]: https://datatracker.ietf.org/doc/html/rfc2986#section-4
/// [RFC 5280 Appendix A.1]: https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1
#[derive(Clone, Debug, PartialEq, Eq, Sequence, ValueOrd)]
pub struct Attribute<'a> {
    /// Attribute type (OID).
    pub oid: AttributeType,

    /// Attribute values.
    pub values: SetOfVec<AttributeValue<'a>>,
}

impl<'a> TryFrom<&'a [u8]> for Attribute<'a> {
    type Error = der::Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::from_der(bytes)
    }
}

/// X.501 `Attributes` as defined in [RFC 2986 Section 4].
///
/// ```text
/// Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
/// ```
///
/// [RFC 2986 Section 4]: https://datatracker.ietf.org/doc/html/rfc2986#section-4
pub type Attributes<'a> = SetOfVec<Attribute<'a>>;

/// X.501 `AttributeTypeAndValue` as defined in [RFC 5280 Appendix A.1].
///
/// ```text
/// AttributeTypeAndValue ::= SEQUENCE {
///   type     AttributeType,
///   value    AttributeValue
/// }
/// ```
///
/// [RFC 5280 Appendix A.1]: https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct AttributeTypeAndValue<'a> {
    /// OID describing the type of the attribute
    pub oid: AttributeType,

    /// Value of the attribute
    pub value: Any<'a>,
}
