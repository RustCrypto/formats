use der::asn1::{Any, ObjectIdentifier, SetOfVec};
use der::{Decodable, Sequence, ValueOrd};

/// PKCS#10 `Attribute` as defined in [RFC 5280 Appendix A.1].
///
/// ```text
/// Attribute               ::= SEQUENCE {
///     type             AttributeType,
///     values    SET OF AttributeValue -- at least one value is required
/// }
///
/// AttributeType           ::= OBJECT IDENTIFIER
///
/// AttributeValue          ::= ANY -- DEFINED BY AttributeType
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
    /// Attribute kind (OID).
    pub oid: ObjectIdentifier,

    /// Attribute values.
    pub values: SetOfVec<Any<'a>>,
}

impl<'a> TryFrom<&'a [u8]> for Attribute<'a> {
    type Error = der::Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::from_der(bytes)
    }
}

/// PKCS#10 `Attributes` as defined in [RFC 2986 Section 4].
///
/// ```text
/// Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
/// ```
///
/// [RFC 2986 Section 4]: https://datatracker.ietf.org/doc/html/rfc2986#section-4
pub type Attributes<'a> = SetOfVec<Attribute<'a>>;
