use const_oid::{db::rfc5280::ID_CE_BASIC_CONSTRAINTS, AssociatedOid, ObjectIdentifier};
use der::Sequence;

/// BasicConstraints as defined in [RFC 5280 Section 4.2.1.9].
///
/// ```text
/// BasicConstraints ::= SEQUENCE {
///     cA                      BOOLEAN DEFAULT FALSE,
///     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
/// }
/// ```
///
/// [RFC 5280 Section 4.2.1.9]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct BasicConstraints {
    #[asn1(default = "Default::default")]
    pub ca: bool,
    pub path_len_constraint: Option<u8>,
}

impl AssociatedOid for BasicConstraints {
    const OID: ObjectIdentifier = ID_CE_BASIC_CONSTRAINTS;
}
