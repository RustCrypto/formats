use der::Sequence;

/// BasicConstraints as defined in [RFC 5280 Section 4.2.1.9].
///
/// This extension is identified by the [`PKIX_CE_BASIC_CONSTRAINTS`](constant.PKIX_CE_BASIC_CONSTRAINTS.html) OID.
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
