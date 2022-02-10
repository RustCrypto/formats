//! PKIX Name Constraint extension

use alloc::vec::Vec;

use der::Sequence;

use super::super::name::GeneralName;

/// NameConstraints extension as defined in [RFC 5280 Section 4.2.1.10].
///
/// This extension is identified by the [`PKIX_CE_NAME_CONSTRAINTS`](constant.PKIX_CE_NAME_CONSTRAINTS.html) OID.
///
/// ```text
/// NameConstraints ::= SEQUENCE {
///      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
///      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL
/// }
/// ```
///
/// [RFC 5280 Section 4.2.1.10]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct NameConstraints<'a> {
    #[asn1(context_specific = "0", optional = "true", tag_mode = "IMPLICIT")]
    pub permitted_subtrees: Option<GeneralSubtrees<'a>>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    pub excluded_subtrees: Option<GeneralSubtrees<'a>>,
}

/// GeneralSubtrees as defined in [RFC 5280 Section 4.2.1.10].
///
/// ```text
/// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
/// ```
///
/// [RFC 5280 Section 4.2.1.10]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
pub type GeneralSubtrees<'a> = Vec<GeneralSubtree<'a>>;

/// GeneralSubtree as defined in [RFC 5280 Section 4.2.1.10].
///
/// ```text
/// GeneralSubtree ::= SEQUENCE {
///     base                    GeneralName,
///     minimum         [0]     BaseDistance DEFAULT 0,
///     maximum         [1]     BaseDistance OPTIONAL
/// }
/// ```
///
/// [RFC 5280 Section 4.2.1.10]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct GeneralSubtree<'a> {
    pub base: GeneralName<'a>,

    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        default = "Default::default"
    )]
    pub minimum: u32,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub maximum: Option<u32>,
}
