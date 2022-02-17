use alloc::vec::Vec;

use der::asn1::ObjectIdentifier;
use der::Sequence;

/// PolicyMappings as defined in [RFC 5280 Section 4.2.1.5].
///
/// This extension is identified by the [`PKIX_CE_POLICY_MAPPINGS`](constant.PKIX_CE_POLICY_MAPPINGS.html) OID.
///
/// ```text
/// PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
/// ```
///
/// [RFC 5280 Section 4.2.1.5]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.5
pub type PolicyMappings<'a> = Vec<PolicyMapping>;

/// PolicyMapping as defined in [RFC 5280 Section 4.2.1.5].
///
/// ```text
/// PolicyMapping ::= SEQUENCE {
///     issuerDomainPolicy      CertPolicyId,
///     subjectDomainPolicy     CertPolicyId
/// }
/// ```
///
/// [RFC 5280 Section 4.2.1.5]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.5
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PolicyMapping {
    /// issuerDomainPolicy      CertPolicyId,
    pub issuer_domain_policy: ObjectIdentifier,

    /// subjectDomainPolicy     CertPolicyId }
    pub subject_domain_policy: ObjectIdentifier,
}
