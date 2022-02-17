//! PKIX Certificate Revocation List extensions

pub mod dp;

pub use dp::IssuingDistributionPoint;

use alloc::vec::Vec;

use der::{asn1::UIntBytes, Enumerated};

/// CrlNumber as defined in [RFC 5280 Section 5.2.3].
///
/// This extension is identified by the [`PKIX_CE_CRLNUMBER`](constant.PKIX_CE_CRLNUMBER.html) OID.
///
/// ```text
/// CRLNumber ::= INTEGER (0..MAX)
/// ```
///
/// [RFC 5280 Section 5.2.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.3
pub type CrlNumber<'a> = UIntBytes<'a>;

/// BaseCRLNumber as defined in [RFC 5280 Section 5.2.4].
///
/// This extension is identified by the [`PKIX_CE_DELTACRLINDICATOR`](constant.PKIX_CE_DELTACRLINDICATOR.html) OID.
///
/// ```text
/// BaseCRLNumber ::= CRLNumber
/// ```
///
/// [RFC 5280 Section 5.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.4
pub type BaseCrlNumber<'a> = CrlNumber<'a>;

/// CrlDistributionPoints as defined in [RFC 5280 Section 4.2.1.13].
///
/// This extension is identified by the [`PKIX_CE_CRL_DISTRIBUTION_POINTS`](constant.PKIX_CE_CRL_DISTRIBUTION_POINTS.html) OID.
///
/// ```text
/// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
/// ```
///
/// [RFC 5280 Section 4.2.1.13]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
pub type CrlDistributionPoints<'a> = Vec<dp::DistributionPoint<'a>>;

/// FreshestCrl as defined in [RFC 5280 Section 5.2.6].
///
/// This extension is identified by the [`PKIX_CE_FRESHEST_CRL`](constant.PKIX_CE_FRESHEST_CRL.html) OID.
///
/// ```text
/// FreshestCRL ::= CRLDistributionPoints
/// ```
///
/// [RFC 5280 Section 5.2.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.6
pub type FreshestCrl<'a> = CrlDistributionPoints<'a>;

/// CRLReason as defined in [RFC 5280 Section 5.3.1].
///
/// This extension is identified by the [`PKIX_CE_CRLREASONS`](constant.PKIX_CE_CRLREASONS.html) OID.
///
/// ```text
/// CRLReason ::= ENUMERATED {
///     unspecified             (0),
///     keyCompromise           (1),
///     cACompromise            (2),
///     affiliationChanged      (3),
///     superseded              (4),
///     cessationOfOperation    (5),
///     certificateHold         (6),
///     removeFromCRL           (8),
///     privilegeWithdrawn      (9),
///     aACompromise           (10)
/// }
/// ```
///
/// [RFC 5280 Section 5.3.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1
#[derive(Copy, Clone, Debug, Eq, PartialEq, Enumerated)]
#[allow(missing_docs)]
#[repr(u32)]
pub enum CrlReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCRL = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}
