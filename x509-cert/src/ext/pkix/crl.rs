//! PKIX Certificate Revocation List extensions

pub mod dp;

use const_oid::db::rfc5280::{
    ID_CE_CRL_DISTRIBUTION_POINTS, ID_CE_CRL_NUMBER, ID_CE_CRL_REASONS, ID_CE_DELTA_CRL_INDICATOR,
    ID_CE_FRESHEST_CRL,
};
use const_oid::{AssociatedOid, ObjectIdentifier};
pub use dp::IssuingDistributionPoint;

use alloc::vec::Vec;

use der::{asn1::UIntRef, Enumerated};

/// CrlNumber as defined in [RFC 5280 Section 5.2.3].
///
/// ```text
/// CRLNumber ::= INTEGER (0..MAX)
/// ```
///
/// [RFC 5280 Section 5.2.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.3
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CrlNumber<'a>(pub UIntRef<'a>);

impl<'a> AssociatedOid for CrlNumber<'a> {
    const OID: ObjectIdentifier = ID_CE_CRL_NUMBER;
}

impl_newtype!(CrlNumber<'a>, UIntRef<'a>);

/// BaseCRLNumber as defined in [RFC 5280 Section 5.2.4].
///
/// ```text
/// BaseCRLNumber ::= CRLNumber
/// ```
///
/// [RFC 5280 Section 5.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.4
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BaseCrlNumber<'a>(pub UIntRef<'a>);

impl<'a> AssociatedOid for BaseCrlNumber<'a> {
    const OID: ObjectIdentifier = ID_CE_DELTA_CRL_INDICATOR;
}

impl_newtype!(BaseCrlNumber<'a>, UIntRef<'a>);

/// CrlDistributionPoints as defined in [RFC 5280 Section 4.2.1.13].
///
/// ```text
/// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
/// ```
///
/// [RFC 5280 Section 4.2.1.13]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CrlDistributionPoints(pub Vec<dp::DistributionPoint>);

impl AssociatedOid for CrlDistributionPoints {
    const OID: ObjectIdentifier = ID_CE_CRL_DISTRIBUTION_POINTS;
}

impl_newtype!(CrlDistributionPoints, Vec<dp::DistributionPoint>);

/// FreshestCrl as defined in [RFC 5280 Section 5.2.6].
///
/// ```text
/// FreshestCRL ::= CRLDistributionPoints
/// ```
///
/// [RFC 5280 Section 5.2.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.6
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FreshestCrl(pub Vec<dp::DistributionPoint>);

impl AssociatedOid for FreshestCrl {
    const OID: ObjectIdentifier = ID_CE_FRESHEST_CRL;
}

impl_newtype!(FreshestCrl, Vec<dp::DistributionPoint>);

/// CRLReason as defined in [RFC 5280 Section 5.3.1].
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

impl AssociatedOid for CrlReason {
    const OID: ObjectIdentifier = ID_CE_CRL_REASONS;
}
