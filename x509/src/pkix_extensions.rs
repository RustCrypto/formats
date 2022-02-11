//! Extensions [`Extensions`] as defined in RFC 5280

use crate::ext::pkix::name::{DistributionPointName, GeneralNames};

use alloc::vec::Vec;

use der::asn1::*;
use der::{Enumerated, Sequence};
use flagset::{flags, FlagSet};

/// CRL number extension as defined in [RFC 5280 Section 5.2.3] and as identified by the [`PKIX_CE_CRLNUMBER`](constant.PKIX_CE_CRLNUMBER.html) OID.
///
/// ```text
/// CRLNumber ::= INTEGER (0..MAX)
/// ```
///
/// [RFC 5280 Section 5.2.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.3
pub type CRLNumber<'a> = UIntBytes<'a>;

/// Delta CRL indicator extension as defined in [RFC 5280 Section 5.2.4] and as identified by the [`PKIX_CE_DELTACRLINDICATOR`](constant.PKIX_CE_DELTACRLINDICATOR.html) OID.
///
/// ```text
/// BaseCRLNumber ::= CRLNumber
/// ```
///
/// [RFC 5280 Section 5.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.4
pub type BaseCRLNumber<'a> = CRLNumber<'a>;

/// Reason code extension as defined in [RFC 5280 Section 5.3.1] and as identified by the [`PKIX_CE_CRLREASONS`](constant.PKIX_CE_CRLREASONS.html) OID.
///
/// ```text
/// CRLReason ::= ENUMERATED {
///      unspecified             (0),
///      keyCompromise           (1),
///      cACompromise            (2),
///      affiliationChanged      (3),
///      superseded              (4),
///      cessationOfOperation    (5),
///      certificateHold         (6),
///      removeFromCRL           (8),
///      privilegeWithdrawn      (9),
///      aACompromise           (10) }
/// ```
///
/// [RFC 5280 Section 5.3.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1
#[derive(Enumerated, Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CRLReason {
    /// unspecified             (0),
    Unspecified = 0,
    /// keyCompromise           (1),
    KeyCompromise = 1,
    /// cACompromise            (2),
    CaCompromise = 2,
    /// affiliationChanged      (3),
    AffiliationChanged = 3,
    /// superseded              (4),
    Superseded = 4,
    /// cessationOfOperation    (5),
    CessationOfOperation = 5,
    /// certificateHold         (6),
    CertificateHold = 6,
    /// removeFromCRL           (8),
    RemoveFromCRL = 8,
    /// privilegeWithdrawn      (9),
    PrivilegeWithdrawn = 9,
    /// aACompromise           (10)
    AaCompromise = 10,
}

flags! {
    /// Reason flags as defined in [RFC 5280 Section 4.2.1.13].
    ///
    /// ```text
    /// ReasonFlags ::= BIT STRING {
    ///      unused                  (0),
    ///      keyCompromise           (1),
    ///      cACompromise            (2),
    ///      affiliationChanged      (3),
    ///      superseded              (4),
    ///      cessationOfOperation    (5),
    ///      certificateHold         (6),
    ///      privilegeWithdrawn      (7),
    ///      aACompromise            (8) }
    /// ```
    ///
    /// [RFC 5280 Section 4.2.1.13]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
    #[allow(missing_docs)]
    pub enum Reasons: u16 {
        Unused = 1 << 0,
        KeyCompromise = 1 << 1,
        CaCompromise = 1 << 2,
        AffiliationChanged = 1 << 3,
        Superseded = 1 << 4,
        CessationOfOperation = 1 << 5,
        CertificateHold = 1 << 6,
        PrivilegeWithdrawn = 1 << 7,
        AaCompromise = 1 << 8,
    }
}

/// `ReasonFlags` as defined in [RFC 5280 Section 4.2.1.13] in support of the CRL distribution points extension.
///
/// [RFC 5280 Section 4.2.1.13]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
pub type ReasonFlags = FlagSet<Reasons>;

/// CRL distribution points extension as defined in [RFC 5280 Section 4.2.1.13] and as identified by the [`PKIX_CE_CRL_DISTRIBUTION_POINTS`](constant.PKIX_CE_CRL_DISTRIBUTION_POINTS.html) OID.
///
/// ```text
/// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
/// ```
///
/// [RFC 5280 Section 4.2.1.13]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
pub type CRLDistributionPoints<'a> = Vec<DistributionPoint<'a>>;

/// DistributionPoint as defined in [RFC 5280 Section 4.2.1.13].
///
/// ```text
/// DistributionPoint ::= SEQUENCE {
///     distributionPoint       [0]     DistributionPointName OPTIONAL,
///     reasons                 [1]     ReasonFlags OPTIONAL,
///     cRLIssuer               [2]     GeneralNames OPTIONAL
/// }
/// ```
///
/// [RFC 5280 Section 4.2.1.13]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct DistributionPoint<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub distribution_point: Option<DistributionPointName<'a>>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub reasons: Option<ReasonFlags>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub crl_issuer: Option<GeneralNames<'a>>,
}

/// Freshest CRL extension as defined in [RFC 5280 Section 5.2.6] and as identified by the [`PKIX_CE_FRESHEST_CRL`](constant.PKIX_CE_FRESHEST_CRL.html) OID.
///
/// ```text
/// FreshestCRL ::= CRLDistributionPoints
/// ```
///
/// [RFC 5280 Section 5.2.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.6
pub type FreshestCRL<'a> = CRLDistributionPoints<'a>;

/// IssuingDistributionPoint as defined in [RFC 5280 Section 5.2.5].
///
/// This extension is identified by the [`PKIX_PE_SUBJECTINFOACCESS`](constant.PKIX_PE_SUBJECTINFOACCESS.html) OID.
///
/// ```text
/// IssuingDistributionPoint ::= SEQUENCE {
///     distributionPoint          [0] DistributionPointName OPTIONAL,
///     onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
///     onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
///     onlySomeReasons            [3] ReasonFlags OPTIONAL,
///     indirectCRL                [4] BOOLEAN DEFAULT FALSE,
///     onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE
///     -- at most one of onlyContainsUserCerts, onlyContainsCACerts,
///     -- and onlyContainsAttributeCerts may be set to TRUE.
/// }
/// ```
///
/// [RFC 5280 Section 5.2.5]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.5
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct IssuingDistributionPoint<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub distribution_point: Option<DistributionPointName<'a>>,

    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        default = "Default::default"
    )]
    pub only_contains_user_certs: bool,

    #[asn1(
        context_specific = "2",
        tag_mode = "IMPLICIT",
        default = "Default::default"
    )]
    pub only_contains_ca_certs: bool,

    #[asn1(context_specific = "3", tag_mode = "IMPLICIT", optional = "true")]
    pub only_some_reasons: Option<ReasonFlags>,

    #[asn1(
        context_specific = "4",
        tag_mode = "IMPLICIT",
        default = "Default::default"
    )]
    pub indirect_crl: bool,

    #[asn1(
        context_specific = "5",
        tag_mode = "IMPLICIT",
        default = "Default::default"
    )]
    pub only_contains_attribute_certs: bool,
}
