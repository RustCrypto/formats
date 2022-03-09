use alloc::vec::Vec;

use const_oid::db::rfc5280::{
    ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE, ID_CE_PRIVATE_KEY_USAGE_PERIOD,
};
use const_oid::AssociatedOid;
use der::asn1::{GeneralizedTime, ObjectIdentifier};
use der::{Newtype, Sequence};
use flagset::{flags, FlagSet};

flags! {
    /// Key usage flags as defined in [RFC 5280 Section 4.2.1.3].
    ///
    /// ```text
    /// KeyUsage ::= BIT STRING {
    ///      digitalSignature        (0),
    ///      nonRepudiation          (1),  -- recent editions of X.509 have
    ///                                    -- renamed this bit to contentCommitment
    ///      keyEncipherment         (2),
    ///      dataEncipherment        (3),
    ///      keyAgreement            (4),
    ///      keyCertSign             (5),
    ///      cRLSign                 (6),
    ///      encipherOnly            (7),
    ///      decipherOnly            (8)
    /// }
    /// ```
    ///
    /// [RFC 5280 Section 4.2.1.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
    #[allow(missing_docs)]
    pub enum KeyUsages: u16 {
        DigitalSignature = 1 << 0,
        NonRepudiation = 1 << 1,
        KeyEncipherment = 1 << 2,
        DataEncipherment = 1 << 3,
        KeyAgreement = 1 << 4,
        KeyCertSign = 1 << 5,
        CRLSign = 1 << 6,
        EncipherOnly = 1 << 7,
        DecipherOnly = 1 << 8,
    }
}

/// KeyUsage as defined in [RFC 5280 Section 4.2.1.3].
///
/// [RFC 5280 Section 4.2.1.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
#[derive(Copy, Clone, Debug, PartialEq, Eq, Newtype)]
pub struct KeyUsage(pub FlagSet<KeyUsages>);

impl AssociatedOid for KeyUsage {
    const OID: ObjectIdentifier = ID_CE_KEY_USAGE;
}

/// ExtKeyUsageSyntax as defined in [RFC 5280 Section 4.2.1.12].
///
/// Many extended key usage values include:
/// - [`PKIX_CE_ANYEXTENDEDKEYUSAGE`](constant.PKIX_CE_ANYEXTENDEDKEYUSAGE.html),
/// - [`PKIX_KP_SERVERAUTH`](constant.PKIX_KP_SERVERAUTH.html),
/// - [`PKIX_KP_CLIENTAUTH`](constant.PKIX_KP_CLIENTAUTH.html),
/// - [`PKIX_KP_CODESIGNING`](constant.PKIX_KP_CODESIGNING.html),
/// - [`PKIX_KP_EMAILPROTECTION`](constant.PKIX_KP_EMAILPROTECTION.html),
/// - [`PKIX_KP_TIMESTAMPING`](constant.PKIX_KP_TIMESTAMPING.html),
///
/// ```text
/// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
/// KeyPurposeId ::= OBJECT IDENTIFIER
/// ```
///
/// [RFC 5280 Section 4.2.1.12]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12
#[derive(Clone, Debug, PartialEq, Eq, Newtype)]
pub struct ExtendedKeyUsage(pub Vec<ObjectIdentifier>);

impl AssociatedOid for ExtendedKeyUsage {
    const OID: ObjectIdentifier = ID_CE_EXT_KEY_USAGE;
}

/// PrivateKeyUsagePeriod as defined in [RFC 3280 Section 4.2.1.4].
///
/// RFC 5280 states "use of this ISO standard extension is neither deprecated nor recommended for use in the Internet PKI."
///
/// ```text
/// PrivateKeyUsagePeriod ::= SEQUENCE {
///      notBefore       [0]     GeneralizedTime OPTIONAL,
///      notAfter        [1]     GeneralizedTime OPTIONAL }
///      -- either notBefore or notAfter MUST be present
/// ```
///
/// [RFC 3280 Section 4.2.1.12]: https://datatracker.ietf.org/doc/html/rfc3280#section-4.2.1.4
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct PrivateKeyUsagePeriod {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub not_before: Option<GeneralizedTime>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub not_after: Option<GeneralizedTime>,
}

impl AssociatedOid for PrivateKeyUsagePeriod {
    const OID: ObjectIdentifier = ID_CE_PRIVATE_KEY_USAGE_PERIOD;
}
