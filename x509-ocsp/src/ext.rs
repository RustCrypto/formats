//! OCSP Extensions

use crate::OcspGeneralizedTime;
use alloc::{boxed::Box, vec::Vec};
use const_oid::{
    AssociatedOid,
    db::rfc6960::{
        ID_PKIX_OCSP_ARCHIVE_CUTOFF, ID_PKIX_OCSP_CRL, ID_PKIX_OCSP_NONCE,
        ID_PKIX_OCSP_PREF_SIG_ALGS, ID_PKIX_OCSP_RESPONSE, ID_PKIX_OCSP_SERVICE_LOCATOR,
    },
};
use der::{
    Sequence, ValueOrd,
    asn1::{Ia5String, ObjectIdentifier, OctetString, Uint},
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    ext::{Criticality, Extension, pkix::AuthorityInfoAccessSyntax},
    impl_newtype,
    name::Name,
};

#[cfg(feature = "rand")]
use rand_core::CryptoRng;

// x509-cert's is not exported
macro_rules! impl_extension {
    ($newtype:ty, critical = $critical:expr) => {
        impl Criticality for $newtype {
            fn criticality(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
                $critical
            }
        }
    };
}

/// Nonce extension as defined in [RFC 6960 Section 4.4.1].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce(pub OctetString);

impl_newtype!(Nonce, OctetString);

// Some responders do not honor nonces
impl_extension!(Nonce, critical = false);

impl AssociatedOid for Nonce {
    const OID: ObjectIdentifier = ID_PKIX_OCSP_NONCE;
}

impl Nonce {
    /// Creates a Nonce object given the bytes
    pub fn new(bytes: impl Into<Box<[u8]>>) -> Result<Self, der::Error> {
        Ok(Self(OctetString::new(bytes)?))
    }

    /// Creates a Nonce object given a random generator and a length.
    ///
    /// A proposed but not (yet) accepted RFC [RFC 8954] wants to limit nonces. RFC 6960 has no
    /// mention of a minimum or maximum length.
    ///
    /// ```text
    /// Nonce ::= OCTET STRING(SIZE(1..32))
    /// ```
    #[cfg(feature = "rand")]
    pub fn generate<R>(rng: &mut R, length: usize) -> Result<Self, der::Error>
    where
        R: CryptoRng + ?Sized,
    {
        let mut bytes = alloc::vec![0; length];
        rng.fill_bytes(&mut bytes);
        Self::new(bytes)
    }
}

/// CrlReferences extension as defined in [RFC 6960 Section 4.4.2]
///
/// This does not seem to be its own type and just another name for CrlID
///
/// [RFC 6960 Section 4.4.2]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.2
pub type CrlReferences = CrlId;

/// CrlID structure as defined in [RFC 6960 Section 4.4.2].
///
/// ```text
/// CrlID ::= SEQUENCE {
///     crlUrl               [0] EXPLICIT IA5String OPTIONAL,
///     crlNum               [1] EXPLICIT INTEGER OPTIONAL,
///     crlTime              [2] EXPLICIT GeneralizedTime OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.4.2]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct CrlId {
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub crl_url: Option<Ia5String>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub crl_num: Option<Uint>,

    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    pub crl_time: Option<OcspGeneralizedTime>,
}

// It may be desirable for the OCSP responder to indicate the CRL on
// which a revoked or onHold certificate is found.  This can be useful
// where OCSP is used between repositories, and also as an auditing
// mechanism.  The CRL may be specified by a URL (the URL at which the
// CRL is available), a number (CRL number), or a time (the time at
// which the relevant CRL was created).  These extensions will be
// specified as singleExtensions.  The identifier for this extension
// will be id-pkix-ocsp-crl, while the value will be CrlID.
impl_extension!(CrlId, critical = false);

impl AssociatedOid for CrlId {
    const OID: ObjectIdentifier = ID_PKIX_OCSP_CRL;
}

/// AcceptableResponses structure as defined in [RFC 6960 Section 4.4.3].
///
/// ```text
/// AcceptableResponses ::= SEQUENCE OF OBJECT IDENTIFIER
/// ```
///
/// [RFC 6960 Section 4.4.3]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.3
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptableResponses(pub Vec<ObjectIdentifier>);

impl_newtype!(AcceptableResponses, Vec<ObjectIdentifier>);

// As noted in Section 4.2.1, OCSP responders SHALL be capable of
// responding with responses of the id-pkix-ocsp-basic response type.
// Correspondingly, OCSP clients SHALL be capable of receiving and
// processing responses of the id-pkix-ocsp-basic response type.
impl_extension!(AcceptableResponses, critical = true);

impl AssociatedOid for AcceptableResponses {
    const OID: ObjectIdentifier = ID_PKIX_OCSP_RESPONSE;
}

/// ArchiveCutoff structure as defined in [RFC 6960 Section 4.4.4].
///
/// ```text
/// ArchiveCutoff ::= GeneralizedTime
/// ```
///
/// [RFC 6960 Section 4.4.4]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.4
pub struct ArchiveCutoff(pub OcspGeneralizedTime);

impl_newtype!(ArchiveCutoff, OcspGeneralizedTime);
impl_extension!(ArchiveCutoff, critical = false);

impl AssociatedOid for ArchiveCutoff {
    const OID: ObjectIdentifier = ID_PKIX_OCSP_ARCHIVE_CUTOFF;
}

/// ServiceLocator structure as defined in [RFC 6960 Section 4.4.6].
///
/// ```text
/// ServiceLocator ::= SEQUENCE {
///    issuer                  Name,
///    locator                 AuthorityInfoAccessSyntax }
/// ```
///
/// [RFC 6960 Section 4.4.6]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.6
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ServiceLocator {
    pub issuer: Name,
    pub locator: Option<AuthorityInfoAccessSyntax>,
}

impl AssociatedOid for ServiceLocator {
    const OID: ObjectIdentifier = ID_PKIX_OCSP_SERVICE_LOCATOR;
}

impl_extension!(ServiceLocator, critical = false);

/// PreferredSignatureAlgorithms structure as defined in [RFC 6960 Section 4.4.7.1].
///
/// ```text
/// PreferredSignatureAlgorithms ::= SEQUENCE OF PreferredSignatureAlgorithm
/// ```
///
/// [RFC 6960 Section 4.4.7.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.7.1
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreferredSignatureAlgorithms(pub Vec<PreferredSignatureAlgorithm>);

impl_newtype!(
    PreferredSignatureAlgorithms,
    Vec<PreferredSignatureAlgorithm>
);
impl_extension!(PreferredSignatureAlgorithms, critical = false);

impl AssociatedOid for PreferredSignatureAlgorithms {
    const OID: ObjectIdentifier = ID_PKIX_OCSP_PREF_SIG_ALGS;
}

/// PreferredSignatureAlgorithm structure as defined in [RFC 6960 Section 4.4.7.1].
///
/// ```text
/// PreferredSignatureAlgorithm ::= SEQUENCE {
///    sigIdentifier   AlgorithmIdentifier,
///    certIdentifier  AlgorithmIdentifier OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.4.7.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.7.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct PreferredSignatureAlgorithm {
    pub sig_identifier: AlgorithmIdentifierOwned,
    pub cert_identifier: Option<AlgorithmIdentifierOwned>,
}
