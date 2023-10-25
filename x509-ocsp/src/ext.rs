//! OCSP Extensions

use alloc::vec::Vec;
use const_oid::{
    db::rfc6960::{
        ID_PKIX_OCSP_ARCHIVE_CUTOFF, ID_PKIX_OCSP_CRL, ID_PKIX_OCSP_NONCE,
        ID_PKIX_OCSP_PREF_SIG_ALGS, ID_PKIX_OCSP_RESPONSE, ID_PKIX_OCSP_SERVICE_LOCATOR,
    },
    AssociatedOid,
};
use der::{
    asn1::{GeneralizedTime, Ia5String, ObjectIdentifier, OctetString, Uint},
    Sequence, ValueOrd,
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    ext::{pkix::AuthorityInfoAccessSyntax, Extension},
    impl_newtype,
    name::Name,
};

#[cfg(feature = "rand_core")]
use rand_core::CryptoRngCore;

/// Trait to be implemented by extensions to allow them to be formated for x509 OCSP
/// requests/responses.
pub trait AsExtension: AssociatedOid + der::Encode {
    /// Should the extension be marked as critical
    const CRITICAL: bool;

    /// Returns the Extension with the content encoded
    fn to_extension(&self) -> Result<Extension, der::Error> {
        Ok(Extension {
            extn_id: <Self as AssociatedOid>::OID,
            critical: Self::CRITICAL,
            extn_value: OctetString::new(<Self as der::Encode>::to_der(self)?)?,
        })
    }
}

/// Nonce extension as defined in [RFC 6960 Section 4.4.1].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce(pub OctetString);

impl_newtype!(Nonce, OctetString);

impl AssociatedOid for Nonce {
    const OID: ObjectIdentifier = ID_PKIX_OCSP_NONCE;
}

impl AsExtension for Nonce {
    // Some responders do not honor nonces
    const CRITICAL: bool = false;
}

impl TryFrom<&[u8]> for Nonce {
    type Error = der::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(OctetString::new(data)?))
    }
}

impl Nonce {
    /// Creates a new Nonce object given a random generator and a length
    #[cfg(feature = "rand_core")]
    pub fn generate<R: CryptoRngCore>(rng: &mut R, length: usize) -> Result<Self, der::Error> {
        let mut bytes = Vec::with_capacity(length);
        let mut random = [0u8; 32];
        while bytes.len() < length {
            rng.fill_bytes(&mut random);
            bytes.extend_from_slice(&random);
        }
        Ok(Self(OctetString::new(bytes)?))
    }
}

/// CrlReferences extension as defined in [RFC 6960 Section 4.4.2]
pub struct CrlReferences(pub Vec<CrlId>);

impl_newtype!(CrlReferences, Vec<CrlId>);

impl AssociatedOid for CrlReferences {
    const OID: ObjectIdentifier = ID_PKIX_OCSP_CRL;
}

impl AsExtension for CrlReferences {
    // It may be desirable for the OCSP responder to indicate the CRL on
    // which a revoked or onHold certificate is found.  This can be useful
    // where OCSP is used between repositories, and also as an auditing
    // mechanism.  The CRL may be specified by a URL (the URL at which the
    // CRL is available), a number (CRL number), or a time (the time at
    // which the relevant CRL was created).  These extensions will be
    // specified as singleExtensions.  The identifier for this extension
    // will be id-pkix-ocsp-crl, while the value will be CrlID.
    const CRITICAL: bool = false;
}

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
    pub crl_time: Option<GeneralizedTime>,
}

/// AcceptableResponses structure as defined in [RFC 6960 Section 4.4.3].
///
/// ```text
/// AcceptableResponses ::= SEQUENCE OF OBJECT IDENTIFIER
/// ```
///
/// [RFC 6960 Section 4.4.3]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.3
pub struct AcceptableResponses(pub Vec<ObjectIdentifier>);

impl_newtype!(AcceptableResponses, Vec<ObjectIdentifier>);

impl AssociatedOid for AcceptableResponses {
    const OID: ObjectIdentifier = ID_PKIX_OCSP_RESPONSE;
}

impl AsExtension for AcceptableResponses {
    // As noted in Section 4.2.1, OCSP responders SHALL be capable of
    // responding with responses of the id-pkix-ocsp-basic response type.
    // Correspondingly, OCSP clients SHALL be capable of receiving and
    // processing responses of the id-pkix-ocsp-basic response type.
    const CRITICAL: bool = true;
}

/// ArchiveCutoff structure as defined in [RFC 6960 Section 4.4.4].
///
/// ```text
/// ArchiveCutoff ::= GeneralizedTime
/// ```
///
/// [RFC 6960 Section 4.4.4]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.4
pub struct ArchiveCutoff(GeneralizedTime);

impl_newtype!(ArchiveCutoff, GeneralizedTime);

impl AssociatedOid for ArchiveCutoff {
    const OID: ObjectIdentifier = ID_PKIX_OCSP_ARCHIVE_CUTOFF;
}

impl AsExtension for ArchiveCutoff {
    const CRITICAL: bool = false;
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

impl AsExtension for ServiceLocator {
    const CRITICAL: bool = false;
}

/// PreferredSignatureAlgorithms structure as defined in [RFC 6960 Section 4.4.7.1].
///
/// ```text
/// PreferredSignatureAlgorithms ::= SEQUENCE OF PreferredSignatureAlgorithm
/// ```
///
/// [RFC 6960 Section 4.4.7.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.7.1
pub struct PreferredSignatureAlgorithms(pub Vec<PreferredSignatureAlgorithm>);

impl_newtype!(
    PreferredSignatureAlgorithms,
    Vec<PreferredSignatureAlgorithm>
);

impl AssociatedOid for PreferredSignatureAlgorithm {
    const OID: ObjectIdentifier = ID_PKIX_OCSP_PREF_SIG_ALGS;
}

impl AsExtension for PreferredSignatureAlgorithm {
    const CRITICAL: bool = false;
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
