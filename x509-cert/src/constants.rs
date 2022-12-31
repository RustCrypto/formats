//! Constants for X509 signature algorithm

use der::{
    asn1::{Any, AnyRef},
    oid::db::rfc5912,
    referenced::{OwnedToRef, RefToOwned},
};
use spki::{AlgorithmIdentifier, AlgorithmIdentifierRef};

/// Signature algorithm used for certificate signature
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct CertificateSignatureAlgorithm<T> {
    /// Algorithm identifier for the certificate signature
    pub identifier: AlgorithmIdentifier<T>,
}

/// `CertificateSignatureAlgorithm` reference which has `AnyRef` parameters.
pub type CertificateSignatureAlgorithmRef<'a> = CertificateSignatureAlgorithm<AnyRef<'a>>;
/// `CertificateSignatureAlgorithm` reference which has `Any` parameters.
pub type CertificateSignatureAlgorithmOwned = CertificateSignatureAlgorithm<Any>;

impl<'a> RefToOwned<'a> for CertificateSignatureAlgorithmRef<'a> {
    type Owned = CertificateSignatureAlgorithmOwned;
    fn ref_to_owned(&self) -> Self::Owned {
        CertificateSignatureAlgorithm {
            identifier: self.identifier.ref_to_owned(),
        }
    }
}

impl OwnedToRef for CertificateSignatureAlgorithmOwned {
    type Borrowed<'a> = CertificateSignatureAlgorithmRef<'a>;
    fn owned_to_ref(&self) -> Self::Borrowed<'_> {
        CertificateSignatureAlgorithm {
            identifier: self.identifier.owned_to_ref(),
        }
    }
}

/// RSA with SHA-256 signature as defined in [RFC 5754 Section 3.2]
///
/// ```text
/// sha256WithRSAEncryption  OBJECT IDENTIFIER  ::=  { iso(1)
///        member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 11 }
/// ```
///
/// [RFC 5754 Section 3.2]: https://datatracker.ietf.org/doc/html/rfc5754#section-3.2
pub const SHA_256_WITH_RSA_ENCRYPTION: CertificateSignatureAlgorithmRef<'static> =
    CertificateSignatureAlgorithm {
        identifier: AlgorithmIdentifierRef {
            oid: rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            parameters: Some(AnyRef::NULL),
        },
    };

/// ECDSA with SHA-256 signature  as defined in [RFC 5754 Section 3.3]
///
/// ```text
/// ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
///        us(840)ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }
/// ```
///
/// [RFC 5754 Section 3.3]: https://datatracker.ietf.org/doc/html/rfc5754#section-3.3
pub const ECDSA_WITH_SHA_256: CertificateSignatureAlgorithmRef<'static> =
    CertificateSignatureAlgorithm {
        identifier: AlgorithmIdentifierRef {
            oid: rfc5912::ECDSA_WITH_SHA_256,
            parameters: Some(AnyRef::NULL),
        },
    };
