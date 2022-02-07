#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/pkcs10/0.0.0"
)]
#![forbid(unsafe_code, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

extern crate alloc;

mod document;
mod info;
mod version;

pub use document::CertReqDocument;
pub use info::CertReqInfo;
pub use version::Version;

use der::asn1::BitString;
use der::{Decodable, Sequence};
use spki::AlgorithmIdentifier;

/// PKCS#10 `CertificationRequest` as defined in [RFC 2986 Section 4].
///
/// ```text
/// CertificationRequest ::= SEQUENCE {
///     certificationRequestInfo CertificationRequestInfo,
///     signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
///     signature          BIT STRING
/// }
/// ```
///
/// [RFC 2986 Section 4]: https://datatracker.ietf.org/doc/html/rfc2986#section-4
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct CertReq<'a> {
    /// Certification request information.
    pub info: CertReqInfo<'a>,

    /// Signature algorithm identifier.
    pub algorithm: AlgorithmIdentifier<'a>,

    /// Signature.
    pub signature: BitString<'a>,
}

impl<'a> TryFrom<&'a [u8]> for CertReq<'a> {
    type Error = der::Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::from_der(bytes)
    }
}
