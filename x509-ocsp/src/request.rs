//! OCSP Request

use crate::{CertId, Version, ext::Nonce};
use alloc::vec::Vec;
use const_oid::db::rfc6960::ID_PKIX_OCSP_NONCE;
use core::{default::Default, option::Option};
use der::{Decode, Sequence, asn1::BitString};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    certificate::{CertificateInner, Profile, Rfc5280},
    ext::{Extensions, pkix::name::GeneralName},
};

/// OCSPRequest structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// OCSPRequest ::= SEQUENCE {
///    tbsRequest              TBSRequest,
///    optionalSignature   [0] EXPLICIT Signature OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct OcspRequest<P: Profile + 'static = Rfc5280> {
    pub tbs_request: TbsRequest<P>,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub optional_signature: Option<Signature>,
}

impl OcspRequest {
    /// Returns the request's nonce value, if any. This method will return `None` if the request
    /// has no `Nonce` extension or decoding of the `Nonce` extension fails.
    pub fn nonce(&self) -> Option<Nonce> {
        self.tbs_request.nonce()
    }
}

/// TBSRequest structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// TBSRequest ::= SEQUENCE {
///    version             [0] EXPLICIT Version DEFAULT v1,
///    requestorName       [1] EXPLICIT GeneralName OPTIONAL,
///    requestList             SEQUENCE OF Request,
///    requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Default, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct TbsRequest<P: Profile + 'static = Rfc5280> {
    #[asn1(
        context_specific = "0",
        default = "Default::default",
        tag_mode = "EXPLICIT"
    )]
    pub version: Version,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub requestor_name: Option<GeneralName>,

    pub request_list: Vec<Request<P>>,

    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    pub request_extensions: Option<Extensions>,
}

impl TbsRequest {
    /// Returns the request's nonce value, if any. This method will return `None` if the request
    /// has no `Nonce` extension or decoding of the `Nonce` extension fails.
    pub fn nonce(&self) -> Option<Nonce> {
        match &self.request_extensions {
            Some(extns) => {
                let mut filter = extns.iter().filter(|e| e.extn_id == ID_PKIX_OCSP_NONCE);
                match filter.next() {
                    Some(extn) => Nonce::from_der(extn.extn_value.as_bytes()).ok(),
                    None => None,
                }
            }
            None => None,
        }
    }
}

/// Signature structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// Signature ::= SEQUENCE {
///    signatureAlgorithm      AlgorithmIdentifier,
///    signature               BIT STRING,
///    certs                  [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct Signature<P: Profile + 'static = Rfc5280> {
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub certs: Option<Vec<CertificateInner<P>>>,
}

/// Request structure as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// Request ::= SEQUENCE {
///    reqCert                     CertID,
///    singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct Request<P: Profile + 'static = Rfc5280> {
    pub req_cert: CertId<P>,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub single_request_extensions: Option<Extensions>,
}

#[cfg(feature = "builder")]
mod builder {
    use crate::{CertId, Request, builder::Error};
    use const_oid::AssociatedOid;
    use digest::Digest;
    use x509_cert::{Certificate, ext::ToExtension, name::Name, serial_number::SerialNumber};

    impl Request {
        /// Returns a new `Request` with the specified `CertID`
        pub fn new(req_cert: CertId) -> Self {
            Self {
                req_cert,
                single_request_extensions: None,
            }
        }

        /// Generates a `CertID` by running the issuer's subject and key through the specified
        /// [`Digest`].
        ///
        /// [RFC 6960 Section 4.1.1]
        ///
        /// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
        pub fn from_issuer<D>(
            issuer: &Certificate,
            serial_number: SerialNumber,
        ) -> Result<Self, Error>
        where
            D: Digest + AssociatedOid,
        {
            Ok(Self::new(CertId::from_issuer::<D>(issuer, serial_number)?))
        }

        /// Generates a `CertID` by running the issuer's subject and key through the specified
        /// [`Digest`] and pulls the serial from `cert`. This does not ensure that `cert` is actually
        /// issued by `issuer`.
        ///
        /// [RFC 6960 Section 4.1.1]
        ///
        /// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
        pub fn from_cert<D>(issuer: &Certificate, cert: &Certificate) -> Result<Self, Error>
        where
            D: Digest + AssociatedOid,
        {
            Ok(Self::new(CertId::from_cert::<D>(issuer, cert)?))
        }

        /// Adds a single request extension as specified in [RFC 6960 Section 4.4]. Errors when the
        /// extension encoding fails.
        ///
        /// [RFC 6960 Section 4.4]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4
        pub fn with_extension<E: ToExtension>(mut self, ext: E) -> Result<Self, E::Error> {
            let ext = ext.to_extension(&Name::default(), &[])?;
            match self.single_request_extensions {
                Some(ref mut exts) => exts.push(ext),
                None => self.single_request_extensions = Some(alloc::vec![ext]),
            }
            Ok(self)
        }
    }
}
