//! Basic OCSP Response

use crate::{
    AsResponseBytes, CertId, CertStatus, OcspGeneralizedTime, ResponderId, Version, ext::Nonce,
};
use alloc::vec::Vec;
use const_oid::{
    AssociatedOid,
    db::rfc6960::{ID_PKIX_OCSP_BASIC, ID_PKIX_OCSP_NONCE},
};
use core::{default::Default, option::Option};
use der::{
    Decode, Sequence,
    asn1::{BitString, ObjectIdentifier},
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{certificate::Certificate, ext::Extensions};

/// BasicOcspResponse structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// BasicOCSPResponse ::= SEQUENCE {
///   tbsResponseData          ResponseData,
///   signatureAlgorithm       AlgorithmIdentifier,
///   signature                BIT STRING,
///   certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct BasicOcspResponse {
    pub tbs_response_data: ResponseData,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub certs: Option<Vec<Certificate>>,
}

impl BasicOcspResponse {
    /// Returns the response's nonce value, if any. This method will return `None` if the response
    /// has no `Nonce` extension or decoding of the `Nonce` extension fails.
    pub fn nonce(&self) -> Option<Nonce> {
        self.tbs_response_data.nonce()
    }
}

impl AssociatedOid for BasicOcspResponse {
    const OID: ObjectIdentifier = ID_PKIX_OCSP_BASIC;
}

impl AsResponseBytes for BasicOcspResponse {}

/// ResponseData structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// ResponseData ::= SEQUENCE {
///    version              [0] EXPLICIT Version DEFAULT v1,
///    responderID             ResponderID,
///    producedAt              GeneralizedTime,
///    responses               SEQUENCE OF SingleResponse,
///    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ResponseData {
    #[asn1(
        context_specific = "0",
        default = "Default::default",
        tag_mode = "EXPLICIT"
    )]
    pub version: Version,
    pub responder_id: ResponderId,
    pub produced_at: OcspGeneralizedTime,
    pub responses: Vec<SingleResponse>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub response_extensions: Option<Extensions>,
}

impl ResponseData {
    /// Returns the response's nonce value, if any. This method will return `None` if the response
    /// has no `Nonce` extension or decoding of the `Nonce` extension fails.
    pub fn nonce(&self) -> Option<Nonce> {
        match &self.response_extensions {
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

/// SingleResponse structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// SingleResponse ::= SEQUENCE {
///    certID                  CertID,
///    certStatus              CertStatus,
///    thisUpdate              GeneralizedTime,
///    nextUpdate              [0] EXPLICIT GeneralizedTime OPTIONAL,
///    singleExtensions        [1] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct SingleResponse {
    pub cert_id: CertId,
    pub cert_status: CertStatus,
    pub this_update: OcspGeneralizedTime,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub next_update: Option<OcspGeneralizedTime>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub single_extensions: Option<Extensions>,
}

#[cfg(feature = "builder")]
mod builder {
    use crate::{CertId, CertStatus, OcspGeneralizedTime, SingleResponse, builder::Error};
    use const_oid::AssociatedOid;
    use digest::Digest;
    use x509_cert::{
        Certificate, crl::CertificateList, ext::ToExtension, name::Name,
        serial_number::SerialNumber,
    };

    impl SingleResponse {
        /// Returns a `SingleResponse` given the `CertID`, `CertStatus`, and `This Update`. `Next
        /// Update` is set to `None`.
        pub fn new(
            cert_id: CertId,
            cert_status: CertStatus,
            this_update: OcspGeneralizedTime,
        ) -> Self {
            Self {
                cert_id,
                cert_status,
                this_update,
                next_update: None,
                single_extensions: None,
            }
        }

        /// Sets `thisUpdate` in the `singleResponse` as defined in [RFC 6960 Section 4.2.1].
        ///
        /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
        pub fn with_this_update(mut self, this_update: OcspGeneralizedTime) -> Self {
            self.this_update = this_update;
            self
        }

        /// Sets `nextUpdate` in the `singleResponse` as defined in [RFC 6960 Section 4.2.1].
        ///
        /// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
        pub fn with_next_update(mut self, next_update: OcspGeneralizedTime) -> Self {
            self.next_update = Some(next_update);
            self
        }

        /// Adds a single response extension as specified in [RFC 6960 Section 4.4]. Errors when the
        /// extension encoding fails.
        ///
        /// [RFC 6960 Section 4.4]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.4
        pub fn with_extension<E: ToExtension>(mut self, ext: E) -> Result<Self, E::Error> {
            let ext = ext.to_extension(&Name::default(), &[])?;
            match self.single_extensions {
                Some(ref mut exts) => exts.push(ext),
                None => self.single_extensions = Some(alloc::vec![ext]),
            }
            Ok(self)
        }

        /// Returns a `SingleResponse` by searching through the CRL to see if `serial` is revoked. If
        /// not, the `CertStatus` is set to good. The `CertID` is built from the issuer and serial
        /// number. This method does not ensure the CRL is issued by the issuer and only asserts the
        /// serial is not revoked in the provided CRL.
        ///
        /// `thisUpdate` and `nextUpdate` will be pulled from the CRL.
        ///
        /// NOTE: this method complies with [RFC 2560 Section 2.2] and not [RFC 6960 Section 2.2].
        /// [RFC 6960] limits the `good` status to only issued certificates. [RFC 2560] only asserts
        /// the serial was not revoked and makes no assertion the serial was ever issued.
        ///
        /// [RFC 2560]: https://datatracker.ietf.org/doc/html/rfc2560
        /// [RFC 2560 Section 2.2]: https://datatracker.ietf.org/doc/html/rfc2560#section-2.2
        /// [RFC 6960]: https://datatracker.ietf.org/doc/html/rfc6960
        /// [RFC 6960 Section 2.2]: https://datatracker.ietf.org/doc/html/rfc6960#section-2.2
        pub fn from_crl<D>(
            issuer: &Certificate,
            crl: &CertificateList,
            serial_number: SerialNumber,
        ) -> Result<Self, Error>
        where
            D: Digest + AssociatedOid,
        {
            let cert_status = match &crl.tbs_cert_list.revoked_certificates {
                Some(revoked_certs) => {
                    let mut filter = revoked_certs
                        .iter()
                        .filter(|rc| rc.serial_number == serial_number);
                    match filter.next() {
                        None => CertStatus::good(),
                        Some(rc) => CertStatus::revoked(rc),
                    }
                }
                None => CertStatus::good(),
            };
            let cert_id = CertId::from_issuer::<D>(issuer, serial_number)?;
            let this_update = crl.tbs_cert_list.this_update.into();
            let next_update = crl.tbs_cert_list.next_update.map(|t| t.into());
            Ok(Self {
                cert_id,
                cert_status,
                this_update,
                next_update,
                single_extensions: None,
            })
        }
    }
}
