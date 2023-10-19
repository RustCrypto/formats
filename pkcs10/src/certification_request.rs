//! PKCS#10 `CertificationRequest`.

use core::fmt::{self};

use alloc::vec;
use der::{
    asn1::{AnyRef, BitString, ContextSpecific},
    Any, Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence, Writer,
};
use spki::AlgorithmIdentifier;

#[cfg(feature = "pem")]
pub use der::pem::PemLabel;

use crate::{certification_request_info::CertificationRequestInfo, Error};

/// PKCS#10 `CertificationRequest`.
///
/// A certification request consists of a distinguished name, a public key,
/// and optionally a set of attributes, collectively signed by the entity
/// requesting certification.  Certification requests are sent to a
/// certification authority, which transforms the request into an X.509
/// [9] public-key certificate.  (In what form the certification
/// authority returns the newly signed certificate is outside the scope
/// of this document.  A PKCS #7 [2] message is one possibility.)
///
/// Supports PKCS#10 as described in [RFC 2986].
///
/// ```text
/// A certification request shall have ASN.1 type CertificationRequest:
///
///    CertificationRequest ::= SEQUENCE {
///         certificationRequestInfo CertificationRequestInfo,
///         signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
///         signature          BIT STRING
///    }
///
///    AlgorithmIdentifier {ALGORITHM:IOSet } ::= SEQUENCE {
///         algorithm          ALGORITHM.&id({IOSet}),
///         parameters         ALGORITHM.&Type({IOSet}{@algorithm}) OPTIONAL
///    }
///
///    SignatureAlgorithms ALGORITHM ::= {
///         ... -- add any locally defined algorithms here -- }
///
///    The components of type CertificationRequest have the following
///    meanings:
///
///         certificateRequestInfo is the "certification request
///           information." It is the value being signed.
///
///         signatureAlgorithm identifies the signature algorithm (and any
///           associated parameters) under which the certification-request
///           information is signed.  For example, a specification might
///           include an ALGORITHM object for PKCS #1's
///           md5WithRSAEncryption in the information object set
///           SignatureAlgorithms:
///
///           SignatureAlgorithms ALGORITHM ::= {
///                ...,
///                { NULL IDENTIFIED BY md5WithRSAEncryption }
///           }
///
///         signature is the result of signing the certification request
///           information with the certification request subject's private
///           key.
///
/// [RFC 2896]: https://www.rfc-editor.org/rfc/rfc2986
#[derive(Clone)]
pub struct CertificationRequest {
    /// The "certification request information." It is the value being signed.
    pub certification_request_info: CertificationRequestInfo,

    /// The signature algorithm (and any associated parameters)
    /// under which the certification-request information is signed..
    pub algorithm_identifier: AlgorithmIdentifier<Any>,

    /// The result of signing the certification request information
    /// with the certification request subject's private key.
    pub signature: BitString,
}

impl CertificationRequest {
    /// Create a new PKCS#10 [`CertificationRequest`] message.
    ///
    /// This is a helper method which initializes `attributes` and `public_key`
    /// to `None`, helpful if you aren't using those.
    pub fn new(
        certification_request_info: CertificationRequestInfo,
        algorithm_identifier: AlgorithmIdentifier<Any>,
    ) -> der::Result<Self> {
        Ok(Self {
            certification_request_info,
            algorithm_identifier,
            signature: BitString::new(0, vec![])?,
        })
    }
}

impl<'a> DecodeValue<'a> for CertificationRequest {
    fn decode_value<R: Reader<'a>>(
        reader: &mut R,
        header: Header,
    ) -> der::Result<CertificationRequest> {
        reader.read_nested(header.length, |reader| {
            let certification_request_info = reader.decode()?;
            let algorithm_identifier = reader.decode()?;
            let signature: BitString = reader.decode()?;

            // Ignore any remaining extension fields
            while !reader.is_finished() {
                reader.decode::<ContextSpecific<AnyRef<'_>>>()?;
            }

            Ok(Self {
                certification_request_info,
                algorithm_identifier,
                signature,
            })
        })
    }
}

impl EncodeValue for CertificationRequest {
    fn value_len(&self) -> der::Result<Length> {
        self.certification_request_info.encoded_len()?
            + self.algorithm_identifier.encoded_len()?
            + self.signature.encoded_len()?
        // + if let Some(signature) = self.signature {
        //     OctetStringRef::new(signature)?.encoded_len()?
        // } else {
        //     Length::ZERO
        // }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.certification_request_info.encode(writer)?;
        self.algorithm_identifier.encode(writer)?;
        self.signature.encode(writer)?;
        // if let Some(signature) = self.signature {
        //     OctetStringRef::new(signature)?.encode(writer)?;
        // }
        Ok(())
    }
}

impl<'a> Sequence<'a> for CertificationRequest {}

impl<'a> TryFrom<&'a [u8]> for CertificationRequest {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::from_der(bytes).map_err(Error::Asn1)
    }
}

impl fmt::Debug for CertificationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificationRequest")
            .field(
                "certification request info",
                &self.certification_request_info,
            )
            .field("algorithm", &self.algorithm_identifier)
            .field("signature", &self.signature)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "pem")]
impl PemLabel for CertificationRequest {
    const PEM_LABEL: &'static str = "CERTIFICATE REQUEST";
}
