//! PKCS#10 `CertificationRequest`.

use core::fmt::{self};

use der::{
    asn1::{AnyRef, ContextSpecific},
    Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence, TagMode, TagNumber,
    Writer,
};
use spki::SubjectPublicKeyInfoOwned;

#[cfg(feature = "pem")]
pub use der::pem::PemLabel;

use crate::{attribute::Attributes, name::Name, Version};

/// The "certification request information." It is the value being signed.
///
/// ```text
///     CertificationRequestInfo:
///  
///     CertificationRequestInfo ::= SEQUENCE {
///          version       INTEGER { v1(0) } (v1,...),
///          subject       Name,
///          subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
///          attributes    [0] Attributes{{ CRIAttributes }}
///     }
///  
///     SubjectPublicKeyInfo { ALGORITHM : IOSet} ::= SEQUENCE {
///          algorithm        AlgorithmIdentifier {{IOSet}},
///          subjectPublicKey BIT STRING
///     }
///  
///     PKInfoAlgorithms ALGORITHM ::= {
///          ...  -- add any locally defined algorithms here -- }
///  
///     Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
///  
///     CRIAttributes  ATTRIBUTE  ::= {
///          ... -- add any locally defined attributes here -- }
///  
///     Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
///          type   ATTRIBUTE.&id({IOSet}),
///          values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
///     }
/// ```
///
///
///    The components of type CertificationRequestInfo have the following
///    meanings:
///
///         version is the version number, for compatibility with future
///           revisions of this document.  It shall be 0 for this version of
///           the standard.
///
///         subject is the distinguished name of the certificate subject
///           (the entity whose public key is to be certified).
///
///         subjectPublicKeyInfo contains information about the public key
///           being certified.  The information identifies the entity's
///           public-key algorithm (and any associated parameters); examples
///           of public-key algorithms include the rsaEncryption object
///           identifier from PKCS #1 [1].  The information also includes a
///           bit-string representation of the entity's public key.  For the
///           public-key algorithm just mentioned, the bit string contains
///           the DER encoding of a value of PKCS #1 type RSAPublicKey.  The
///           values of type SubjectPublicKeyInfo{} allowed for
///           subjectPKInfo are constrained to the values specified by the
///           information object set PKInfoAlgorithms, which includes the
///           extension marker (...).  Definitions of specific algorithm
///           objects are left to specifications that reference this
///           document.  Such specifications will be interoperable with
///           their future versions if any additional algorithm objects are
///           added after the extension marker.
///
///         attributes is a collection of attributes providing additional
///           information about the subject of the certificate.  Some
///           attribute types that might be useful here are defined in PKCS
///           #9.  An example is the challenge-password attribute, which
///           specifies a password by which the entity may request
///           certificate revocation.  Another example is information to
///           appear in X.509 certificate extensions (e.g. the
///           extensionRequest attribute from PKCS #9).  The values of type
///
/// [RFC 2896]: https://www.rfc-editor.org/rfc/rfc2986
#[derive(Clone)]
pub struct CertificationRequestInfo {
    version: Version,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
    attributes: Option<Attributes>,
}

impl<'a> DecodeValue<'a> for CertificationRequestInfo {
    fn decode_value<R: Reader<'a>>(
        reader: &mut R,
        header: Header,
    ) -> der::Result<CertificationRequestInfo> {
        reader.read_nested(header.length, |reader| {
            // Parse and validate `version` INTEGER.
            let version = Version::decode(reader)?;
            let subject = reader.decode()?;
            let subject_public_key_info: SubjectPublicKeyInfoOwned = reader.decode()?;
            let attributes =
                reader.context_specific::<Attributes>(TagNumber::N0, TagMode::Implicit)?;

            // Ignore any remaining extension fields
            while !reader.is_finished() {
                reader.decode::<ContextSpecific<AnyRef<'_>>>()?;
            }

            Ok(Self {
                version,
                subject,
                subject_public_key_info,
                attributes, // attributes,
            })
        })
    }
}

impl<'a> Sequence<'a> for CertificationRequestInfo {}

impl EncodeValue for CertificationRequestInfo {
    fn value_len(&self) -> der::Result<Length> {
        self.version.encoded_len()?
            + self.subject.encoded_len()?
            + self.subject_public_key_info.encoded_len()?
        // + self.attributes.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.version.encode(writer)?;
        self.subject.encode(writer)?;
        self.subject_public_key_info.encode(writer)?;
        // self.attributes.encode(writer)?;
        Ok(())
    }
}

impl fmt::Debug for CertificationRequestInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificationRequestInfo")
            .field("version", &self.version)
            .field("subject", &self.subject)
            .field("subject public key info", &self.subject_public_key_info)
            .field("attributes", &self.attributes)
            .finish_non_exhaustive()
    }
}
