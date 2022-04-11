//! Certificate types

use crate::{name::Name, time::Validity};

use alloc::vec::Vec;

use const_oid::AssociatedOid;
use der::asn1::{BitString, UIntBytes};
use der::{Decode, Enumerated, Error, ErrorKind, Newtype, Sequence};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

/// Certificate `Version` as defined in [RFC 5280 Section 4.1].
///
/// ```text
/// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
/// ```
///
/// [RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Version {
    /// Version 1 (default)
    V1 = 0,

    /// Version 2
    V2 = 1,

    /// Version 3
    V3 = 2,
}

impl Default for Version {
    fn default() -> Self {
        Self::V1
    }
}

/// X.509 `TbsCertificate` as defined in [RFC 5280 Section 4.1]
///
/// ASN.1 structure containing the names of the subject and issuer, a public
/// key associated with the subject, a validity period, and other associated
/// information.
///
/// ```text
/// TBSCertificate  ::=  SEQUENCE  {
///     version         [0]  EXPLICIT Version DEFAULT v1,
///     serialNumber         CertificateSerialNumber,
///     signature            AlgorithmIdentifier,
///     issuer               Name,
///     validity             Validity,
///     subject              Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///                          -- If present, version MUST be v2 or v3
///     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///                          -- If present, version MUST be v2 or v3
///     extensions      [3]  Extensions OPTIONAL
///                          -- If present, version MUST be v3 --
/// }
/// ```
///
/// [RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct TbsCertificate<'a> {
    /// The certificate version
    ///
    /// Note that this value defaults to Version 1 per the RFC. However,
    /// fields such as `issuer_unique_id`, `subject_unique_id` and `extensions`
    /// require later versions. Care should be taken in order to ensure
    /// standards compliance.
    #[asn1(context_specific = "0", default = "Default::default")]
    pub version: Version,

    pub serial_number: UIntBytes<'a>,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: Name<'a>,
    pub validity: Validity,
    pub subject: Name<'a>,
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer_unique_id: Option<BitString<'a>>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub subject_unique_id: Option<BitString<'a>>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<crate::ext::Extensions<'a>>,
}

impl<'a> TbsCertificate<'a> {
    /// Decodes a single extension
    ///
    /// Returns an error if multiple of these extensions is present. Returns
    /// `Ok(None)` if the extension is not present. Returns a decoding error
    /// if decoding failed. Otherwise returns the extension.
    pub fn get<'b: 'a, T: Decode<'a> + AssociatedOid>(
        &'b self,
    ) -> Result<Option<(bool, T)>, Error> {
        let mut iter = self.filter::<T>().peekable();
        match iter.next() {
            None => Ok(None),
            Some(item) => match iter.peek() {
                Some(..) => Err(ErrorKind::Failed.into()),
                None => Ok(Some(item?)),
            },
        }
    }

    /// Filters extensions by an associated OID
    ///
    /// Returns a filtered iterator over all the extensions with the OID.
    pub fn filter<'b: 'a, T: Decode<'a> + AssociatedOid>(
        &'b self,
    ) -> impl 'b + Iterator<Item = Result<(bool, T), Error>> {
        self.extensions
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter(|e| e.extn_id == T::OID)
            .map(|e| Ok((e.critical, T::from_der(e.extn_value)?)))
    }
}

/// X.509 certificates are defined in [RFC 5280 Section 4.1].
///
/// ```text
/// Certificate  ::=  SEQUENCE  {
///     tbsCertificate       TBSCertificate,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signature            BIT STRING
/// }
/// ```
///
/// [RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct Certificate<'a> {
    pub tbs_certificate: TbsCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature: BitString<'a>,
}

/// `PkiPath` as defined by X.509 and referenced by [RFC 6066].
///
/// This contains a series of certificates in validation order from the
/// top-most certificate to the bottom-most certificate. This means that
/// the first certificate signs the second certificate and so on.
///
/// ```text
/// PkiPath ::= SEQUENCE OF Certificate
/// ```
///
/// [RFC 6066]: https://datatracker.ietf.org/doc/html/rfc6066#section-10.1
#[derive(Clone, Debug, PartialEq, Eq, Default, Newtype)]
pub struct PkiPath<'a>(pub Vec<Certificate<'a>>);
