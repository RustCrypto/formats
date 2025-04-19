//! Standardized X.509 Certificate Extensions

use const_oid::AssociatedOid;
use der::{Sequence, ValueOrd, asn1::OctetString};
use spki::ObjectIdentifier;

pub mod pkix;

/// Extension as defined in [RFC 5280 Section 4.1.2.9].
///
/// The ASN.1 definition for Extension objects is below. The extnValue type
/// may be further parsed using a decoder corresponding to the extnID value.
///
/// ```text
/// Extension  ::=  SEQUENCE  {
///     extnID      OBJECT IDENTIFIER,
///     critical    BOOLEAN DEFAULT FALSE,
///     extnValue   OCTET STRING
///                 -- contains the DER encoding of an ASN.1 value
///                 -- corresponding to the extension type identified
///                 -- by extnID
/// }
/// ```
///
/// [RFC 5280 Section 4.1.2.9]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.9
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct Extension {
    pub extn_id: ObjectIdentifier,

    #[asn1(default = "Default::default")]
    pub critical: bool,

    pub extn_value: OctetString,
}

/// Extensions as defined in [RFC 5280 Section 4.1.2.9].
///
/// ```text
/// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
/// ```
///
/// [RFC 5280 Section 4.1.2.9]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.9
pub type Extensions = alloc::vec::Vec<Extension>;

/// Trait to be implemented by extensions to allow them to be formatted as x509 v3 extensions by
/// builder.
///
/// # Examples
///
/// ```
/// use const_oid::{AssociatedOid, ObjectIdentifier};
/// use x509_cert::{der::Sequence, ext, name};
///
/// /// This extension indicates the age of the captain at the time of signature
/// #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
/// pub struct CaptainAge {
///     pub age: u32,
/// }
///
/// impl AssociatedOid for CaptainAge {
/// # // https://datatracker.ietf.org/doc/html/rfc5612
/// # // 32473 is the private OID reserved for documentation.
///     const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.1");
/// }
///
/// impl ext::AsExtension for CaptainAge {
///     fn critical(&self, _subject: &name::Name, _extensions: &[ext::Extension]) -> bool {
///         false
///     }
/// }
/// ```
pub trait AsExtension: AssociatedOid + der::Encode {
    /// Should the extension be marked critical
    ///
    /// This affects the behavior of a validator when using the generated certificate.
    /// See [RFC 5280 Section 4.2]:
    /// ```text
    /// A certificate-using system MUST reject the certificate if it encounters
    /// a critical extension it does not recognize or a critical extension
    /// that contains information that it cannot process.  A non-critical
    /// extension MAY be ignored if it is not recognized, but MUST be
    /// processed if it is recognized.
    /// ```
    ///
    /// [RFC 5280 Section 4.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2
    fn critical(&self, subject: &crate::name::Name, extensions: &[Extension]) -> bool;

    /// Returns the Extension with the content encoded.
    fn to_extension(
        &self,
        subject: &crate::name::Name,
        extensions: &[Extension],
    ) -> Result<Extension, der::Error> {
        let content = OctetString::new(<Self as der::Encode>::to_der(self)?)?;

        Ok(Extension {
            extn_id: <Self as AssociatedOid>::OID,
            critical: self.critical(subject, extensions),
            extn_value: content,
        })
    }
}
