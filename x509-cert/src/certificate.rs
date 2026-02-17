//! Certificate types

use crate::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use crate::{ext, name::Name, serial_number::SerialNumber, time::Validity};
use alloc::vec::Vec;
use const_oid::AssociatedOid;
use core::{cmp::Ordering, fmt::Debug};
use der::{Decode, Enumerated, ErrorKind, Sequence, Tag, ValueOrd, asn1::BitString};

#[cfg(feature = "pem")]
use der::{
    DecodePem,
    pem::{self, PemLabel},
};

#[cfg(feature = "digest")]
use {
    der::Encode,
    digest::{Digest, Output},
    spki::DigestWriter,
};

use crate::time::Time;

/// [`Profile`] allows the consumer of this crate to customize the behavior when parsing
/// certificates.
/// By default, parsing will be made in a rfc5280-compliant manner.
pub trait Profile: PartialEq + Debug + Eq + Ord + Clone + Copy + Default + 'static {
    /// Checks to run when parsing serial numbers
    fn check_serial_number(serial: &SerialNumber<Self>) -> der::Result<()> {
        // See the note in `SerialNumber::new`: we permit lengths of 21 bytes here,
        // since some X.509 implementations interpret the limit of 20 bytes to refer
        // to the pre-encoded value.
        if serial.inner.len() > SerialNumber::<Self>::MAX_DECODE_LEN {
            Err(Tag::Integer.value_error().into())
        } else {
            Ok(())
        }
    }

    /// Adjustments to the time to run while serializing validity.
    /// See [RFC 5280 Section 4.1.2.5]:
    /// ```text
    /// CAs conforming to this profile MUST always encode certificate
    /// validity dates through the year 2049 as UTCTime; certificate validity
    /// dates in 2050 or later MUST be encoded as GeneralizedTime.
    /// ```
    ///
    /// [RFC 5280 Section 4.1.2.5]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5
    fn time_encoding(mut time: Time) -> der::Result<Time> {
        time.rfc5280_adjust_utc_time()?;
        Ok(time)
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Default)]
/// Parse and serialize certificates in rfc5280-compliant manner
pub struct Rfc5280;

impl Profile for Rfc5280 {}

#[cfg(feature = "hazmat")]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Default)]
/// Parse raw x509 certificate and disable all the checks and modification to the underlying data.
pub struct Raw;

#[cfg(feature = "hazmat")]
impl Profile for Raw {
    fn check_serial_number(_serial: &SerialNumber<Self>) -> der::Result<()> {
        Ok(())
    }
    fn time_encoding(time: Time) -> der::Result<Time> {
        Ok(time)
    }
}

/// Certificate `Version` as defined in [RFC 5280 Section 4.1].
///
/// ```text
/// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
/// ```
///
/// [RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[derive(Default)]
pub enum Version {
    /// Version 1 (default)
    #[default]
    V1 = 0,

    /// Version 2
    V2 = 1,

    /// Version 3
    V3 = 2,
}

impl ValueOrd for Version {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        (*self as u8).value_cmp(&(*other as u8))
    }
}

/// X.509 `TbsCertificate` as defined in [RFC 5280 Section 4.1]
pub type TbsCertificate = TbsCertificateInner<Rfc5280>;

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
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct TbsCertificateInner<P: Profile = Rfc5280> {
    /// The certificate version.
    ///
    /// Note that this value defaults to Version 1 per the RFC. However,
    /// fields such as `issuer_unique_id`, `subject_unique_id` and `extensions`
    /// require later versions. Care should be taken in order to ensure
    /// standards compliance.
    #[asn1(context_specific = "0", default = "Default::default")]
    pub(crate) version: Version,

    pub(crate) serial_number: SerialNumber<P>,
    pub(crate) signature: AlgorithmIdentifier,
    pub(crate) issuer: Name,
    pub(crate) validity: Validity<P>,
    pub(crate) subject: Name,
    pub(crate) subject_public_key_info: SubjectPublicKeyInfo,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub(crate) issuer_unique_id: Option<BitString>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub(crate) subject_unique_id: Option<BitString>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) extensions: Option<ext::Extensions>,
}

impl<P: Profile> TbsCertificateInner<P> {
    /// [`Version`] of this certificate (v1/v2/v3).
    pub fn version(&self) -> Version {
        self.version
    }

    /// Serial number of this certificate.
    ///
    /// X.509 serial numbers are used to uniquely identify certificates issued by a given
    /// Certificate Authority (CA) identified in the `issuer` field.
    pub fn serial_number(&self) -> &SerialNumber<P> {
        &self.serial_number
    }

    /// Identifies the signature algorithm that this `TBSCertificate` should be signed with.
    ///
    /// In a signed certificate, matches [`CertificateInner::signature_algorithm`].
    pub fn signature(&self) -> &AlgorithmIdentifier {
        &self.signature
    }

    /// Certificate issuer: [`Name`] of the Certificate Authority (CA) which issued this
    /// certificate.
    pub fn issuer(&self) -> &Name {
        &self.issuer
    }

    /// Validity period for this certificate: time range in which a certificate is considered valid,
    /// after which it expires.
    pub fn validity(&self) -> &Validity<P> {
        &self.validity
    }

    /// Subject of this certificate: entity that the certificate is intended to represent or
    /// authenticate, e.g. an individual, a device, or an organization.
    pub fn subject(&self) -> &Name {
        &self.subject
    }

    /// Subject Public Key Info (SPKI): public key information about this certificate including
    /// algorithm identifier and key data.
    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfo {
        &self.subject_public_key_info
    }

    /// Issuer unique ID: unique identifier representing the issuing CA, as defined by the
    /// issuing CA.
    ///
    /// (NOTE: added in X.509 v2)
    pub fn issuer_unique_id(&self) -> &Option<BitString> {
        &self.issuer_unique_id
    }

    /// Subject unique ID: unique identifier representing the certificate subject, as defined by the
    /// issuing CA.
    ///
    /// (NOTE: added in X.509 v2)
    pub fn subject_unique_id(&self) -> &Option<BitString> {
        &self.subject_unique_id
    }

    /// Certificate extensions.
    ///
    /// Additional fields in a digital certificate that provide extra information beyond the
    /// standard fields. These extensions enhance the functionality and flexibility of certificates,
    /// allowing them to convey more specific details about the certificate's usage and constraints.
    ///
    /// (NOTE: added in X.509 v3)
    pub fn extensions(&self) -> Option<&ext::Extensions> {
        self.extensions.as_ref()
    }

    /// Decodes a single extension.
    ///
    /// Returns `Ok(None)` if the extension is not present.
    ///
    /// Otherwise, returns the extension, and indicates if the extension was marked critical in the
    /// boolean.
    ///
    /// ```
    /// # #[cfg(feature = "pem")]
    /// # fn pemonly() {
    /// # const CERT_PEM: &str = include_str!("../tests/examples/amazon.pem");
    /// use x509_cert::{der::DecodePem, ext::pkix::BasicConstraints, Certificate};
    /// let certificate = Certificate::from_pem(CERT_PEM.as_bytes()).expect("parse certificate");
    ///
    /// let (critical, constraints) = certificate.tbs_certificate().get_extension::<BasicConstraints>()
    ///     .expect("Failed to parse extension")
    ///     .expect("Basic constraints expected");
    /// # let _ = constraints;
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if multiple of these extensions are present.
    ///
    /// Returns a decoding error if decoding failed.
    pub fn get_extension<'a, T: Decode<'a> + AssociatedOid>(
        &'a self,
    ) -> Result<Option<(bool, T)>, <T as Decode<'a>>::Error> {
        let mut iter = self.filter_extensions::<T>().peekable();
        match iter.next() {
            None => Ok(None),
            Some(item) => match iter.peek() {
                Some(..) => Err(der::Error::from(ErrorKind::Failed).into()),
                None => Ok(Some(item?)),
            },
        }
    }

    /// Filters extensions by an associated OID
    ///
    /// Returns a filtered iterator over all the extensions with the OID.
    ///
    /// ```
    /// # #[cfg(feature = "pem")]
    /// # fn pemonly() {
    /// # const CERT_PEM: &str = include_str!("../tests/examples/amazon.pem");
    /// use x509_cert::{der::DecodePem, ext::pkix::BasicConstraints, Certificate};
    /// let certificate = Certificate::from_pem(CERT_PEM.as_bytes()).expect("parse certificate");
    ///
    /// let mut extensions_found = certificate.tbs_certificate().filter_extensions::<BasicConstraints>();
    /// while let Some(Ok((critical, extension))) = extensions_found.next() {
    ///     println!("Found (critical={critical}): {extension:?}");
    /// }
    /// # }
    /// ```
    ///
    /// # Safety
    ///
    /// According to [RFC 5290 section 4.2], extensions should not appear more than once.
    /// A better alternative is to use [`TbsCertificateInner::get_extension`] instead.
    ///
    /// [RFC 5290 section 4.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2
    pub fn filter_extensions<'a, T: Decode<'a> + AssociatedOid>(
        &'a self,
    ) -> impl 'a + Iterator<Item = Result<(bool, T), <T as Decode<'a>>::Error>> {
        self.extensions
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter(|e| e.extn_id == T::OID)
            .map(|e| Ok((e.critical, T::from_der(e.extn_value.as_bytes())?)))
    }
}

/// X.509 certificates are defined in [RFC 5280 Section 4.1].
///
/// [RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
pub type Certificate = CertificateInner<Rfc5280>;

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
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct CertificateInner<P: Profile = Rfc5280> {
    pub(crate) tbs_certificate: TbsCertificateInner<P>,
    pub(crate) signature_algorithm: AlgorithmIdentifier,
    pub(crate) signature: BitString,
}

impl<P: Profile> CertificateInner<P> {
    /// Get the [`TbsCertificateInner`] (i.e. the part the signature is computed over).
    pub fn tbs_certificate(&self) -> &TbsCertificateInner<P> {
        &self.tbs_certificate
    }

    /// Signature algorithm used to sign the serialization of [`CertificateInner::tbs_certificate`].
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// Signature over the DER serialization of [`CertificateInner::tbs_certificate`] using the
    /// algorithm identified in [`CertificateInner::signature_algorithm`].
    pub fn signature(&self) -> &BitString {
        &self.signature
    }
}

#[cfg(feature = "pem")]
impl<P: Profile> PemLabel for CertificateInner<P> {
    const PEM_LABEL: &'static str = "CERTIFICATE";
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
pub type PkiPath = Vec<Certificate>;

#[cfg(feature = "pem")]
impl<P: Profile> CertificateInner<P> {
    /// Parse a chain of pem-encoded certificates from a slice.
    ///
    /// Returns the list of certificates.
    pub fn load_pem_chain(mut input: &[u8]) -> Result<Vec<Self>, der::Error> {
        fn find_boundary<T>(haystack: &[T], needle: &[T]) -> Option<usize>
        where
            for<'a> &'a [T]: PartialEq,
        {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        }

        let mut certs = Vec::new();
        let mut position: usize = 0;

        let end_boundary = &b"-----END CERTIFICATE-----"[..];

        // Strip the trailing whitespaces
        loop {
            if input.is_empty() {
                break;
            }
            let last_pos = input.len() - 1;

            match input.get(last_pos) {
                Some(b'\r') | Some(b'\n') => {
                    input = &input[..last_pos];
                }
                _ => break,
            }
        }

        while position + 1 < input.len() {
            let rest = &input[position..];
            let end_pos = find_boundary(rest, end_boundary)
                .ok_or(pem::Error::PostEncapsulationBoundary)?
                + end_boundary.len();

            let cert_buf = &rest[..end_pos];
            let cert = Self::from_pem(cert_buf)?;
            certs.push(cert);

            position += end_pos;
        }

        Ok(certs)
    }
}

#[cfg(feature = "digest")]
impl<P> CertificateInner<P>
where
    P: Profile,
{
    /// Return the hash of the DER serialization of this certificate
    pub fn hash<D>(&self) -> der::Result<Output<D>>
    where
        D: Digest,
    {
        let mut digest = D::new();

        self.encode(&mut DigestWriter(&mut digest))?;

        Ok(digest.finalize())
    }
}
