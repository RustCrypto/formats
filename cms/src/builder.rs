// TODO NM #![cfg(feature = "std")]

//! CMS Builder

use crate::cert::CertificateChoices;
use crate::content_info::{CmsVersion, ContentInfo};
use crate::revocation::{RevocationInfoChoice, RevocationInfoChoices};
use crate::signed_data::{
    CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedAttributes,
    SignedData, SignerInfo, SignerInfos,
};
use crate::{PKCS9_CONTENT_TYPE_OID, PKCS9_MESSAGE_DIGEST_OID, PKCS9_SIGNING_TIME_OID};
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use const_oid::ObjectIdentifier;
use core::cmp::Ordering;
use core::fmt;
use der::asn1::{OctetString, OctetStringRef, SetOfVec};
use der::oid::db::DB;
use der::{Any, AnyRef, DateTime, Decode, Encode, Tag, ValueOrd};
use signature::digest::DynDigest;
use signature::{SignatureEncoding, Signer};
use spki::AlgorithmIdentifierOwned;
use std::time::SystemTime;
use x509_cert::attr::{Attribute, AttributeValue};

/// Error type
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// ASN.1 DER-related errors.
    Asn1(der::Error),

    /// Public key errors propagated from the [`spki::Error`] type.
    PublicKey(spki::Error),

    /// Signing error propagated for the [`signature::Signer`] type.
    Signature(signature::Error),

    /// Builder no table to build, because the struct is not properly configured
    Builder(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Asn1(err) => write!(f, "ASN.1 error: {}", err),
            Error::PublicKey(err) => write!(f, "public key error: {}", err),
            Error::Signature(err) => write!(f, "signature error: {}", err),
            Error::Builder(message) => write!(f, "builder error: {message}"),
        }
    }
}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
    }
}

impl From<spki::Error> for Error {
    fn from(err: spki::Error) -> Error {
        Error::PublicKey(err)
    }
}

impl From<signature::Error> for Error {
    fn from(err: signature::Error) -> Error {
        Error::Signature(err)
    }
}

type Result<T> = core::result::Result<T, Error>;

/// Builder for signedData PKCS #7
pub struct SignedDataBuilder {
    digest_algorithms: Vec<AlgorithmIdentifierOwned>,
    encap_content_info: Option<EncapsulatedContentInfo>,
    certificates: Option<Vec<CertificateChoices>>,
    crls: Option<Vec<RevocationInfoChoice>>,
    signer_infos: Vec<SignerInfo>,
    is_signed: bool,
    is_finalized: bool,
}

impl SignedDataBuilder {
    /// Create a new builder for `SignedData`
    pub fn new() -> SignedDataBuilder {
        Self {
            digest_algorithms: Vec::new(),
            encap_content_info: None,
            certificates: None,
            crls: None,
            signer_infos: Vec::new(),
            is_signed: false,
            is_finalized: false,
        }
    }

    /// Add a digest algorithm to the collection of message digest algorithms.
    /// RFC 5652 § 5.1: digestAlgorithms is a collection of message digest algorithm
    /// identifiers.  There MAY be any number of elements in the
    /// collection, including zero.  Each element identifies the message
    /// digest algorithm, along with any associated parameters, used by
    /// one or more signer.  The collection is intended to list the
    /// message digest algorithms employed by all of the signers, in any
    /// order, to facilitate one-pass signature verification.
    pub fn add_digest_algorithm(
        &mut self,
        digest_algorithm: AlgorithmIdentifierOwned,
    ) -> Result<&mut Self> {
        self.check_finalized()?;
        self.digest_algorithms.push(digest_algorithm);
        Ok(self)
    }

    /// Set the content of the PKCS #7
    pub fn set_content_info(&mut self, content_info: EncapsulatedContentInfo) -> Result<&mut Self> {
        self.check_finalized()?;
        self.check_signed()?;
        self.encap_content_info = Some(content_info);
        Ok(self)
    }

    /// Add a certificate to the certificate collection.
    /// RFC 5652 § 5.1:
    /// certificates is a collection of certificates.  It is intended that
    /// the set of certificates be sufficient to contain certification
    /// paths from a recognized "root" or "top-level certification
    /// authority" to all of the signers in the signerInfos field.  There
    /// may be more certificates than necessary, and there may be
    /// certificates sufficient to contain certification paths from two or
    /// more independent top-level certification authorities.  There may
    /// also be fewer certificates than necessary, if it is expected that
    /// recipients have an alternate means of obtaining necessary
    /// certificates (e.g., from a previous set of certificates).  The
    /// signer's certificate MAY be included.  The use of version 1
    /// attribute certificates is strongly discouraged.
    pub fn add_certificate(&mut self, certificate: CertificateChoices) -> Result<&mut Self> {
        self.check_finalized()?;
        if self.certificates.is_none() {
            self.certificates = Some(Vec::new());
        }
        if let Some(certificates) = &mut self.certificates {
            certificates.push(certificate);
        }
        Ok(self)
    }

    /// Add a CRL to the collection of CRLs.
    /// RFC 5652 § 5.1:
    /// crls is a collection of revocation status information.  It is
    /// intended that the collection contain information sufficient to
    /// determine whether the certificates in the certificates field are
    /// valid, but such correspondence is not necessary.  Certificate
    /// revocation lists (CRLs) are the primary source of revocation
    /// status information.  There MAY be more CRLs than necessary, and
    /// there MAY also be fewer CRLs than necessary.
    pub fn add_crl(&mut self, crl: RevocationInfoChoice) -> Result<&mut Self> {
        self.check_finalized()?;
        if self.crls.is_none() {
            self.crls = Some(Vec::new());
        }
        if let Some(crls) = &mut self.crls {
            crls.push(crl);
        }
        Ok(self)
    }

    /// Sign the encapsulated content according to
    /// [RFC 5652 § 5.4](https://datatracker.ietf.org/doc/html/rfc5652#section-5.4)
    /// This method may be called multiple times for different `signer`s. Each call will add a
    /// `SignerInfo` to the PKCS #7 object. After first signing, the encapsulated content will be
    /// locked and can't be changed any more, as this would invalidate existing signatures.
    /// If an `external_message_digest` is passed in, it is assumed, that we are signing external
    /// content (see RFC 5652 § 5.2). In this case, the `eContent` in `EncapsulatedContentInfo`
    /// must be `None`.
    /// This method creates `SignedAttributes`(, if they do not already exist), as the signing time
    /// is added. This also means, that the `signed_attributes` including the message digest are
    /// signed and not the encapsulated content itself.
    pub fn sign<S, Signature>(
        &mut self,
        signer: &mut S,
        mut signer_info: SignerInfo,
        external_message_digest: Option<&[u8]>,
    ) -> Result<&mut Self>
    where
        S: Signer<Signature>,
        Signature: SignatureEncoding,
    {
        let encap_content_info = match &self.encap_content_info {
            None => {
                return Err(Error::Builder(
                    "Encapsulated content info missing, cannot sign".to_string(),
                ))
            }
            Some(encap_content_info) => {
                if let None = external_message_digest {
                    // Internal content must be present
                    if encap_content_info.econtent.is_none() {
                        return Err(Error::Builder(
                            "Encapsulated content missing, cannot sign".to_string(),
                        ));
                    }
                } else {
                    // Internal content must be empty
                    if encap_content_info.econtent.is_some() {
                        return Err(Error::Builder(
                            "Encapsulated content must be empty, if external digest is given."
                                .to_string(),
                        ));
                    }
                }
                encap_content_info
            }
        };

        let message_digest = match external_message_digest {
            Some(external_content_digest) => external_content_digest.to_vec(),
            None => match &encap_content_info.econtent {
                None => return Err(Error::Builder("Content missing, cannot sign".to_string())),
                Some(content) => {
                    let mut hasher = get_hasher(&signer_info.digest_alg).ok_or_else(|| {
                        Error::Builder(format!(
                            "Unsupported hash algorithm: {}",
                            &signer_info.digest_alg.oid.to_string()
                        ))
                    })?;
                    // TODO NM is this value DER encoded TLV or is it just V? For hashing, only V must be used.
                    hasher.update(content.value());
                    hasher.finalize_reset().to_vec()
                }
            },
        };

        // We set the signing time attribute. In this case, signed attributes are used and
        // will be signed instead of the eContent itself.
        if let Some(signed_attributes) = &mut signer_info.signed_attrs {
            if !signed_attributes
                .iter()
                .any(|attr| attr.oid.cmp(&PKCS9_SIGNING_TIME_OID) == Ordering::Equal)
            {
                // Add current time as signing time
                signed_attributes.add(create_signing_time_attribute()?)?;
            }
        } else {
            // Add signed attributes with signing time attribute and content type attribute
            let mut signed_attributes = SignedAttributes::new();
            signed_attributes.add(create_signing_time_attribute()?)?;
            signer_info.signed_attrs = Some(signed_attributes);
        }

        // Add digest attribute to (to be) signed attributes
        let signed_attributes = signer_info
            .signed_attrs
            .as_mut()
            .expect("Signed attributes must be present.");
        signed_attributes.add(create_message_digest_attribute(&message_digest)?)?;

        // The content-type attribute type specifies the content type of the
        // ContentInfo within signed-data or authenticated-data.  The content-
        // type attribute type MUST be present whenever signed attributes are
        // present in signed-data or authenticated attributes present in
        // authenticated-data.  The content-type attribute value MUST match the
        // encapContentInfo eContentType value in the signed-data or
        // authenticated-data.
        let econtent_type = encap_content_info.econtent_type;
        let signed_attributes_content_type = signed_attributes
            .iter()
            .find(|attr| attr.oid.cmp(&PKCS9_CONTENT_TYPE_OID) == Ordering::Equal);
        if let Some(signed_attributes_content_type) = signed_attributes_content_type {
            // Check against `eContentType`
            if signed_attributes_content_type.oid != econtent_type {
                return Err(Error::Builder(
                    "Mismatch between content types: encapsulated content info <-> signed attributes."
                        .to_string(),
                ));
            }
        } else {
            signed_attributes.add(create_content_type_attribute(econtent_type)?)?;
        }

        // Now use `signer` to sign the DER encoded signed attributes
        let mut signed_attributes_der = Vec::new();
        signed_attributes.encode_to_vec(&mut signed_attributes_der)?;
        let signature: Signature = signer.try_sign(&signed_attributes_der)?;
        let signature_der = signature.to_vec();
        signer_info.signature = OctetString::new(signature_der)?;
        self.signer_infos.push(signer_info);

        self.is_signed = true;

        Ok(self)
    }

    /// Return finalized `SignedData` struct.
    /// This method returns a `ContentInfo` of type `signedData`. After this call, the builder cannot
    /// be used any more.
    pub fn build(&mut self) -> Result<ContentInfo> {
        self.check_finalized()?;

        // Sort digest_algorithms before adding to a DigestAlgorithmIdentifiers object
        // -> See der::asn1::set_of
        self.digest_algorithms
            .sort_by(|a, b| a.value_cmp(b).unwrap());
        let mut digest_algorithms: DigestAlgorithmIdentifiers = DigestAlgorithmIdentifiers::new();
        for digest_algorithm in self.digest_algorithms.drain(..) {
            digest_algorithms.add(digest_algorithm)?;
        }

        let encap_content_info = self
            .encap_content_info
            .clone()
            .ok_or_else(|| Error::Builder("EncapsulatedContentInfo is required".to_string()))?;

        let certificates = if let Some(certificates) = &mut self.certificates {
            // Ensure lexicographical DER ordering:
            certificates.sort_by(|a, b| a.value_cmp(b).unwrap());
            let mut certificate_set: CertificateSet = CertificateSet(Default::default());
            for certificate in certificates.drain(..) {
                certificate_set.0.add(certificate)?;
            }
            Some(certificate_set)
        } else {
            None
        };

        let crls = if let Some(crls) = &mut self.crls {
            // Ensure lexicographical DER ordering:
            crls.sort_by(|a, b| a.value_cmp(b).unwrap());
            let mut revocation_info_choices: RevocationInfoChoices =
                RevocationInfoChoices(Default::default());
            for crl in crls.drain(..) {
                revocation_info_choices.0.add(crl)?;
            }
            Some(revocation_info_choices)
        } else {
            None
        };

        self.signer_infos.sort_by(|a, b| a.value_cmp(b).unwrap());
        let mut signer_infos = SignerInfos(Default::default());
        for signer_info in &self.signer_infos {
            signer_infos.0.add(signer_info.to_owned())?;
        }

        let signed_data = SignedData {
            version: self.calculate_version(),
            digest_algorithms,
            encap_content_info,
            certificates,
            crls,
            signer_infos,
        };

        let signed_data_der = signed_data.to_der()?;
        let content = AnyRef::try_from(signed_data_der.as_slice())?;

        let signed_data = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: Any::from(content),
        };

        self.is_finalized = true; // no more changes allowed after here
        Ok(signed_data)
    }

    fn calculate_version(&self) -> CmsVersion {
        // RFC 5652, 5.1.  SignedData Type
        // IF ((certificates is present) AND
        //             (any certificates with a type of other are present)) OR
        //             ((crls is present) AND
        //             (any crls with a type of other are present))
        //          THEN version MUST be 5
        //          ELSE
        //             IF (certificates is present) AND
        //                (any version 2 attribute certificates are present)
        //             THEN version MUST be 4
        //             ELSE
        //                IF ((certificates is present) AND
        //                   (any version 1 attribute certificates are present)) OR
        //                   (any SignerInfo structures are version 3) OR
        //                   (encapContentInfo eContentType is other than id-data)
        //                THEN version MUST be 3
        //                ELSE version MUST be 1
        let other_certificates_are_present = if let Some(certificates) = &self.certificates {
            certificates.iter().any(|certificate| match certificate {
                CertificateChoices::Other(_) => true,
                _ => false,
            })
        } else {
            false
        };
        // v1 and v2 currently not supported
        // let v2_certificates_are_present = if let Some(certificates) = &self.certificates {
        //     certificates.iter().any(|certificate| match certificate {
        //         CertificateChoices::V2AttrCert(_) => true,
        //         _ => false,
        //     })
        // } else {
        //     false
        // };
        // let v1_certificates_are_present = if let Some(certificates) = &self.certificates {
        //     certificates.iter().any(|certificate| match certificate {
        //         CertificateChoices::V1AttrCert(_) => true,
        //         _ => false,
        //     })
        // } else {
        //     false
        // };
        let v2_certificates_are_present = false;
        let v1_certificates_are_present = false;
        let other_crls_are_present = if let Some(crls) = &self.crls {
            crls.iter()
                .any(|revocation_info_choice| match revocation_info_choice {
                    RevocationInfoChoice::Other(_) => true,
                    _ => false,
                })
        } else {
            false
        };
        let v3_signer_infos_present = self
            .signer_infos
            .iter()
            .any(|signer_info| signer_info.version == CmsVersion::V3);
        let content_not_data = match &self.encap_content_info {
            None => false,
            Some(encap_content_info) => {
                encap_content_info.econtent_type
                    != *DB
                        .by_name("id-data")
                        .expect("id-data not found in OID database")
            }
        };

        if other_certificates_are_present || other_crls_are_present {
            CmsVersion::V5
        } else if v2_certificates_are_present {
            CmsVersion::V4
        } else if v1_certificates_are_present || v3_signer_infos_present || content_not_data {
            CmsVersion::V3
        } else {
            CmsVersion::V1
        }
    }

    fn check_finalized(&self) -> Result<()> {
        if self.is_finalized {
            Err(Error::Builder(
                "Builder is finalized. Changes are not possible.".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    fn check_signed(&self) -> Result<()> {
        if self.is_signed {
            Err(Error::Builder(
                "Content can't be changed, as Builder is already signed.".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

/// Get a hasher for a given digest algorithm
fn get_hasher(
    digest_algorithm_identifier: &AlgorithmIdentifierOwned,
) -> Option<Box<dyn DynDigest>> {
    let digest_name = DB.by_oid(&digest_algorithm_identifier.oid)?;
    match digest_name {
        "id-sha1" => Some(Box::new(sha1::Sha1::default())),
        "id-sha256" => Some(Box::new(sha2::Sha256::default())),
        "id-sha384" => Some(Box::new(sha2::Sha384::default())),
        "id-sha512" => Some(Box::new(sha2::Sha512::default())),
        "id-sha224" => Some(Box::new(sha2::Sha224::default())),
        "id-sha-3-224" => Some(Box::new(sha3::Sha3_224::default())),
        "id-sha-3-256" => Some(Box::new(sha3::Sha3_256::default())),
        "id-sha-3-384" => Some(Box::new(sha3::Sha3_384::default())),
        "id-sha-3-512" => Some(Box::new(sha3::Sha3_512::default())),
        // TODO add more hashers
        _ => None,
    }
}

/// Create a content-type attribute according to
/// [RFC 5652 § 11.1](https://datatracker.ietf.org/doc/html/rfc5652#section-11.1)
pub fn create_content_type_attribute(content_type: ObjectIdentifier) -> Result<Attribute> {
    let content_type_attribute_value =
        AttributeValue::new(Tag::ObjectIdentifier, content_type.as_bytes())?;
    let mut values = SetOfVec::new();
    values.add(content_type_attribute_value)?;
    let attribute = Attribute {
        oid: PKCS9_CONTENT_TYPE_OID,
        values,
    };
    Ok(attribute)
}

/// Create a message digest attribute according to
/// [RFC 5652 § 11.2](https://datatracker.ietf.org/doc/html/rfc5652#section-11.2)
pub fn create_message_digest_attribute(message_digest: &[u8]) -> Result<Attribute> {
    let message_digest_der = OctetStringRef::new(message_digest)?;
    let message_digest_attribute_value =
        AttributeValue::new(Tag::OctetString, message_digest_der.as_bytes())?;
    let mut values = SetOfVec::new();
    values.add(message_digest_attribute_value)?;
    let attribute = Attribute {
        oid: PKCS9_MESSAGE_DIGEST_OID,
        values,
    };
    Ok(attribute)
}

/// Create a signing time attribute according to
/// [RFC 5652 § 11.3](https://datatracker.ietf.org/doc/html/rfc5652#section-11.3)
/// Dates between 1 January 1950 and 31 December 2049 (inclusive) MUST be
/// encoded as UTCTime.  Any dates with year values before 1950 or after
/// 2049 MUST be encoded as GeneralizedTime.
pub fn create_signing_time_attribute() -> Result<Attribute> {
    let now = DateTime::from_system_time(SystemTime::now())?;
    let tag = if now.year() < 1950 || now.year() > 2049 {
        Tag::GeneralizedTime
    } else {
        Tag::UtcTime
    };
    // let mut signing_time_buf = Vec::new();
    let time_der = if tag == Tag::GeneralizedTime {
        // der::asn1::GeneralizedTime::from_date_time(now).encode_to_vec(&mut signing_time_buf)?;
        der::asn1::GeneralizedTime::from_date_time(now).to_der()?
    } else {
        // der::asn1::UtcTime::from_date_time(now)?.encode_to_vec(&mut signing_time_buf)?;
        der::asn1::UtcTime::from_date_time(now)?.to_der()?
    };
    //let signing_time_attribute_value = AttributeValue::new(tag, signing_time_buf.as_slice())?;
    let signing_time_attribute_value = AttributeValue::from_der(&time_der)?;
    let mut values = SetOfVec::<AttributeValue>::new();
    values.add(signing_time_attribute_value)?;
    let attribute = Attribute {
        oid: PKCS9_SIGNING_TIME_OID,
        values,
    };
    Ok(attribute)
}
