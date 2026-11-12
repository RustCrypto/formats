//! Builders for signed CMS messages and signer information.

use super::{Result, create_content_type_attribute, create_message_digest_attribute};
use crate::{
    cert::CertificateChoices,
    content_info::{CmsVersion, ContentInfo},
    revocation::{RevocationInfoChoice, RevocationInfoChoices},
    signed_data::{
        CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignatureValue,
        SignedAttributes, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
        UnsignedAttributes,
    },
};
use alloc::{borrow::ToOwned, boxed::Box, vec, vec::Vec};
use const_oid::ObjectIdentifier;
use core::{cmp::Ordering, future::ready};
use der::{Any, AnyRef, Encode, ErrorKind, asn1::BitString, oid::db::DB};
use digest::Digest;
use signature::{
    AsyncRandomizedSigner, AsyncSigner, Keypair, RandomizedSigner, Signer, digest::DynDigest,
    rand_core::CryptoRng,
};
use spki::AlgorithmIdentifierOwned;
use spki::{DynSignatureAlgorithmIdentifier, EncodePublicKey, SignatureBitStringEncoding};
use x509_cert::{
    attr::Attribute,
    builder::{self, AsyncBuilder, Builder},
    certificate::{Profile, Rfc5280},
};

/// Collect info needed for creating a `SignerInfo`.
/// Calling `build()` on this struct will
/// - calculate the correct `CMSVersion` (depends on `sid`)
/// - calculate the signature
/// - set the signing time attribute
/// - create a `SignerInfo` object
pub struct SignerInfoBuilder<'s, P: Profile = Rfc5280> {
    sid: SignerIdentifier<P>,
    digest_algorithm: AlgorithmIdentifierOwned,
    signed_attributes: Option<Vec<Attribute>>,
    unsigned_attributes: Option<Vec<Attribute>>,
    encapsulated_content_info: &'s EncapsulatedContentInfo,
    external_message_digest: Option<&'s [u8]>,
}

impl<'s, P: Profile> SignerInfoBuilder<'s, P> {
    /// Create a new `SignerInfoBuilder`. This is used for adding `SignerInfo`s to `SignedData`
    /// structures.
    /// The content to be signed can be stored externally. In this case `eContent` in
    /// `encapsulated_content_info` must be `None` and the message digest must be passed with
    /// `external_message_digest`. `digest_algorithm` must match the used digest algorithm.
    pub fn new(
        sid: SignerIdentifier<P>,
        digest_algorithm: AlgorithmIdentifierOwned,
        encapsulated_content_info: &'s EncapsulatedContentInfo,
        external_message_digest: Option<&'s [u8]>,
    ) -> Result<Self> {
        Ok(SignerInfoBuilder {
            sid,
            digest_algorithm,
            signed_attributes: None,
            unsigned_attributes: None,
            encapsulated_content_info,
            external_message_digest,
        })
    }

    /// Add a "signed" attribute. The attribute will be signed together with the other "signed"
    /// attributes, when `build()` is called.
    pub fn add_signed_attribute(&mut self, signed_attribute: Attribute) -> Result<&mut Self> {
        if let Some(signed_attributes) = &mut self.signed_attributes {
            signed_attributes.push(signed_attribute);
        } else {
            self.signed_attributes = Some(vec![signed_attribute]);
        }
        Ok(self)
    }

    /// Add an unsigned attribute.
    pub fn add_unsigned_attribute(&mut self, unsigned_attribute: Attribute) -> Result<&mut Self> {
        if let Some(unsigned_attributes) = &mut self.unsigned_attributes {
            unsigned_attributes.push(unsigned_attribute);
        } else {
            self.unsigned_attributes = Some(vec![unsigned_attribute]);
        }
        Ok(self)
    }

    /// Calculate the CMSVersion of the signer info.
    /// Intended to be called during building the `SignerInfo`.
    /// RFC 5652 § 5.3: version is the syntax version number.  If the SignerIdentifier is
    /// the CHOICE issuerAndSerialNumber, then the version MUST be 1. If
    /// the SignerIdentifier is subjectKeyIdentifier, then the version MUST be 3.
    pub fn version(&self) -> CmsVersion {
        match self.sid {
            SignerIdentifier::IssuerAndSerialNumber(_) => CmsVersion::V1,
            SignerIdentifier::SubjectKeyIdentifier(_) => CmsVersion::V3,
        }
    }
}

impl<P: Profile> Builder for SignerInfoBuilder<'_, P> {
    type Output = SignerInfo<P>;

    /// Calculate the data to be signed
    /// [RFC 5652 § 5.4](https://www.rfc-editor.org/info/rfc5652#section-5.4)
    /// If an `external_message_digest` is passed in, it is assumed, that we are signing external
    /// content (see RFC 5652 § 5.2). In this case, the `eContent` in `EncapsulatedContentInfo`
    /// must be `None`.
    fn finalize<S>(&mut self, _signer: &S) -> builder::Result<Vec<u8>>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        let message_digest = match self.external_message_digest {
            Some(external_content_digest) => {
                if self.encapsulated_content_info.econtent.is_some() {
                    // Encapsulated content must be empty, if external digest is given.
                    return Err(der::Error::from(ErrorKind::Failed).into());
                }
                Some(external_content_digest.to_vec())
            }
            None => match &self.encapsulated_content_info.econtent {
                None => {
                    // This case is allowed. E.g. for degenerate certificates-only messages.
                    // See RFC 5652 § 5.2 or RFC 8894 § 3.4.
                    None
                }
                Some(content) => {
                    let mut hasher = get_hasher(&self.digest_algorithm).ok_or_else(|| {
                        // Unsupported hash algorithm: {}, &self.digest_algorithm.oid.to_string()
                        builder::Error::from(der::Error::from(ErrorKind::Failed))
                    })?;
                    // Only the octets comprising the value of the eContent
                    // OCTET STRING are input to the message digest algorithm, not the tag
                    // or the length octets.
                    let content_value = content.value();
                    hasher.update(content_value);
                    Some(hasher.finalize_reset().to_vec())
                }
            },
        };

        // This implementation uses signed attributes to store the message digest.
        if self.signed_attributes.is_none() {
            self.signed_attributes = Some(vec![]);
        }

        let signed_attributes = self
            .signed_attributes
            .as_mut()
            .expect("Signed attributes must be present.");

        if let Some(message_digest) = message_digest {
            // Add digest attribute to (to be) signed attributes
            signed_attributes.push(
                create_message_digest_attribute(&message_digest)
                    .map_err(|_| der::Error::from(ErrorKind::Failed))?,
            );

            // The content-type attribute type specifies the content type of the
            // ContentInfo within signed-data or authenticated-data.  The content-
            // type attribute type MUST be present whenever signed attributes are
            // present in signed-data or authenticated attributes present in
            // authenticated-data.  The content-type attribute value MUST match the
            // encapContentInfo eContentType value in the signed-data or
            // authenticated-data.
            let econtent_type = self.encapsulated_content_info.econtent_type;
            let signed_attributes_content_type = signed_attributes.iter().find(|attr| {
                attr.oid.cmp(&const_oid::db::rfc5911::ID_CONTENT_TYPE) == Ordering::Equal
            });
            if let Some(signed_attributes_content_type) = signed_attributes_content_type {
                if signed_attributes_content_type.values.len() != 1 {
                    return Err(der::Error::from(ErrorKind::Failed).into());
                }
                let Some(value) = signed_attributes_content_type.values.get(0) else {
                    return Err(der::Error::from(ErrorKind::Failed).into());
                };

                let value = value.decode_as::<ObjectIdentifier>()?;

                // Check against `eContentType`
                if value != econtent_type {
                    // Mismatch between content types: encapsulated content info <-> signed attributes.
                    return Err(der::Error::from(ErrorKind::Failed).into());
                }
            } else {
                signed_attributes.push(
                    create_content_type_attribute(econtent_type)
                        .map_err(|_| der::Error::from(ErrorKind::Failed))?,
                );
            }
        }

        // Now use `signer` to sign the DER encoded signed attributes
        let signed_attributes = SignedAttributes::try_from(signed_attributes.to_owned())
            .map_err(|_| der::Error::from(ErrorKind::Failed))?;
        let mut signed_attributes_der = Vec::new();
        signed_attributes.encode_to_vec(&mut signed_attributes_der)?;

        Ok(signed_attributes_der)
    }

    fn assemble<S>(self, signature: BitString, signer: &S) -> builder::Result<Self::Output>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        let signed_attrs = self.signed_attributes.as_ref().map(|signed_attributes| {
            SignedAttributes::try_from(signed_attributes.to_owned()).unwrap()
        });
        let unsigned_attrs = self
            .unsigned_attributes
            .as_ref()
            .map(|unsigned_attributes| {
                UnsignedAttributes::try_from(unsigned_attributes.to_owned()).unwrap()
            });

        let signature_value =
            SignatureValue::new(signature.raw_bytes()).map_err(builder::Error::from)?;

        let signature_algorithm = signer.signature_algorithm_identifier()?;

        Ok(SignerInfo {
            version: self.version(),
            sid: self.sid.clone(),
            digest_alg: self.digest_algorithm,
            signed_attrs,
            signature_algorithm,
            signature: signature_value,
            unsigned_attrs,
        })
    }
}

/// Builder for signedData (CMS and PKCS #7)
pub struct SignedDataBuilder<'s, P: Profile = Rfc5280> {
    digest_algorithms: Vec<AlgorithmIdentifierOwned>,
    encapsulated_content_info: &'s EncapsulatedContentInfo,
    certificates: Option<Vec<CertificateChoices<P>>>,
    crls: Option<Vec<RevocationInfoChoice>>,
    signer_infos: Vec<SignerInfo<P>>,
}

impl<'s, P: Profile> SignedDataBuilder<'s, P> {
    /// Create a new builder for `SignedData`
    pub fn new(encapsulated_content_info: &'s EncapsulatedContentInfo) -> Self {
        Self {
            digest_algorithms: Vec::new(),
            encapsulated_content_info,
            certificates: None,
            crls: None,
            signer_infos: Vec::new(),
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
        self.digest_algorithms.push(digest_algorithm);
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
    pub fn add_certificate(&mut self, certificate: CertificateChoices<P>) -> Result<&mut Self> {
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
        if self.crls.is_none() {
            self.crls = Some(Vec::new());
        }
        if let Some(crls) = &mut self.crls {
            crls.push(crl);
        }
        Ok(self)
    }

    /// Add a signer info. The signature will be calculated. Note that the encapsulated content
    /// must not be changed after the first signer info was added.
    pub fn add_signer_info<S, Signature>(
        &mut self,
        signer_info_builder: SignerInfoBuilder<'_, P>,
        signer: &S,
    ) -> Result<&mut Self>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S: Signer<Signature>,
        S::VerifyingKey: EncodePublicKey,
        Signature: SignatureBitStringEncoding,
    {
        self.add_signer_info_cb::<S, Signature, _>(signer_info_builder, signer, |_| Ok(()))
    }

    /// Add a signer info. The signature will be calculated. Note that the encapsulated content
    /// must not be changed after the first signer info was added.
    pub fn add_signer_info_cb<S, Signature, CB>(
        &mut self,
        signer_info_builder: SignerInfoBuilder<'_, P>,
        signer: &S,
        callback: CB,
    ) -> Result<&mut Self>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S: Signer<Signature>,
        S::VerifyingKey: EncodePublicKey,
        Signature: SignatureBitStringEncoding,
        CB: FnOnce(&mut SignerInfo<P>) -> Result<()>,
    {
        let mut signer_info = signer_info_builder
            .build::<S, Signature>(signer)
            .map_err(|_| der::Error::from(ErrorKind::Failed))?;

        callback(&mut signer_info)?;

        self.signer_infos.push(signer_info);

        Ok(self)
    }

    /// Add a signer info. The signature will be calculated. Note that the encapsulated content
    /// must not be changed after the first signer info was added.
    pub fn add_signer_info_with_rng<S, Signature, R>(
        &mut self,
        signer_info_builder: SignerInfoBuilder<'_, P>,
        signer: &S,
        rng: &mut R,
    ) -> Result<&mut Self>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S: RandomizedSigner<Signature>,
        S::VerifyingKey: EncodePublicKey,
        Signature: SignatureBitStringEncoding,
        R: CryptoRng + ?Sized,
    {
        self.add_signer_info_with_rng_cb::<S, Signature, _, R>(
            signer_info_builder,
            signer,
            |_| Ok(()),
            rng,
        )
    }

    /// Add a signer info. The signature will be calculated. Note that the encapsulated content
    /// must not be changed after the first signer info was added.
    pub fn add_signer_info_with_rng_cb<S, Signature, CB, R>(
        &mut self,
        signer_info_builder: SignerInfoBuilder<'_, P>,
        signer: &S,
        callback: CB,
        rng: &mut R,
    ) -> Result<&mut Self>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S: RandomizedSigner<Signature>,
        S::VerifyingKey: EncodePublicKey,
        Signature: SignatureBitStringEncoding,
        CB: FnOnce(&mut SignerInfo<P>) -> Result<()>,
        R: CryptoRng + ?Sized,
    {
        let mut signer_info = signer_info_builder
            .build_with_rng::<S, Signature, R>(signer, rng)
            .map_err(|_| der::Error::from(ErrorKind::Failed))?;

        callback(&mut signer_info)?;

        self.signer_infos.push(signer_info);

        Ok(self)
    }

    /// Add a signer info. The signature will be calculated. Note that the encapsulated content
    /// must not be changed after the first signer info was added.
    pub async fn add_signer_info_async<S, Signature>(
        &mut self,
        signer_info_builder: SignerInfoBuilder<'_, P>,
        signer: &S,
    ) -> Result<&mut Self>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S: AsyncSigner<Signature>,
        S::VerifyingKey: EncodePublicKey,
        Signature: SignatureBitStringEncoding,
    {
        self.add_signer_info_cb_async(signer_info_builder, signer, |_| ready(Ok(())))
            .await
    }

    /// Add a signer info. The signature will be calculated. Note that the encapsulated content
    /// must not be changed after the first signer info was added.
    pub async fn add_signer_info_cb_async<S, Signature, F, CB>(
        &mut self,
        signer_info_builder: SignerInfoBuilder<'_, P>,
        signer: &S,
        callback: CB,
    ) -> Result<&mut Self>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S: AsyncSigner<Signature>,
        S::VerifyingKey: EncodePublicKey,
        Signature: SignatureBitStringEncoding,
        F: Future<Output = Result<()>>,
        CB: FnOnce(&mut SignerInfo<P>) -> F,
    {
        let mut signer_info = signer_info_builder
            .build_async::<S, Signature>(signer)
            .await
            .map_err(|_| der::Error::from(ErrorKind::Failed))?;

        callback(&mut signer_info).await?;

        self.signer_infos.push(signer_info);

        Ok(self)
    }

    /// Add a signer info. The signature will be calculated. Note that the encapsulated content
    /// must not be changed after the first signer info was added.
    pub async fn add_signer_info_with_rng_async<S, Signature, R>(
        &mut self,
        signer_info_builder: SignerInfoBuilder<'_, P>,
        signer: &S,
        rng: &mut R,
    ) -> Result<&mut Self>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S: AsyncRandomizedSigner<Signature>,
        S::VerifyingKey: EncodePublicKey,
        Signature: SignatureBitStringEncoding,
        R: CryptoRng + ?Sized,
    {
        self.add_signer_info_with_rng_cb_async(signer_info_builder, signer, rng, |_| ready(Ok(())))
            .await
    }

    /// Add a signer info. The signature will be calculated. Note that the encapsulated content
    /// must not be changed after the first signer info was added.
    pub async fn add_signer_info_with_rng_cb_async<S, Signature, R, F, CB>(
        &mut self,
        signer_info_builder: SignerInfoBuilder<'_, P>,
        signer: &S,
        rng: &mut R,
        callback: CB,
    ) -> Result<&mut Self>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S: AsyncRandomizedSigner<Signature>,
        S::VerifyingKey: EncodePublicKey,
        Signature: SignatureBitStringEncoding,
        R: CryptoRng + ?Sized,
        F: Future<Output = Result<()>>,
        CB: FnOnce(&mut SignerInfo<P>) -> F,
    {
        let mut signer_info = signer_info_builder
            .build_with_rng_async::<S, Signature, R>(signer, rng)
            .await
            .map_err(|_| der::Error::from(ErrorKind::Failed))?;

        callback(&mut signer_info).await?;

        self.signer_infos.push(signer_info);

        Ok(self)
    }

    /// This method returns a `ContentInfo` of type `signedData`.
    pub fn build(&mut self) -> Result<ContentInfo> {
        let digest_algorithms =
            DigestAlgorithmIdentifiers::try_from(self.digest_algorithms.to_owned()).unwrap();

        let encap_content_info = self.encapsulated_content_info.clone();

        let certificates = self
            .certificates
            .as_mut()
            .map(|certificates| CertificateSet::try_from(certificates.to_owned()).unwrap());

        let crls = self
            .crls
            .as_mut()
            .map(|crls| RevocationInfoChoices::try_from(crls.to_owned()).unwrap());

        let signer_infos = SignerInfos::try_from(self.signer_infos.clone()).unwrap();

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
            certificates
                .iter()
                .any(|certificate| matches!(certificate, CertificateChoices::Other(_)))
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
            crls.iter().any(|revocation_info_choice| {
                matches!(revocation_info_choice, RevocationInfoChoice::Other(_))
            })
        } else {
            false
        };
        let v3_signer_infos_present = self
            .signer_infos
            .iter()
            .any(|signer_info| signer_info.version == CmsVersion::V3);
        let content_not_data =
            self.encapsulated_content_info.econtent_type != const_oid::db::rfc5911::ID_DATA;

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
}

/// Get a hasher for a given digest algorithm
fn get_hasher(
    digest_algorithm_identifier: &AlgorithmIdentifierOwned,
) -> Option<Box<dyn DynDigest>> {
    let digest_name = DB.by_oid(&digest_algorithm_identifier.oid)?;
    match digest_name {
        "id-sha1" => Some(Box::new(sha1::Sha1::new())),
        "id-sha256" => Some(Box::new(sha2::Sha256::new())),
        "id-sha384" => Some(Box::new(sha2::Sha384::new())),
        "id-sha512" => Some(Box::new(sha2::Sha512::new())),
        "id-sha224" => Some(Box::new(sha2::Sha224::new())),
        "id-sha-3-224" => Some(Box::new(sha3::Sha3_224::new())),
        "id-sha-3-256" => Some(Box::new(sha3::Sha3_256::new())),
        "id-sha-3-384" => Some(Box::new(sha3::Sha3_384::new())),
        "id-sha-3-512" => Some(Box::new(sha3::Sha3_512::new())),
        _ => None,
    }
}
