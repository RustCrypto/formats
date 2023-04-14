//! PKCS #7 Builder

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use const_oid::db::DB;
use core::cmp::Ordering;
use core::fmt;
use der::oid::db::{Database, DB};
use spki::{DynSignatureAlgorithmIdentifier, EncodePublicKey, ObjectIdentifier};
use crate::algorithm_identifier_types::{DigestAlgorithmIdentifier, DigestAlgorithmIdentifiers};
use crate::cms_version::CmsVersion;
use crate::{ContentInfo, PKCS9_SIGNING_TIME_OID};
use crate::ContentType::SignedData;
use crate::encapsulated_content_info::EncapsulatedContentInfo;
use crate::revocation_info_choices::RevocationInfoChoices;
use crate::signed_data_content::{CertificateSet, SignedDataContent};
use crate::signer_info::{SignerInfo, SignerInfos};

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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Asn1(err) => write!(f, "ASN.1 error: {}", err),
            Error::PublicKey(err) => write!(f, "public key error: {}", err),
            Error::Signature(err) => write!(f, "signature error: {}", err),
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



pub struct SignedDataBuilder<'s> {
    version: CmsVersion,
    digest_algorithms: Vec<DigestAlgorithmIdentifier<'s>>,
    encap_content_info: Option<EncapsulatedContentInfo<'s>>,
    certificates: Option<CertificateSet<'s>>,
    crls: Option<RevocationInfoChoices<'s>>,
    signer_infos: SignerInfos<'s>,
    is_signed: bool,
}

impl<'s> SignedDataBuilder<'s> {
    pub fn new() -> SignedDataBuilder {
        Self {
            version,
            digest_algorithms: Vec::new(),
            encap_content_info: None,
            certificates: None,
            crls: None,
            signer_infos: SignerInfos::new(),
            is_signed: false,
        }
    }

    pub fn add_digest_algorithm(&mut self, digest_algorithm: DigestAlgorithmIdentifier) -> Result<&Self> {
        self.digest_algorithms.push(digest_algorithm)?;
        Ok(self)
    }

    pub fn set_content_info(&mut self, content_info: EncapsulatedContentInfo) -> &Self {
        self.encap_content_info = Some(content_info);
        self
    }

    pub fn add_certificate(&self) -> &Self {
        self
    }

    pub fn add_crl(&self) -> &Self {
        self
    }

    pub fn add_signer(&self, ) -> &Self {
        self
    }

    // Sign the message. Return finalized `SignedData` struct.
    pub fn sign_and_build(&mut self) -> Result<ContentInfo::SignedData> {
        // Sort digest_algorithms before adding to a DigestAlgorithmIdentifiers object
        // -> See der::asn1::set_of
        self.digest_algorithms.sort();
        // ...

        let signed_data = ContentInfo::SignedData(SignedDataContent {
            version: self.calculate_version(),
            digest_algorithms,
            encap_content_info,
            certificates,
            crls,
            signer_infos,
        });
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
        // TODO NP
        CmsVersion::V0
    }

    // Sign the encapsulated content according to RFC 5652
    // This method may be called
    // https://datatracker.ietf.org/doc/html/rfc5652#section-5.4
    fn sign<'s, S>(&mut self, signer_info: &SignerInfo<'s>, signer: &'s mut S) -> Result<&Self>
        where
            S: Keypair,
            S::VerifyingKey: EncodePublicKey,
            S::VerifyingKey: DynSignatureAlgorithmIdentifier,
            // TODO NP S: Signer<Signature>,
            // TODO NP Signature: SignatureEncoding,
    {
        let digest_algorithm = find_digest_algorithm(&signer_info.digest_algorithm)?;

        if add_signing_time {
            if let Some(signed_attributes) = &signer.signed_attributes {
                if !signed_attributes.iter().any(|attr| attr.oid.cmp(&PKCS9_SIGNING_TIME_OID) == Ordering::Equal) {
                    // TODO NP
                    // Add current time as signing time
                }
            } else {
                // TODO NP
                // Add signed attributes and signing time attribute
            }
        }

        let data = if let Some(signed_attributes) = &signer.signed_attributes {
            // TODO NP
            // If signed attributes are present, we add a PKCS9_MESSAGE_DIGEST_OID
            // attribute. Only the attributes will be signed.
        } else {
            // TODO NP
            // No signed attributes are present.
        };
        Ok(self)
    }
}

fn find_digest_algorithm(digest_algorithm_identifier: &DigestAlgorithmIdentifier) -> Option<Box<dyn DynDigest>> {
    let digest_name = DB.by_oid(digest_algorithm_identifier as &ObjectIdentifier)?;
    match digest_name {
        "id-sha1" => Some(Box::new(sha1::sha1::default())),
        "id-sha256" => Some(Box::new(sha2::Sha256::default())),
        "id-sha384" => Some(Box::new(sha2::Sha384::default())),
        "id-sha512" => Some(Box::new(sha2::Sha512::default())),
        "id-sha224" => Some(Box::new(sha2::Sha224::default())),
        "id-sha-3-224" => Some(Box::new(sha3::Sha3_224::default())),
        "id-sha-3-256" => Some(Box::new(sha3::Sha3_256::default())),
        "id-sha-3-384" => Some(Box::new(sha3::Sha3_384::default())),
        "id-sha-3-512" => Some(Box::new(sha3::Sha3_512::default())),
        "id-shake128" => Some(Box::new(sha3::Shake128::default())),
        "id-shake256" => Some(Box::new(sha3::Shake256::default())),
        // TODO add more hashers
        _ => None,
    }
}