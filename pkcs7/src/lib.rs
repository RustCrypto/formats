#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

mod certificate_choices;
mod cms_version;
mod content_info;
mod content_type;
mod revocation_info_choices;
mod signer_info;

pub use crate::{content_info::ContentInfo, content_type::ContentType};

pub mod data_content;
pub mod encapsulated_content_info;
pub mod encrypted_data_content;
pub mod enveloped_data_content;
pub mod signed_data_content;

use der::asn1::ObjectIdentifier;

/// `pkcs-7` Object Identifier (OID).
pub const PKCS_7_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7");

/// `pkcs-7 data` Object Identifier (OID).
pub const PKCS_7_DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

/// `pkcs-7 signedData` Object Identifier (OID).
pub const PKCS_7_SIGNED_DATA_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// `pkcs-7 signedData` Object Identifier (OID).
pub const PKCS_7_ENVELOPED_DATA_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");

/// `pkcs-7 signedAndEnvelopedData` Object Identifier (OID).
pub const PKCS_7_SIGNED_AND_ENVELOPED_DATA_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.4");

/// `pkcs-7 digestedData` Object Identifier (OID).
pub const PKCS_7_DIGESTED_DATA_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.5");

/// `pkcs-7 encryptedData` Object Identifier (OID).
pub const PKCS_7_ENCRYPTED_DATA_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.6");
