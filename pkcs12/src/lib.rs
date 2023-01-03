#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_qualifications
)]

//! TODO: PKCS#12 crate
//!
//!
// #[cfg(feature = "pem")]

use spki::ObjectIdentifier;
extern crate alloc;

pub mod authenticated_safe;
pub mod bag_type;
pub mod cert_bag_content;
pub mod cert_type;
pub mod content_info;
pub mod digest_info;
pub mod mac_data;
pub mod pfx;
pub mod safe_bag;
// bag types

/// `pkcs-12 keyBag` Object Identifier (OID).
pub const PKCS_12_KEY_BAG_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.1");

/// `pkcs-12 pkcs8ShroudedKeyBag` Object Identifier (OID).
pub const PKCS_12_PKCS8_KEY_BAG_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.2");

/// `pkcs-12 certBag` Object Identifier (OID).
pub const PKCS_12_CERT_BAG_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.3");

/// `pkcs-12 crlBag` Object Identifier (OID).
pub const PKCS_12_CRL_BAG_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.4");

/// `pkcs-12 secretBag` Object Identifier (OID).
pub const PKCS_12_SECRET_BAG_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.5");

/// `pkcs-12 safeContentsBag` Object Identifier (OID).
pub const PKCS_12_SAFE_CONTENTS_BAG_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.6");

// cert types

/// `pkcs-9 x509Certificate for pkcs-12` Object Identifier (OID).
pub const PKCS_12_X509_CERT_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.22.1");

/// `pkcs-9 sdsiCertificate for pkcs-12` Object Identifier (OID).
pub const PKCS_12_SDSI_CERT_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.22.2");
