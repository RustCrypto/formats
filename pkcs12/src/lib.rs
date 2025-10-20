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

extern crate alloc;

pub mod pbe_params;
pub mod pfx;
pub mod safe_bag;

#[cfg(feature = "kdf")]
pub mod kdf;

mod authenticated_safe;
mod bag_type;
mod cert_type;
mod crl_type;
mod digest_info;
mod mac_data;

pub use crate::{
    authenticated_safe::AuthenticatedSafe,
    bag_type::BagType,
    cert_type::{CertBag, CertTypes},
    crl_type::{CrlBag, CrlTypes},
    digest_info::DigestInfo,
    mac_data::MacData,
    pfx::Pfx,
    safe_bag::SafeBag,
};
pub use cms;

use const_oid::ObjectIdentifier;

// pbe oids
/// `pbeWithSHAAnd128BitRC4` Object Identifier (OID).
pub const PKCS_12_PBE_WITH_SHAAND128_BIT_RC4: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.1");

/// `pbeWithSHAAnd128BitRC4` Object Identifier (OID).
pub const PKCS_12_PBE_WITH_SHAAND40_BIT_RC4: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.2");

/// `pbeWithSHAAnd128BitRC4` Object Identifier (OID).
pub const PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.3");

/// `pbeWithSHAAnd128BitRC4` Object Identifier (OID).
pub const PKCS_12_PBE_WITH_SHAAND2_KEY_TRIPLE_DES_CBC: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.4");

/// `pbeWithSHAAnd128BitRC4` Object Identifier (OID).
pub const PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.5");

/// `pbeWithSHAAnd128BitRC4` Object Identifier (OID).
pub const PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.6");

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

// todo: return the friendly name if present? (minimally, defer until BMPString support is available)
// todo: support separate mac and encryption passwords?
// todo: add decryption support
// todo: add more encryption tests
// todo: add a builder
// todo: add RC2 support
