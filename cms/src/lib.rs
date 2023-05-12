#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

//! # `p7b` support
//!
//! This crate can be used to convert an X.509 certificate into a certs-only
//! [`signed_data::SignedData`] message, a.k.a `.p7b` file.
//!
//! Use a [`TryFrom`] conversion between [`cert::x509::Certificate`] and
//! [`content_info::ContentInfo`] to generate the data structures, then use
//! `to_der` to serialize it.

extern crate alloc;

// TODO NM revert: #[cfg(feature = "std")]
extern crate std;

use const_oid::ObjectIdentifier;

pub mod attr;
pub mod authenticated_data;
pub mod builder;
pub mod cert;
pub mod compressed_data;
pub mod content_info;
pub mod digested_data;
pub mod encrypted_data;
pub mod enveloped_data;
pub mod revocation;
pub mod signed_data;


// TODO NM define these OIDs somewhere else?

/// From RFC 5652. https://datatracker.ietf.org/doc/html/rfc5652#section-12.1

/// `id-messageDigest` Object identifier (OID).
pub const PKCS9_CONTENT_TYPE_OID:  ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

/// `id-messageDigest` Object identifier (OID).
pub const PKCS9_MESSAGE_DIGEST_OID:  ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// `id-signingTime` Object identifier (OID).
pub const PKCS9_SIGNING_TIME_OID:  ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
