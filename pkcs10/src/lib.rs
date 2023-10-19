#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
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
    unused_lifetimes,
    unused_qualifications
)]

//! ## About this crate
//! This library provides generalized PKCS#10 support designed to work with a
//! number of different algorithms. It supports `no_std` platforms including
//! ones without a heap (albeit with reduced functionality).
//!
//! It supports decoding/encoding the following types:
//!
//! - [`CertificationRequest`]: the PKCS#10 certification request.
//! - [`CertificationRequestInfo`]: the value being signed
//!   Optionally also includes public key data for asymmetric keys.
//! - [`SubjectPublicKeyInfo`]: algorithm identifier and data representing a public key
//!   (re-exported from the [`spki`] crate)
//! - [`Name`]: the X.501 Name
//! - [`DistinguishedName`]: the X.501 DistinguishedName
//! - [`Attributes`]: the X.501 Attributes and associated definitions
//!
//! When the `pem` feature is enabled, it also supports decoding/encoding
//! documents from "PEM encoding" format as defined in RFC 7468.
//!
//! [RFC 2986]: https://datatracker.ietf.org/doc/html/rfc2986

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[macro_use]
mod macros;

mod attribute;
mod certification_request;
mod certification_request_info;
mod error;
mod name;
mod version;

pub use crate::{
    certification_request::CertificationRequest,
    certification_request_info::CertificationRequestInfo,
    error::Error,
    name::{DistinguishedName, Name},
    version::Version,
};
pub use der::{self, asn1::ObjectIdentifier, oid::AssociatedOid};
pub use spki::{
    self, AlgorithmIdentifierRef, DecodePublicKey, SubjectPublicKeyInfo, SubjectPublicKeyInfoRef,
};

#[cfg(feature = "alloc")]
pub use {
    der::{Document, SecretDocument},
    spki::EncodePublicKey,
};

#[cfg(feature = "pem")]
pub use der::pem::LineEnding;
