#![doc = include_str!("../README.md")]

//! # Usage
//! The following example demonstrates how to use an OID as the `parameters`
//! of an [`AlgorithmIdentifier`].
//!
//! Borrow the [`ObjectIdentifier`] first then use [`der::Any::from`] or `.into()`:
//!
//! ```
//! use spki::{AlgorithmIdentifier, ObjectIdentifier, der::Any};
//!
//! let alg_oid = "1.2.840.10045.2.1".parse::<ObjectIdentifier>().unwrap();
//! let params_oid = "1.2.840.10045.3.1.7".parse::<ObjectIdentifier>().unwrap();
//!
//! let alg_id = AlgorithmIdentifier {
//!     oid: alg_oid,
//!     parameters: Some(Any::from(&params_oid))
//! };
//! ```

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/spki/0.5.4"
)]
#![forbid(unsafe_code, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod algorithm;
mod error;
mod spki;
mod traits;

#[cfg(feature = "alloc")]
mod document;

pub use crate::{
    algorithm::AlgorithmIdentifier,
    error::{Error, Result},
    spki::SubjectPublicKeyInfo,
    traits::DecodePublicKey,
};
pub use der::{self, asn1::ObjectIdentifier};

#[cfg(feature = "alloc")]
pub use crate::{document::PublicKeyDocument, traits::EncodePublicKey};
