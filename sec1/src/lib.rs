//! Pure Rust implementation of [SEC1: Elliptic Curve Cryptography] encoding
//! formats including ASN.1 DER-serialized private keys as well as the
//! `Elliptic-Curve-Point-to-Octet-String` encoding.
//!
//! # Minimum Supported Rust Version
//! This crate requires **Rust 1.51** at a minimum.
//!
//! [SEC1: Elliptic Curve Cryptography]: https://www.secg.org/sec1-v2.pdf
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/sec1/0.0.0"
)]
#![forbid(unsafe_code, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod point;

mod error;
mod parameters;
mod private_key;
mod traits;

pub use der;

pub use self::{
    error::{Error, Result},
    parameters::EcParameters,
    point::EncodedPoint,
    private_key::EcPrivateKey,
    traits::FromEcPrivateKey,
};

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
pub use pem_rfc7468::LineEnding;

#[cfg(feature = "alloc")]
pub use crate::{private_key::document::EcPrivateKeyDocument, traits::ToEcPrivateKey};

#[cfg(feature = "pem")]
use pem_rfc7468 as pem;
