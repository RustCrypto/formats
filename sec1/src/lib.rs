#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/sec1/0.2.0-pre"
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

#[cfg(feature = "pkcs8")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
pub mod pkcs8;

pub use der;

pub use self::{
    error::{Error, Result},
    parameters::EcParameters,
    point::EncodedPoint,
    private_key::EcPrivateKey,
    traits::DecodeEcPrivateKey,
};

pub use generic_array::typenum::consts;

#[cfg(feature = "alloc")]
pub use crate::{private_key::document::EcPrivateKeyDocument, traits::EncodeEcPrivateKey};

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
pub use der::pem::{self, LineEnding};
