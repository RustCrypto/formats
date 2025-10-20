#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::alloc_instead_of_core,
    clippy::mod_module_files,
    clippy::std_instead_of_alloc,
    clippy::std_instead_of_core,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[macro_use]
mod macros;

pub mod anchor;
pub mod attr;
pub mod certificate;
pub mod crl;
pub mod ext;
pub mod name;
pub mod request;
pub mod serial_number;
pub mod time;

#[cfg(feature = "builder")]
pub mod builder;

pub use certificate::{Certificate, PkiPath, TbsCertificate, Version};
pub use der;
pub use spki;
pub use spki::{
    AlgorithmIdentifierOwned as AlgorithmIdentifier,
    SubjectPublicKeyInfoOwned as SubjectPublicKeyInfo,
};
