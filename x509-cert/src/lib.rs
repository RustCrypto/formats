#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
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
pub mod time;

pub use certificate::{Certificate, PkiPath, TbsCertificate, Version};
pub use der;
