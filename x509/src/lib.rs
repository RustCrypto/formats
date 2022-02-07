#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/x509/0.0.1"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod certificate;
pub mod certificate_document;
pub mod certificate_traits;
pub mod extensions_utils;
pub mod general_name;
pub mod pkix_extensions;
pub mod pkix_oids;
pub mod trust_anchor_format;

pub use crate::{
    certificate::*, extensions_utils::*, general_name::*, pkix_extensions::*, pkix_oids::*,
};
pub use der::{self, asn1::ObjectIdentifier};
pub use spki::{self, AlgorithmIdentifier, SubjectPublicKeyInfo};
