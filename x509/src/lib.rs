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

// extern crate alloc and use alloc::collections::BTreeSet as Set are not presently used since
// change in definition of RelativeDistinguishedName
// extern crate alloc;
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod attribute;
mod certificate;
mod crl;
mod extensions;
pub mod extensions_utils;
mod pkix_oids;
mod rdn;
mod time;
mod validity;

pub use crate::{
    attribute::AttributeTypeAndValue, certificate::*, crl::*, extensions::*, pkix_oids::*, rdn::*,
    time::Time, validity::Validity,
};
pub use der::{self, asn1::ObjectIdentifier};
pub use spki::{self, AlgorithmIdentifier, SubjectPublicKeyInfo};
