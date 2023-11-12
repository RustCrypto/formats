#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

extern crate alloc;

mod basic;
mod request;
mod response;
mod time;

pub mod ext;

pub use basic::{
    BasicOcspResponse, CertId, CertStatus, KeyHash, ResponderId, ResponseData, RevokedInfo,
    SingleResponse, UnknownInfo, Version,
};
pub use request::{OcspRequest, Request, Signature, TbsRequest};
pub use response::{AsResponseBytes, OcspNoCheck, OcspResponse, OcspResponseStatus, ResponseBytes};
pub use time::OcspGeneralizedTime;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "builder")]
pub mod builder;
