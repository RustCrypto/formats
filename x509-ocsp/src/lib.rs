#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
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
mod cert_id;
mod cert_status;
mod request;
mod responder_id;
mod response;
mod time;

pub mod ext;

pub use basic::{BasicOcspResponse, ResponseData, SingleResponse};
pub use cert_id::CertId;
pub use cert_status::{CertStatus, RevokedInfo, UnknownInfo};
pub use request::{OcspRequest, Request, Signature, TbsRequest};
pub use responder_id::ResponderId;
pub use response::{AsResponseBytes, OcspNoCheck, OcspResponse, OcspResponseStatus, ResponseBytes};
pub use time::OcspGeneralizedTime;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "builder")]
pub mod builder;

use der::Enumerated;

/// OCSP `Version` as defined in [RFC 6960 Section 4.1.1].
///
/// ```text
/// Version ::= INTEGER { v1(0) }
/// ```
///
/// [RFC 6960 Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.1.1
#[derive(Clone, Debug, Default, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Version {
    /// Version 1 (default)
    #[default]
    V1 = 0,
}
