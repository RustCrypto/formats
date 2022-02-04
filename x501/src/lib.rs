#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/x501/0.1.0-pre.0"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

extern crate alloc;

pub mod attr;
pub mod name;
