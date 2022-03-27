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

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod array;
pub mod slice;

pub use serde;

use serde::Serializer;

#[cfg(not(feature = "alloc"))]
use serde::ser::Error as _;

#[cfg(feature = "alloc")]
use serde::Serialize;

fn serialize_hex<S, T, const UPPERCASE: bool>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    #[cfg(feature = "alloc")]
    if UPPERCASE {
        return base16ct::upper::encode_string(value.as_ref()).serialize(serializer);
    } else {
        return base16ct::lower::encode_string(value.as_ref()).serialize(serializer);
    }
    #[cfg(not(feature = "alloc"))]
    {
        let _ = value;
        let _ = serializer;
        return Err(S::Error::custom(
            "serializer is human readable, which requires the `alloc` crate feature",
        ));
    }
}
