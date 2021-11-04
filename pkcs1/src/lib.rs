#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/pkcs1/0.3.0-pre"
)]
#![forbid(unsafe_code, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod error;
mod private_key;
mod public_key;
mod traits;
mod version;

pub use der::{self, asn1::UIntBytes};

pub use self::{
    error::{Error, Result},
    private_key::RsaPrivateKey,
    public_key::RsaPublicKey,
    traits::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    version::Version,
};

#[cfg(feature = "alloc")]
pub use crate::{
    private_key::{
        document::RsaPrivateKeyDocument, other_prime_info::OtherPrimeInfo, OtherPrimeInfos,
    },
    public_key::document::RsaPublicKeyDocument,
    traits::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
};

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
pub use der::pem::{self, LineEnding};
