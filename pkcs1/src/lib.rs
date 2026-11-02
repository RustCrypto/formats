#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

//! ## Usage
//!
//! ### Borrowed DER decoding
//!
//! [`RsaPrivateKeyRef`] and [`RsaPublicKeyRef`] borrow their integer data from the input.
//! Import [`der::Decode`] to use `from_der`:
//!
//! ```rust
//! use pkcs1::{RsaPrivateKeyRef, der::Decode};
//!
//! # let der = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/examples/rsa2048-priv.der"));
//! let key = RsaPrivateKeyRef::from_der(der)?;
//! # Ok::<(), pkcs1::Error>(())
//! ```
//!
//! Here, `der` is a byte slice containing a PKCS#1 DER-encoded private key.
//! `RsaPrivateKeyRef::try_from(der)` also decodes DER when `der` has type `&[u8]`.
//! Both methods are available without enabling any features.
//!
//! ### Owned DER decoding and encoding
//!
//! Enable the `alloc` feature to use [`RsaPrivateKeyOwned`] and [`RsaPublicKeyOwned`].
//! These types own their integer data and implement [`DecodeRsaPrivateKey`] and
//! [`DecodeRsaPublicKey`], respectively:
//!
//! ```rust
//! # #[cfg(feature = "alloc")]
//! # {
//! use pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, RsaPrivateKeyOwned};
//!
//! # let der = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/examples/rsa2048-priv.der"));
//! let key = RsaPrivateKeyOwned::from_pkcs1_der(der)?;
//! let document = key.to_pkcs1_der()?;
//! assert_eq!(document.as_bytes(), der);
//! # }
//! # Ok::<(), pkcs1::Error>(())
//! ```
//!
//! [`EncodeRsaPrivateKey`] and [`EncodeRsaPublicKey`] support both borrowed and owned keys.
//! The decoding traits require owned results; use [`der::Decode`] for the borrowed types as shown
//! above. RSA implementations can also implement these traits for their own key types.
//!
//! ### PEM decoding and encoding
//!
//! Enable the `pem` feature (which also enables `alloc`) to use `from_pkcs1_pem` and
//! `to_pkcs1_pem` with the PEM labels shown above:
//!
//! ```rust
//! # #[cfg(feature = "pem")]
//! # {
//! use pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding, RsaPrivateKeyOwned};
//!
//! # let pem = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/examples/rsa2048-priv.pem"));
//! let key = RsaPrivateKeyOwned::from_pkcs1_pem(pem)?;
//! let encoded = key.to_pkcs1_pem(LineEnding::LF)?;
//! assert_eq!(encoded.as_str(), pem);
//! # }
//! # Ok::<(), pkcs1::Error>(())
//! ```
//!
//! Here, `pem` is a string containing a PEM-encoded RSA private key.
//!
//! For public  keys, use `RsaPublicKeyOwned` with `DecodeRsaPublicKey` and `EncodeRsaPublicKey`
//! (the method names are the same).

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod error;
mod params;
mod private_key;
mod public_key;
mod traits;
mod version;

pub use der::{
    self,
    asn1::{ObjectIdentifier, UintRef},
};

pub use crate::{
    error::{Error, Result},
    params::{RsaOaepParams, RsaOaepParamsRef, RsaPssParams, RsaPssParamsRef, TrailerField},
    private_key::{RsaPrivateKey, RsaPrivateKeyRef},
    public_key::{RsaPublicKey, RsaPublicKeyRef},
    traits::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    version::Version,
};

#[cfg(feature = "alloc")]
pub use crate::{
    params::{RsaOaepParamsOwned, RsaPssParamsOwned},
    private_key::{OtherPrimeInfos, RsaPrivateKeyOwned, other_prime_info::OtherPrimeInfo},
    public_key::RsaPublicKeyOwned,
    traits::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
};

#[cfg(feature = "pem")]
pub use der::pem::{self, LineEnding};

/// `rsaEncryption` Object Identifier (OID)
pub const ALGORITHM_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// `AlgorithmIdentifier` for RSA.
pub const ALGORITHM_ID: spki::AlgorithmIdentifierRef<'static> = spki::AlgorithmIdentifierRef {
    oid: ALGORITHM_OID,
    parameters: Some(der::asn1::AnyRef::NULL),
};
