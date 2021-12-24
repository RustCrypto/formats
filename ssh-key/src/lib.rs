#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/ssh-key/0.1.0"
)]
#![doc = include_str!("../README.md")]

//! ## Usage
//!
//! ### OpenSSH Public Keys
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(feature = "std")]
//! # {
//! use ssh_key::PublicKey;
//!
//! let encoded_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti foo@bar.com";
//! let key = PublicKey::from_openssh(encoded_key)?;
//!
//! // Key attributes
//! assert_eq!(key.algorithm(), ssh_key::Algorithm::Ed25519);
//! assert_eq!(key.comment, "foo@bar.com");
//!
//! // Key data
//! if let Some(ed25519_key) = key.key_data.ed25519() {
//!     assert_eq!(
//!         ed25519_key.as_ref(),
//!         [
//!             0xb3, 0x3e, 0xae, 0xf3, 0x7e, 0xa2, 0xdf, 0x7c, 0xaa, 0x1, 0xd, 0xef, 0xde, 0xa3,
//!             0x4e, 0x24, 0x1f, 0x65, 0xf1, 0xb5, 0x29, 0xa4, 0xf4, 0x3e, 0xd1, 0x43, 0x27, 0xf5,
//!             0xc5, 0x4a, 0xab, 0x62
//!         ].as_ref()
//!     );
//! }
//! # }
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod private;
pub mod public;

mod algorithm;
mod base64;
mod error;

#[cfg(feature = "alloc")]
mod mpint;

pub use crate::{
    algorithm::{Algorithm, CipherAlg, EcdsaCurve, KdfAlg, KdfOptions},
    error::{Error, Result},
    private::PrivateKey,
    public::PublicKey,
};

#[cfg(feature = "alloc")]
pub use crate::mpint::MPInt;

#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
pub use sec1;
