#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

extern crate alloc;

pub use serde;

use alloc::vec::Vec;
use serde::{
    de::{self, Error},
    ser, Deserialize, Serialize,
};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// [`HexOrBin`] serializer which uses lower case.
pub type HexLowerOrBin = HexOrBin<false>;

/// [`HexOrBin`] serializer which uses upper case.
pub type HexUpperOrBin = HexOrBin<true>;

/// Serializer/deserializer newtype which encodes as binary when using
/// binary-oriented formats or hexadecimal when using human-readable formats.
pub struct HexOrBin<const UPPERCASE: bool>(pub Vec<u8>);

impl<const UPPERCASE: bool> AsRef<[u8]> for HexOrBin<UPPERCASE> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const UPPERCASE: bool> From<&[u8]> for HexOrBin<UPPERCASE> {
    fn from(bytes: &[u8]) -> HexOrBin<UPPERCASE> {
        Self(bytes.into())
    }
}

impl<const UPPERCASE: bool> From<Vec<u8>> for HexOrBin<UPPERCASE> {
    fn from(vec: Vec<u8>) -> HexOrBin<UPPERCASE> {
        Self(vec)
    }
}

impl<const UPPERCASE: bool> From<HexOrBin<UPPERCASE>> for Vec<u8> {
    fn from(vec: HexOrBin<UPPERCASE>) -> Vec<u8> {
        vec.0
    }
}

impl<const UPPERCASE: bool> Serialize for HexOrBin<UPPERCASE> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            if UPPERCASE {
                base16ct::upper::encode_string(self.as_ref())
            } else {
                base16ct::lower::encode_string(self.as_ref())
            }
            .serialize(serializer)
        } else {
            self.as_ref().serialize(serializer)
        }
    }
}

impl<'de, const UPPERCASE: bool> Deserialize<'de> for HexOrBin<UPPERCASE> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            base16ct::mixed::decode_vec(<&str>::deserialize(deserializer)?)
                .map_err(D::Error::custom)
        } else {
            Vec::deserialize(deserializer)
        }
        .map(Self)
    }
}

#[cfg(feature = "zeroize")]
impl<const UPPERCASE: bool> Zeroize for HexOrBin<UPPERCASE> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
