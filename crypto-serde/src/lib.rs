#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
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

#[cfg(feature = "alloc")]
extern crate alloc;

pub use serde;

use core::fmt;

use serde::de::{Error, Expected, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserializer, Serialize, Serializer};

#[cfg(feature = "alloc")]
use {alloc::vec::Vec, serde::de::Deserialize};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Serialize the given type as lower case hex when using human-readable
/// formats or binary if the format is binary.
pub fn serialize_array_hex_lower_or_bin<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    #[cfg(feature = "alloc")]
    if serializer.is_human_readable() {
        return base16ct::lower::encode_string(value.as_ref()).serialize(serializer);
    }
    #[cfg(not(feature = "alloc"))]
    if serializer.is_human_readable() {
        return Err(S::Error::custom(
            "serializer is human readable, which requires the `alloc` crate feature",
        ));
    }

    let mut seq = serializer.serialize_tuple(value.as_ref().len())?;

    for byte in value.as_ref() {
        seq.serialize_element(byte)?;
    }

    seq.end()
}

/// Serialize the given type as upper case hex when using human-readable
/// formats or binary if the format is binary.
pub fn serialize_array_hex_upper_or_bin<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    #[cfg(feature = "alloc")]
    if serializer.is_human_readable() {
        return base16ct::upper::encode_string(value.as_ref()).serialize(serializer);
    }
    #[cfg(not(feature = "alloc"))]
    if serializer.is_human_readable() {
        return Err(S::Error::custom(
            "serializer is human readable, which requires the `alloc` crate feature",
        ));
    }

    let mut seq = serializer.serialize_tuple(value.as_ref().len())?;

    for byte in value.as_ref() {
        seq.serialize_element(byte)?;
    }

    seq.end()
}

/// Serialize the given type as lower case hex when using human-readable
/// formats or binary if the format is binary.
pub fn serialize_slice_hex_lower_or_bin<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    #[cfg(feature = "alloc")]
    if serializer.is_human_readable() {
        return base16ct::lower::encode_string(value.as_ref()).serialize(serializer);
    }
    #[cfg(not(feature = "alloc"))]
    if serializer.is_human_readable() {
        return Err(S::Error::custom(
            "serializer is human readable, which requires the `alloc` crate feature",
        ));
    }

    value.as_ref().serialize(serializer)
}

/// Serialize the given type as upper case hex when using human-readable
/// formats or binary if the format is binary.
pub fn serialize_slice_hex_upper_or_bin<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    #[cfg(feature = "alloc")]
    if serializer.is_human_readable() {
        return base16ct::upper::encode_string(value.as_ref()).serialize(serializer);
    }
    #[cfg(not(feature = "alloc"))]
    if serializer.is_human_readable() {
        return Err(S::Error::custom(
            "serializer is human readable, which requires the `alloc` crate feature",
        ));
    }

    value.as_ref().serialize(serializer)
}

/// Deserialize the given array from hex when using human-readable formats or
/// binary if the format is binary.
pub fn deserialize_array_hex_or_bin<'de, D, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let hex = <&str>::deserialize(deserializer)?;

        if hex.len() != N * 2 {
            struct LenError<const N: usize>;

            impl<const N: usize> Expected for LenError<N> {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(formatter, "a string of length {}", N * 2)
                }
            }

            return Err(Error::invalid_length(hex.len(), &LenError::<N>));
        }

        let mut buffer = [0; N];
        base16ct::mixed::decode(hex, &mut buffer).map_err(D::Error::custom)?;

        Ok(buffer)
    } else {
        struct ArrayVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for ArrayVisitor<N> {
            type Value = [u8; N];

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an array of length {}", N)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut buffer = [0; N];

                for (index, byte) in buffer.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(index, &self))?;
                }

                Ok(buffer)
            }
        }

        deserializer.deserialize_tuple(N, ArrayVisitor)
    }
}

/// Deserialize the given slice from hex when using human-readable formats or
/// binary if the format is binary.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn deserialize_slice_hex_or_bin<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        base16ct::mixed::decode_vec(<&str>::deserialize(deserializer)?).map_err(D::Error::custom)
    } else {
        Vec::deserialize(deserializer)
    }
}

/// [`HexOrBin`] serializer which uses lower case.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub type HexLowerOrBin = HexOrBin<false>;

/// [`HexOrBin`] serializer which uses upper case.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub type HexUpperOrBin = HexOrBin<true>;

/// Serializer/deserializer newtype which encodes bytes as either binary or hex.
///
/// Use hexadecimal with human-readable formats, or raw binary with binary formats.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub struct HexOrBin<const UPPERCASE: bool>(pub Vec<u8>);

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<const UPPERCASE: bool> AsRef<[u8]> for HexOrBin<UPPERCASE> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<const UPPERCASE: bool> From<&[u8]> for HexOrBin<UPPERCASE> {
    fn from(bytes: &[u8]) -> HexOrBin<UPPERCASE> {
        Self(bytes.into())
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<const UPPERCASE: bool> From<Vec<u8>> for HexOrBin<UPPERCASE> {
    fn from(vec: Vec<u8>) -> HexOrBin<UPPERCASE> {
        Self(vec)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<const UPPERCASE: bool> From<HexOrBin<UPPERCASE>> for Vec<u8> {
    fn from(vec: HexOrBin<UPPERCASE>) -> Vec<u8> {
        vec.0
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<const UPPERCASE: bool> Serialize for HexOrBin<UPPERCASE> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if UPPERCASE {
            serialize_slice_hex_upper_or_bin(self, serializer)
        } else {
            serialize_slice_hex_lower_or_bin(self, serializer)
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<'de, const UPPERCASE: bool> Deserialize<'de> for HexOrBin<UPPERCASE> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_slice_hex_or_bin(deserializer).map(Self)
    }
}

#[cfg(all(feature = "alloc", feature = "zeroize"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "alloc", feature = "zeroize"))))]
impl<const UPPERCASE: bool> Zeroize for HexOrBin<UPPERCASE> {
    fn zeroize(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}
