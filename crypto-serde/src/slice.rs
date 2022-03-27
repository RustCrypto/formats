//! TODO
//! crypto-serde implementation for slices.

use serde::{Serialize, Serializer};

#[cfg(feature = "alloc")]
use ::{
    alloc::vec::Vec,
    serde::de::Error,
    serde::{Deserialize, Deserializer},
};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Serialize the given type as lower case hex when using human-readable
/// formats or binary if the format is binary.
pub fn serialize_hex_lower_or_bin<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    if serializer.is_human_readable() {
        crate::serialize_hex::<_, _, false>(value, serializer)
    } else {
        value.as_ref().serialize(serializer)
    }
}

/// Serialize the given type as upper case hex when using human-readable
/// formats or binary if the format is binary.
pub fn serialize_hex_upper_or_bin<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    if serializer.is_human_readable() {
        crate::serialize_hex::<_, _, true>(value, serializer)
    } else {
        value.as_ref().serialize(serializer)
    }
}

/// Deserialize the given slice from hex when using human-readable formats or
/// binary if the format is binary.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn deserialize_hex_or_bin<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
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
            serialize_hex_upper_or_bin(self, serializer)
        } else {
            serialize_hex_lower_or_bin(self, serializer)
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
        deserialize_hex_or_bin(deserializer).map(Self)
    }
}

#[cfg(all(feature = "alloc", feature = "zeroize"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "alloc", feature = "zeroize"))))]
impl<const UPPERCASE: bool> Zeroize for HexOrBin<UPPERCASE> {
    fn zeroize(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}
