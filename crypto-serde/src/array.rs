//! TODO
//! crypto-serde implementation for arrays.

use core::fmt;

use serde::de::{Error, Expected, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
        let mut seq = serializer.serialize_tuple(value.as_ref().len())?;

        for byte in value.as_ref() {
            seq.serialize_element(byte)?;
        }

        seq.end()
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
        let mut seq = serializer.serialize_tuple(value.as_ref().len())?;

        for byte in value.as_ref() {
            seq.serialize_element(byte)?;
        }

        seq.end()
    }
}

/// Deserialize the given array from hex when using human-readable formats or
/// binary if the format is binary.
pub fn deserialize_hex_or_bin<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
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

/// [`HexOrBin`] serializer which uses lower case.
pub type HexLowerOrBin<const N: usize> = HexOrBin<N, false>;

/// [`HexOrBin`] serializer which uses upper case.
pub type HexUpperOrBin<const N: usize> = HexOrBin<N, true>;

/// Serializer/deserializer newtype which encodes bytes as either binary or hex.
///
/// Use hexadecimal with human-readable formats, or raw binary with binary formats.
pub struct HexOrBin<const N: usize, const UPPERCASE: bool>(pub [u8; N]);

impl<const N: usize, const UPPERCASE: bool> AsRef<[u8]> for HexOrBin<N, UPPERCASE> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const N: usize, const UPPERCASE: bool> From<&[u8; N]> for HexOrBin<N, UPPERCASE> {
    fn from(bytes: &[u8; N]) -> Self {
        Self(*bytes)
    }
}

impl<const N: usize, const UPPERCASE: bool> From<[u8; N]> for HexOrBin<N, UPPERCASE> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize, const UPPERCASE: bool> From<HexOrBin<N, UPPERCASE>> for [u8; N] {
    fn from(hex_or_bin: HexOrBin<N, UPPERCASE>) -> Self {
        hex_or_bin.0
    }
}

impl<const N: usize, const UPPERCASE: bool> Serialize for HexOrBin<N, UPPERCASE> {
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

impl<'de, const N: usize, const UPPERCASE: bool> Deserialize<'de> for HexOrBin<N, UPPERCASE> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_hex_or_bin(deserializer).map(Self)
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<const N: usize, const UPPERCASE: bool> Zeroize for HexOrBin<N, UPPERCASE> {
    fn zeroize(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}
