//! Serialization primitives for slices.

use core::fmt;
use core::marker::PhantomData;

use serde::de::{Error, Visitor};
use serde::{Deserializer, Serializer};

#[cfg(feature = "alloc")]
use serde::Serialize;

#[cfg(feature = "alloc")]
use ::{alloc::vec::Vec, serde::Deserialize};

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
        serializer.serialize_bytes(value.as_ref())
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
        serializer.serialize_bytes(value.as_ref())
    }
}

pub(crate) trait LengthCheck {
    fn length_check(buffer_length: usize, data_length: usize) -> bool;
    fn expecting(
        formatter: &mut fmt::Formatter<'_>,
        data_type: &str,
        data_length: usize,
    ) -> fmt::Result;
}

pub(crate) struct ExactLength;

impl LengthCheck for ExactLength {
    fn length_check(buffer_length: usize, data_length: usize) -> bool {
        buffer_length == data_length
    }
    fn expecting(
        formatter: &mut fmt::Formatter<'_>,
        data_type: &str,
        data_length: usize,
    ) -> fmt::Result {
        write!(formatter, "{} of length {}", data_type, data_length)
    }
}

struct UpperBound;

impl LengthCheck for UpperBound {
    fn length_check(buffer_length: usize, data_length: usize) -> bool {
        buffer_length >= data_length
    }
    fn expecting(
        formatter: &mut fmt::Formatter<'_>,
        data_type: &str,
        data_length: usize,
    ) -> fmt::Result {
        write!(
            formatter,
            "{} with a maximum length of {}",
            data_type, data_length
        )
    }
}

pub(crate) struct StrVisitor<'b, T: LengthCheck>(pub &'b mut [u8], pub PhantomData<T>);

impl<'de, 'b, T: LengthCheck> Visitor<'de> for StrVisitor<'b, T> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        T::expecting(formatter, "a string", self.0.len() * 2)
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if !T::length_check(self.0.len() * 2, v.len()) {
            return Err(Error::invalid_length(v.len(), &self));
        }
        // TODO: Map `base16ct::Error::InvalidLength` to `Error::invalid_length`.
        base16ct::mixed::decode(v, self.0)
            .map(|_| ())
            .map_err(E::custom)
    }
}

pub(crate) struct SliceVisitor<'b, T: LengthCheck>(pub &'b mut [u8], pub PhantomData<T>);

impl<'de, 'b, T: LengthCheck> Visitor<'de> for SliceVisitor<'b, T> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        T::expecting(formatter, "an array", self.0.len())
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        // Workaround for
        // https://github.com/rust-lang/rfcs/blob/b1de05846d9bc5591d753f611ab8ee84a01fa500/text/2094-nll.md#problem-case-3-conditional-control-flow-across-functions
        if T::length_check(self.0.len(), v.len()) {
            let buffer = &mut self.0[..v.len()];
            buffer.copy_from_slice(v);
            return Ok(());
        }

        Err(E::invalid_length(v.len(), &self))
    }

    #[cfg(feature = "alloc")]
    fn visit_byte_buf<E>(self, mut v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: Error,
    {
        // Workaround for
        // https://github.com/rust-lang/rfcs/blob/b1de05846d9bc5591d753f611ab8ee84a01fa500/text/2094-nll.md#problem-case-3-conditional-control-flow-across-functions
        if T::length_check(self.0.len(), v.len()) {
            let buffer = &mut self.0[..v.len()];
            buffer.swap_with_slice(&mut v);
            return Ok(());
        }

        Err(E::invalid_length(v.len(), &self))
    }
}

/// Deserialize from hex when using human-readable formats or binary if the
/// format is binary. Fails if the `buffer` is smaller then the resulting
/// slice.
pub fn deserialize_hex_or_bin<'de, D>(buffer: &mut [u8], deserializer: D) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        deserializer.deserialize_str(StrVisitor::<UpperBound>(buffer, PhantomData))
    } else {
        deserializer.deserialize_byte_buf(SliceVisitor::<UpperBound>(buffer, PhantomData))
    }
}

/// Deserialize from hex when using human-readable formats or binary if the
/// format is binary.
#[cfg(feature = "alloc")]
pub fn deserialize_hex_or_bin_vec<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        struct StrVisitor;

        impl<'de> Visitor<'de> for StrVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                base16ct::mixed::decode_vec(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(StrVisitor)
    } else {
        struct VecVisitor;

        impl<'de> Visitor<'de> for VecVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a bytestring")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(v.into())
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(v)
            }
        }

        deserializer.deserialize_byte_buf(VecVisitor)
    }
}

/// [`HexOrBin`] serializer which uses lower case.
#[cfg(feature = "alloc")]
pub type HexLowerOrBin = HexOrBin<false>;

/// [`HexOrBin`] serializer which uses upper case.
#[cfg(feature = "alloc")]
pub type HexUpperOrBin = HexOrBin<true>;

/// Serializer/deserializer newtype which encodes bytes as either binary or hex.
///
/// Use hexadecimal with human-readable formats, or raw binary with binary formats.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HexOrBin<const UPPERCASE: bool>(pub Vec<u8>);

#[cfg(feature = "alloc")]
impl<const UPPERCASE: bool> AsRef<[u8]> for HexOrBin<UPPERCASE> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(feature = "alloc")]
impl<const UPPERCASE: bool> From<&[u8]> for HexOrBin<UPPERCASE> {
    fn from(bytes: &[u8]) -> HexOrBin<UPPERCASE> {
        Self(bytes.into())
    }
}

#[cfg(feature = "alloc")]
impl<const UPPERCASE: bool> From<Vec<u8>> for HexOrBin<UPPERCASE> {
    fn from(vec: Vec<u8>) -> HexOrBin<UPPERCASE> {
        Self(vec)
    }
}

#[cfg(feature = "alloc")]
impl<const UPPERCASE: bool> From<HexOrBin<UPPERCASE>> for Vec<u8> {
    fn from(vec: HexOrBin<UPPERCASE>) -> Vec<u8> {
        vec.0
    }
}

#[cfg(feature = "alloc")]
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
impl<'de, const UPPERCASE: bool> Deserialize<'de> for HexOrBin<UPPERCASE> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_hex_or_bin_vec(deserializer).map(Self)
    }
}

#[cfg(all(feature = "alloc", feature = "zeroize"))]
impl<const UPPERCASE: bool> Zeroize for HexOrBin<UPPERCASE> {
    fn zeroize(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}
