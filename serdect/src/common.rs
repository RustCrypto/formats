use core::fmt;
use core::marker::PhantomData;

use serde::{
    de::{Error, Visitor},
    Serializer,
};

#[cfg(feature = "alloc")]
use ::{alloc::vec::Vec, serde::Serialize};

#[cfg(not(feature = "alloc"))]
use serde::ser::Error as SerError;

pub(crate) fn serialize_hex<S, T, const UPPERCASE: bool>(
    value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error>
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

pub(crate) fn serialize_hex_lower_or_bin<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    if serializer.is_human_readable() {
        serialize_hex::<_, _, false>(value, serializer)
    } else {
        serializer.serialize_bytes(value.as_ref())
    }
}

/// Serialize the given type as upper case hex when using human-readable
/// formats or binary if the format is binary.
pub(crate) fn serialize_hex_upper_or_bin<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    if serializer.is_human_readable() {
        serialize_hex::<_, _, true>(value, serializer)
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

pub(crate) struct StrIntoBufVisitor<'b, T: LengthCheck>(pub &'b mut [u8], pub PhantomData<T>);

impl<'de, 'b, T: LengthCheck> Visitor<'de> for StrIntoBufVisitor<'b, T> {
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

#[cfg(feature = "alloc")]
pub(crate) struct StrIntoVecVisitor;

#[cfg(feature = "alloc")]
impl<'de> Visitor<'de> for StrIntoVecVisitor {
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

#[cfg(feature = "alloc")]
pub(crate) struct VecVisitor;

#[cfg(feature = "alloc")]
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
