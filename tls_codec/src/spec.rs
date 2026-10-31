//! Round-trip proof obligations for the codec traits.
//!
//! `cfg(hax)`-only; compiled out of every ordinary build.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{
    DeserializeBytes, Error, SerializeBytes, TlsByteVecU8, TlsByteVecU16, TlsByteVecU24,
    TlsByteVecU32, TlsVarInt, U24, VLBytes,
};

// Trait-level round trip: composes through generic types.

/// Serialize `value`, append `rest`, deserialize: the value and the remainder, or `Ok(None)` if
/// decoding fails. `Err` only when serializing fails.
///
/// A free function, not a method of [`RoundTrip`]: an impl may override a method, not a free
/// function, so [`RoundTrip::round_trip`] constrains the codecs themselves.
pub fn encode_decode_rest<T: SerializeBytes + DeserializeBytes>(
    value: &T,
    rest: &[u8],
) -> Result<Option<(T, Vec<u8>)>, Error> {
    let mut bytes = value.tls_serialize_bytes()?;
    bytes.extend_from_slice(rest);
    match T::tls_deserialize_bytes(&bytes) {
        Ok((out, remainder)) => Ok(Some((out, remainder.to_vec()))),
        Err(_) => Ok(None),
    }
}

/// Types whose serialization round-trips, stated once per type (and per generic
/// instance, from the round trip of its parameters).
#[hax_lib::attributes]
pub trait RoundTrip: SerializeBytes + DeserializeBytes + PartialEq + Sized {
    /// Lemma method (empty body): [`encode_decode_rest`] gives back the value and exactly `rest`.
    /// Its `Err` is reserved for serialization failure; a decoding failure is `Ok(None)`.
    /// The bound keeps the concatenation within `usize`.
    #[hax_lib::requires(rest.len() <= usize::MAX - self.tls_serialized_len())]
    #[hax_lib::ensures(|_| {
        let r = encode_decode_rest(self, rest);
        r.is_err()
            || r.is_ok_and(|o| o.is_some_and(|(out, remainder)| out == *self
                && remainder.as_slice() == rest))
    })]
    #[allow(unused_variables)]
    fn round_trip(&self, rest: &[u8]) {}
}

/// Types whose encoding is never empty (at least one byte): needed by `Vec<T>`'s round trip,
/// whose deserializer reads an empty content as an empty vector.
///
/// A subtrait of [`RoundTrip`], not of `Size`: a bound `T: NonEmpty` then carries the one
/// dictionary of `T`'s codecs, so the fact speaks about the very serializer `Vec<T>` calls. The
/// post is on the serializer's output, not on `tls_serialized_len`: the size is unspecified on
/// overflow, the output is not.
#[hax_lib::attributes]
pub trait NonEmpty: RoundTrip {
    /// Lemma method (empty body): when serialization succeeds, the output has at least one byte.
    #[hax_lib::ensures(|_| {
        let r = self.tls_serialize_bytes();
        r.is_err() || r.is_ok_and(|b| b.len() > 0)
    })]
    #[allow(unused_variables)]
    fn nonempty(&self) {}
}

// Implementations: the empty lemma, for every type of the round trips below.

impl RoundTrip for u8 {}
impl RoundTrip for u16 {}
impl RoundTrip for u32 {}
impl RoundTrip for u64 {}
impl RoundTrip for U24 {}
impl RoundTrip for [u8; 4] {}
impl<T: RoundTrip> RoundTrip for Option<T> {}
impl RoundTrip for TlsVarInt {}
impl RoundTrip for VLBytes {}
impl RoundTrip for TlsByteVecU8 {}
impl RoundTrip for TlsByteVecU16 {}
impl RoundTrip for TlsByteVecU24 {}
impl RoundTrip for TlsByteVecU32 {}
impl RoundTrip for String {}
impl<T: NonEmpty> RoundTrip for Vec<T> {}

impl NonEmpty for u8 {}
impl NonEmpty for u16 {}
impl NonEmpty for u32 {}
impl NonEmpty for u64 {}
impl NonEmpty for U24 {}
impl NonEmpty for [u8; 4] {}
impl<T: RoundTrip> NonEmpty for Option<T> {}
impl NonEmpty for TlsVarInt {}
impl NonEmpty for VLBytes {}
impl NonEmpty for TlsByteVecU8 {}
impl NonEmpty for TlsByteVecU16 {}
impl NonEmpty for TlsByteVecU24 {}
impl NonEmpty for TlsByteVecU32 {}
impl NonEmpty for String {}
impl<T: NonEmpty> NonEmpty for Vec<T> {}

// Fixed-size encodings: `encode_decode` always succeeds.

/// Serialize, then deserialize: always succeeds, and is the identity on values.
#[hax_lib::ensures(|res| res.is_ok_and(|(out, remaining)| out == *value && remaining == 0))]
pub fn u8_encode_decode(value: &u8) -> Result<(u8, usize), Error> {
    let bytes = value.tls_serialize_bytes()?;
    let (out, remainder) = u8::tls_deserialize_bytes(&bytes)?;
    Ok((out, remainder.len()))
}

/// Deserialize, then serialize: the identity on the bytes consumed.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, consumed)| bytes.get(..consumed) == Some(out.as_slice())))]
pub fn u8_decode_encode(bytes: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let (value, remainder) = u8::tls_deserialize_bytes(bytes)?;
    let consumed = bytes.len() - remainder.len();
    let out = value.tls_serialize_bytes()?;
    Ok((out, consumed))
}

/// Serialize, then deserialize: always succeeds, and is the identity on values.
#[hax_lib::ensures(|res| res.is_ok_and(|(out, remaining)| out == *value && remaining == 0))]
pub fn u16_encode_decode(value: &u16) -> Result<(u16, usize), Error> {
    let bytes = value.tls_serialize_bytes()?;
    let (out, remainder) = u16::tls_deserialize_bytes(&bytes)?;
    Ok((out, remainder.len()))
}

/// Deserialize, then serialize: the identity on the bytes consumed.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, consumed)| bytes.get(..consumed) == Some(out.as_slice())))]
pub fn u16_decode_encode(bytes: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let (value, remainder) = u16::tls_deserialize_bytes(bytes)?;
    let consumed = bytes.len() - remainder.len();
    let out = value.tls_serialize_bytes()?;
    Ok((out, consumed))
}

/// Serialize, then deserialize: always succeeds, and is the identity on values.
#[hax_lib::ensures(|res| res.is_ok_and(|(out, remaining)| out == *value && remaining == 0))]
pub fn u32_encode_decode(value: &u32) -> Result<(u32, usize), Error> {
    let bytes = value.tls_serialize_bytes()?;
    let (out, remainder) = u32::tls_deserialize_bytes(&bytes)?;
    Ok((out, remainder.len()))
}

/// Deserialize, then serialize: the identity on the bytes consumed.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, consumed)| bytes.get(..consumed) == Some(out.as_slice())))]
pub fn u32_decode_encode(bytes: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let (value, remainder) = u32::tls_deserialize_bytes(bytes)?;
    let consumed = bytes.len() - remainder.len();
    let out = value.tls_serialize_bytes()?;
    Ok((out, consumed))
}

/// Serialize, then deserialize: always succeeds, and is the identity on values.
#[hax_lib::ensures(|res| res.is_ok_and(|(out, remaining)| out == *value && remaining == 0))]
pub fn u64_encode_decode(value: &u64) -> Result<(u64, usize), Error> {
    let bytes = value.tls_serialize_bytes()?;
    let (out, remainder) = u64::tls_deserialize_bytes(&bytes)?;
    Ok((out, remainder.len()))
}

/// Deserialize, then serialize: the identity on the bytes consumed.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, consumed)| bytes.get(..consumed) == Some(out.as_slice())))]
pub fn u64_decode_encode(bytes: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let (value, remainder) = u64::tls_deserialize_bytes(bytes)?;
    let consumed = bytes.len() - remainder.len();
    let out = value.tls_serialize_bytes()?;
    Ok((out, consumed))
}

/// Serialize, then deserialize: always succeeds, and is the identity on values.
#[hax_lib::ensures(|res| res.is_ok_and(|(out, remaining)| out == *value && remaining == 0))]
pub fn u24_encode_decode(value: &U24) -> Result<(U24, usize), Error> {
    let bytes = value.tls_serialize_bytes()?;
    let (out, remainder) = U24::tls_deserialize_bytes(&bytes)?;
    Ok((out, remainder.len()))
}

/// Deserialize, then serialize: the identity on the bytes consumed.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, consumed)| bytes.get(..consumed) == Some(out.as_slice())))]
pub fn u24_decode_encode(bytes: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let (value, remainder) = U24::tls_deserialize_bytes(bytes)?;
    let consumed = bytes.len() - remainder.len();
    let out = value.tls_serialize_bytes()?;
    Ok((out, consumed))
}

/// Serialize, then deserialize: always succeeds, and is the identity on values.
#[hax_lib::ensures(|res| res.is_ok_and(|(out, remaining)| out == *value && remaining == 0))]
pub fn array4_encode_decode(value: &[u8; 4]) -> Result<([u8; 4], usize), Error> {
    let bytes = value.tls_serialize_bytes()?;
    let (out, remainder) = <[u8; 4]>::tls_deserialize_bytes(&bytes)?;
    Ok((out, remainder.len()))
}

/// Deserialize, then serialize: the identity on the bytes consumed.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, consumed)| bytes.get(..consumed) == Some(out.as_slice())))]
pub fn array4_decode_encode(bytes: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let (value, remainder) = <[u8; 4]>::tls_deserialize_bytes(bytes)?;
    let consumed = bytes.len() - remainder.len();
    let out = value.tls_serialize_bytes()?;
    Ok((out, consumed))
}

/// Serialize, then deserialize: always succeeds, and is the identity on values.
#[hax_lib::ensures(|res| res.is_ok_and(|(out, remaining)| out == *value && remaining == 0))]
pub fn option_u16_encode_decode(value: &Option<u16>) -> Result<(Option<u16>, usize), Error> {
    let bytes = value.tls_serialize_bytes()?;
    let (out, remainder) = <Option<u16>>::tls_deserialize_bytes(&bytes)?;
    Ok((out, remainder.len()))
}

/// Deserialize, then serialize: the identity on the bytes consumed.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, consumed)| bytes.get(..consumed) == Some(out.as_slice())))]
pub fn option_u16_decode_encode(bytes: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let (value, remainder) = <Option<u16>>::tls_deserialize_bytes(bytes)?;
    let consumed = bytes.len() - remainder.len();
    let out = value.tls_serialize_bytes()?;
    Ok((out, consumed))
}

// Variable-length integer: total on its valid range.

/// Serialize, then deserialize: always succeeds, and is the identity on values.
#[hax_lib::requires(value.value() <= TlsVarInt::MAX)]
#[hax_lib::ensures(|res| res.is_ok_and(|(out, remaining)| out == *value && remaining == 0))]
pub fn varint_encode_decode(value: &TlsVarInt) -> Result<(TlsVarInt, usize), Error> {
    let bytes = value.tls_serialize_bytes()?;
    let (out, remainder) = TlsVarInt::tls_deserialize_bytes(&bytes)?;
    Ok((out, remainder.len()))
}

/// Deserialize, then serialize: the identity on the bytes consumed.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, consumed)| bytes.get(..consumed) == Some(out.as_slice())))]
pub fn varint_decode_encode(bytes: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let (value, remainder) = TlsVarInt::tls_deserialize_bytes(bytes)?;
    let consumed = bytes.len() - remainder.len();
    let out = value.tls_serialize_bytes()?;
    Ok((out, consumed))
}

// Variable-length vectors and strings.

/// Serialize, then deserialize: the identity on values.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, remaining)| out == *value && remaining == 0))]
pub fn vlbytes_encode_decode(value: &VLBytes) -> Result<(VLBytes, usize), Error> {
    let bytes = value.tls_serialize_bytes()?;
    let (out, remainder) = VLBytes::tls_deserialize_bytes(&bytes)?;
    Ok((out, remainder.len()))
}

/// Deserialize, then serialize: the identity on the bytes consumed.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, consumed)| bytes.get(..consumed) == Some(out.as_slice())))]
pub fn vlbytes_decode_encode(bytes: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let (value, remainder) = VLBytes::tls_deserialize_bytes(bytes)?;
    let consumed = bytes.len() - remainder.len();
    let out = value.tls_serialize_bytes()?;
    Ok((out, consumed))
}

/// Serialize, then deserialize: the identity on values.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, remaining)| out == *value && remaining == 0))]
pub fn byte_vec_u8_encode_decode(value: &TlsByteVecU8) -> Result<(TlsByteVecU8, usize), Error> {
    let bytes = value.tls_serialize_bytes()?;
    let (out, remainder) = TlsByteVecU8::tls_deserialize_bytes(&bytes)?;
    Ok((out, remainder.len()))
}

/// Deserialize, then serialize: the identity on the bytes consumed.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, consumed)| bytes.get(..consumed) == Some(out.as_slice())))]
pub fn byte_vec_u8_decode_encode(bytes: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let (value, remainder) = TlsByteVecU8::tls_deserialize_bytes(bytes)?;
    let consumed = bytes.len() - remainder.len();
    let out = value.tls_serialize_bytes()?;
    Ok((out, consumed))
}

/// Serialize, then deserialize: the identity on values.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, remaining)| out == *value && remaining == 0))]
pub fn byte_vec_u16_encode_decode(value: &TlsByteVecU16) -> Result<(TlsByteVecU16, usize), Error> {
    let bytes = value.tls_serialize_bytes()?;
    let (out, remainder) = TlsByteVecU16::tls_deserialize_bytes(&bytes)?;
    Ok((out, remainder.len()))
}

/// Deserialize, then serialize: the identity on the bytes consumed.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, consumed)| bytes.get(..consumed) == Some(out.as_slice())))]
pub fn byte_vec_u16_decode_encode(bytes: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let (value, remainder) = TlsByteVecU16::tls_deserialize_bytes(bytes)?;
    let consumed = bytes.len() - remainder.len();
    let out = value.tls_serialize_bytes()?;
    Ok((out, consumed))
}

/// Serialize, then deserialize: the identity on values.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, remaining)| out == *value && remaining == 0))]
pub fn byte_vec_u24_encode_decode(value: &TlsByteVecU24) -> Result<(TlsByteVecU24, usize), Error> {
    let bytes = value.tls_serialize_bytes()?;
    let (out, remainder) = TlsByteVecU24::tls_deserialize_bytes(&bytes)?;
    Ok((out, remainder.len()))
}

/// Deserialize, then serialize: the identity on the bytes consumed.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, consumed)| bytes.get(..consumed) == Some(out.as_slice())))]
pub fn byte_vec_u24_decode_encode(bytes: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let (value, remainder) = TlsByteVecU24::tls_deserialize_bytes(bytes)?;
    let consumed = bytes.len() - remainder.len();
    let out = value.tls_serialize_bytes()?;
    Ok((out, consumed))
}

/// Serialize, then deserialize: the identity on values.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, remaining)| out == *value && remaining == 0))]
pub fn byte_vec_u32_encode_decode(value: &TlsByteVecU32) -> Result<(TlsByteVecU32, usize), Error> {
    let bytes = value.tls_serialize_bytes()?;
    let (out, remainder) = TlsByteVecU32::tls_deserialize_bytes(&bytes)?;
    Ok((out, remainder.len()))
}

/// Deserialize, then serialize: the identity on the bytes consumed.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, consumed)| bytes.get(..consumed) == Some(out.as_slice())))]
pub fn byte_vec_u32_decode_encode(bytes: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let (value, remainder) = TlsByteVecU32::tls_deserialize_bytes(bytes)?;
    let consumed = bytes.len() - remainder.len();
    let out = value.tls_serialize_bytes()?;
    Ok((out, consumed))
}

/// Serialize, then deserialize: the identity on values.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, remaining)| out == *value && remaining == 0))]
pub fn vec_u16_encode_decode(value: &Vec<u16>) -> Result<(Vec<u16>, usize), Error> {
    let bytes = value.tls_serialize_bytes()?;
    let (out, remainder) = <Vec<u16>>::tls_deserialize_bytes(&bytes)?;
    Ok((out, remainder.len()))
}

/// Deserialize, then serialize: the identity on the bytes consumed.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, consumed)| bytes.get(..consumed) == Some(out.as_slice())))]
pub fn vec_u16_decode_encode(bytes: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let (value, remainder) = <Vec<u16>>::tls_deserialize_bytes(bytes)?;
    let consumed = bytes.len() - remainder.len();
    let out = value.tls_serialize_bytes()?;
    Ok((out, consumed))
}

/// Serialize, then deserialize: the identity on values.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, remaining)| out == *value && remaining == 0))]
pub fn string_encode_decode(value: &String) -> Result<(String, usize), Error> {
    let bytes = value.tls_serialize_bytes()?;
    let (out, remainder) = String::tls_deserialize_bytes(&bytes)?;
    Ok((out, remainder.len()))
}

/// Deserialize, then serialize: the identity on the bytes consumed.
#[hax_lib::ensures(|res| res.is_err()
    || res.is_ok_and(|(out, consumed)| bytes.get(..consumed) == Some(out.as_slice())))]
pub fn string_decode_encode(bytes: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    let (value, remainder) = String::tls_deserialize_bytes(bytes)?;
    let consumed = bytes.len() - remainder.len();
    let out = value.tls_serialize_bytes()?;
    Ok((out, consumed))
}

// The `std` (`Read` / `Write`) path.

/// Vocabulary of the `Serialize` / `Deserialize` contracts and the lemma traits of the `std`
/// path. The four observers are ghost functions: opaque, defined in the Lean model from the laws
/// of lawful writers / readers (`Write.Lawful`, `Read.Lawful`).
#[cfg(feature = "std")]
pub mod io {
    use alloc::vec::Vec;
    use std::io::{Read, Write};

    use crate::{Deserialize, Error, Serialize, SerializeBytes, VLBytes};

    /// Ghost: the bytes written to `writer` so far (opaque).
    #[allow(unused_variables)]
    pub fn sink<W: Write>(writer: &W) -> Vec<u8> {
        unimplemented!("ghost")
    }

    /// Ghost: the bytes `reader` still yields (opaque).
    #[allow(unused_variables)]
    pub fn stream<R: Read>(reader: &R) -> Vec<u8> {
        unimplemented!("ghost")
    }

    /// Ghost: `after` is `before` after reading some of its bytes (opaque).
    #[allow(unused_variables)]
    pub fn advanced<R: Read>(before: &R, after: &R) -> bool {
        unimplemented!("ghost")
    }

    /// `whole` is `prefix` followed by `suffix` (opaque, for the Lean `++`).
    pub fn is_concat(prefix: &[u8], suffix: &[u8], whole: &[u8]) -> bool {
        whole.len() >= prefix.len()
            && whole.len() - prefix.len() == suffix.len()
            && &whole[..prefix.len()] == prefix
            && &whole[prefix.len()..] == suffix
    }

    /// The encoding of `value`: its serializer run on an empty vector. A free function, so that
    /// the contracts speak about `T`'s serializer, not about an overridable method.
    pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        value.tls_serialize(&mut bytes)?;
        Ok(bytes)
    }

    /// `T`'s deserializer run on `reader`: the result and the reader after it.
    pub fn decode_std<T: Deserialize, R: Read>(mut reader: R) -> (Result<T, Error>, R) {
        let res = T::tls_deserialize(&mut reader);
        (res, reader)
    }

    /// Types whose `std` serialization round-trips, for every lawful reader.
    #[hax_lib::attributes]
    pub trait RoundTripStd: Serialize + Deserialize + PartialEq + Sized {
        /// Lemma method (empty body): on a reader yielding the encoding of `self` then `rest`,
        /// the deserializer gives back `self` and leaves exactly `rest`.
        #[hax_lib::requires(encode(self).is_ok_and(|bytes| is_concat(&bytes, rest, &stream(&reader))))]
        #[hax_lib::ensures(|_| {
            let (res, after) = decode_std::<Self, R>(reader);
            res.is_ok_and(|out| out == *self) && stream(&after).as_slice() == rest
        })]
        #[allow(unused_variables)]
        fn round_trip_std<R: Read>(&self, reader: R, rest: &[u8]) {}

        /// Lemma method (empty body): `tls_deserialize_exact` of the encoding gives back `self`.
        #[hax_lib::ensures(|_| {
            let e = encode(self);
            e.is_err() || e.is_ok_and(|bytes| {
                Self::tls_deserialize_exact(bytes.as_slice()).is_ok_and(|out| out == *self)
            })
        })]
        fn round_trip_exact(&self) {}
    }

    /// Types whose `std` encoding is never empty (bound of `Vec<T>`'s round trip).
    #[hax_lib::attributes]
    pub trait NonEmptyStd: RoundTripStd {
        /// Lemma method (empty body): when encoding succeeds, it has at least one byte.
        #[hax_lib::ensures(|_| {
            let e = encode(self);
            e.is_err() || e.is_ok_and(|bytes| bytes.len() > 0)
        })]
        fn nonempty_std(&self) {}
    }

    /// Types whose `std` and bytes serializers agree.
    #[hax_lib::attributes]
    pub trait SameBytes: Serialize + SerializeBytes {
        /// Lemma method (empty body): both serializers fail, or both give the same bytes.
        #[hax_lib::ensures(|_| {
            let e = encode(self);
            let b = self.tls_serialize_bytes();
            (e.is_err() && b.is_err())
                || e.is_ok_and(|e| b.is_ok_and(|b| e.as_slice() == b.as_slice()))
        })]
        fn same_bytes(&self) {}
    }

    impl RoundTripStd for u8 {}
    impl RoundTripStd for VLBytes {}
    impl<T: NonEmptyStd + core::fmt::Debug> RoundTripStd for Vec<T> {}

    impl NonEmptyStd for u8 {}
    impl NonEmptyStd for VLBytes {}
    impl<T: NonEmptyStd + core::fmt::Debug> NonEmptyStd for Vec<T> {}

    impl SameBytes for u8 {}
    impl SameBytes for VLBytes {}
}
