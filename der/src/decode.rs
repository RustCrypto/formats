//! Trait definition for [`Decode`].

use crate::{Decoder, FixedTag, Header, Result};

/// Decoding trait.
///
/// This trait provides the core abstraction upon which all decoding operations
/// are based.
///
/// # Blanket impl for `TryFrom<Any>`
///
/// In almost all cases you do not need to impl this trait yourself, but rather
/// can instead impl `TryFrom<Any<'a>, Error = Error>` and receive a blanket
/// impl of this trait.
pub trait Decode<'a>: Sized {
    /// Attempt to decode this message using the provided decoder.
    fn decode(decoder: &mut Decoder<'a>) -> Result<Self>;

    /// Parse `Self` from the provided DER-encoded byte slice.
    fn from_der(bytes: &'a [u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes)?;
        let result = Self::decode(&mut decoder)?;
        decoder.finish(result)
    }
}

impl<'a, T> Decode<'a> for T
where
    T: DecodeValue<'a> + FixedTag,
{
    fn decode(decoder: &mut Decoder<'a>) -> Result<T> {
        let header = Header::decode(decoder)?;
        header.tag.assert_eq(T::TAG)?;
        T::decode_value(decoder, header)
    }
}

/// Marker trait for data structures that can be decoded from DER without
/// borrowing any data from the decoder.
///
/// This is primarily useful for trait bounds on functions which require that
/// no data is borrowed from the decoder, for example a PEM decoder which needs
/// to first decode data from Base64.
///
/// This trait is inspired by the [`DeserializeOwned` trait from `serde`](https://docs.rs/serde/latest/serde/de/trait.DeserializeOwned.html).
pub trait DecodeOwned: for<'a> Decode<'a> {}

impl<T> DecodeOwned for T where T: for<'a> Decode<'a> {}

/// Decode the value part of a Tag-Length-Value encoded field, sans the [`Tag`]
/// and [`Length`].
pub trait DecodeValue<'a>: Sized {
    /// Attempt to decode this message using the provided [`Decoder`].
    fn decode_value(decoder: &mut Decoder<'a>, header: Header) -> Result<Self>;
}
