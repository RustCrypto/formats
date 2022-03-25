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

/// Decode the value part of a Tag-Length-Value encoded field, sans the [`Tag`]
/// and [`Length`].
pub trait DecodeValue<'a>: Sized {
    /// Attempt to decode this message using the provided [`Decoder`].
    fn decode_value(decoder: &mut Decoder<'a>, header: Header) -> Result<Self>;
}
