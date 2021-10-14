//! ASN.1 `SEQUENCE` support.

pub(super) mod iter;

use self::iter::SequenceIter;
use crate::{
    asn1::Any, ByteSlice, Decodable, DecodeValue, Decoder, Encodable, EncodeValue, Encoder, Error,
    ErrorKind, Length, Result, Tag, Tagged,
};
use core::convert::TryFrom;

/// ASN.1 `SEQUENCE` type.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Sequence<'a> {
    /// Inner value
    inner: ByteSlice<'a>,
}

impl<'a> Sequence<'a> {
    /// Create a new [`Sequence`] from a slice.
    pub(crate) fn new(slice: &'a [u8]) -> Result<Self> {
        ByteSlice::new(slice)
            .map(|inner| Self { inner })
            .map_err(|_| ErrorKind::Length { tag: Self::TAG }.into())
    }

    /// Borrow the inner byte sequence.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.inner.as_bytes()
    }

    /// Decode values nested within a sequence, creating a new [`Decoder`] for
    /// the data contained in the sequence's body and passing it to the provided
    /// [`FnOnce`].
    pub fn decode_nested<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Decoder<'a>) -> Result<T>,
    {
        let mut seq_decoder = Decoder::new(self.as_bytes());
        let result = f(&mut seq_decoder)?;
        seq_decoder.finish(result)
    }

    /// Iterate over the values in a heterogenously typed sequence.
    pub fn iter<T: Decodable<'a>>(&self) -> SequenceIter<'a, T> {
        SequenceIter::new(Decoder::new(self.as_bytes()))
    }
}

impl AsRef<[u8]> for Sequence<'_> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a> DecodeValue<'a> for Sequence<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, length: Length) -> Result<Self> {
        Self::new(ByteSlice::decode_value(decoder, length)?.as_bytes())
    }
}

impl<'a> EncodeValue for Sequence<'a> {
    fn value_len(&self) -> Result<Length> {
        self.inner.value_len()
    }

    fn encode_value(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        self.inner.encode_value(encoder)
    }
}

impl<'a> From<Sequence<'a>> for Any<'a> {
    fn from(seq: Sequence<'a>) -> Any<'a> {
        Any::from_tag_and_value(Tag::Sequence, seq.inner)
    }
}

impl<'a> TryFrom<Any<'a>> for Sequence<'a> {
    type Error = Error;

    fn try_from(any: Any<'a>) -> Result<Self> {
        any.decode_into()
    }
}

impl<'a> Tagged for Sequence<'a> {
    const TAG: Tag = Tag::Sequence;
}

impl<'a, T, const N: usize> DecodeValue<'a> for [T; N]
where
    // TODO(tarcieri): remove `Default` bounds with `array::try_from_fn`
    T: Decodable<'a> + Default,
{
    fn decode_value(decoder: &mut Decoder<'a>, length: Length) -> Result<Self> {
        let end_pos = (decoder.position() + length)?;
        let mut result = [(); N].map(|_| Default::default());

        for elem in &mut result {
            *elem = decoder.decode()?;

            if decoder.position() > end_pos {
                decoder.error(ErrorKind::Length { tag: Self::TAG });
            }
        }

        if decoder.position() != end_pos {
            decoder.error(ErrorKind::Length { tag: Self::TAG });
        }

        Ok(result)
    }
}

impl<'a, T, const N: usize> EncodeValue for [T; N]
where
    T: Encodable,
{
    fn value_len(&self) -> Result<Length> {
        self.iter()
            .fold(Ok(Length::ZERO), |len, elem| len + elem.encoded_len()?)
    }

    fn encode_value(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        for elem in self {
            elem.encode(encoder)?;
        }

        Ok(())
    }
}

impl<'a, T, const N: usize> Tagged for [T; N]
where
    T: Decodable<'a>,
{
    const TAG: Tag = Tag::Sequence;
}
