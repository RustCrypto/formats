//! The [`Sequence`] trait simplifies writing decoders/encoders which map ASN.1
//! `SEQUENCE`s to Rust structs.

use crate::{
    ByteSlice, Decodable, DecodeValue, Decoder, Encodable, EncodeValue, Encoder, FixedTag, Header,
    Length, Result, Tag,
};

/// ASN.1 `SEQUENCE` trait.
///
/// Types which impl this trait receive blanket impls for the [`Decodable`],
/// [`Encodable`], and [`FixedTag`] traits.
pub trait Sequence<'a>: Decodable<'a> {
    /// Call the provided function with a slice of [`Encodable`] trait objects
    /// representing the fields of this `SEQUENCE`.
    ///
    /// This method uses a callback because structs with fields which aren't
    /// directly [`Encodable`] may need to construct temporary values from
    /// their fields prior to encoding.
    fn fields<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> Result<T>;
}

impl<'a, M> EncodeValue for M
where
    M: Sequence<'a>,
{
    fn value_len(&self) -> Result<Length> {
        self.fields(|fields| {
            fields
                .iter()
                .fold(Ok(Length::ZERO), |len, field| len + field.encoded_len()?)
        })
    }

    fn encode_value(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        self.fields(|fields| {
            for &field in fields {
                field.encode(encoder)?;
            }

            Ok(())
        })
    }
}

impl<'a, M> FixedTag for M
where
    M: Sequence<'a>,
{
    const TAG: Tag = Tag::Sequence;
}

/// The [`SequenceRef`] type provides raw access to the octets which comprise a
/// DER-encoded `SEQUENCE`.
pub struct SequenceRef<'a> {
    /// Body of the `SEQUENCE`.
    body: ByteSlice<'a>,

    /// Offset location in the outer document where this `SEQUENCE` begins.
    offset: Length,
}

impl<'a> SequenceRef<'a> {
    /// Decode the body of this sequence.
    pub fn decode_body<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Decoder<'a>) -> Result<T>,
    {
        let mut nested_decoder = Decoder::new_with_offset(self.body, self.offset);
        let result = f(&mut nested_decoder)?;
        nested_decoder.finish(result)
    }
}

impl<'a> DecodeValue<'a> for SequenceRef<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, header: Header) -> Result<Self> {
        let offset = decoder.position();
        let body = ByteSlice::decode_value(decoder, header)?;
        Ok(Self { body, offset })
    }
}

impl EncodeValue for SequenceRef<'_> {
    fn value_len(&self) -> Result<Length> {
        Ok(self.body.len())
    }

    fn encode_value(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        self.body.encode_value(encoder)
    }
}

impl<'a> FixedTag for SequenceRef<'a> {
    const TAG: Tag = Tag::Sequence;
}
