//! The [`Message`] trait simplifies writing decoders/encoders which map ASN.1
//! `SEQUENCE`s to Rust structs.

use crate::{Decodable, Encodable, EncodeValue, Encoder, Length, Result, Tag, Tagged};

/// Messages encoded as an ASN.1 `SEQUENCE`.
///
/// The "message" pattern this trait provides is not an ASN.1 concept,
/// but rather a pattern for writing ASN.1 DER decoders and encoders which
/// map ASN.1 `SEQUENCE` types to Rust structs with a minimum of code.
///
/// Types which impl this trait receive blanket impls for the [`Decodable`],
/// [`Encodable`], and [`Tagged`] traits.
pub trait Message<'a>: Decodable<'a> {
    /// Call the provided function with a slice of [`Encodable`] trait objects
    /// representing the fields of this message.
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
    M: Message<'a>,
{
    fn value_len(&self) -> Result<Length> {
        self.fields(|fields| encoded_len_inner(fields))
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

impl<'a, M> Tagged for M
where
    M: Message<'a>,
{
    const TAG: Tag = Tag::Sequence;
}

/// Obtain the length of an ASN.1 message `SEQUENCE` consisting of the given
/// [`Encodable`] fields when serialized as ASN.1 DER, including the header
/// (i.e. tag and length)
pub(super) fn encoded_len_inner(fields: &[&dyn Encodable]) -> Result<Length> {
    fields.iter().fold(Ok(Length::ZERO), |sum, encodable| {
        sum + encodable.encoded_len()?
    })
}
