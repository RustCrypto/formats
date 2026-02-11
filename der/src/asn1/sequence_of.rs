//! ASN.1 `SEQUENCE OF` support.

use crate::{
    Decode, DecodeValue, DerOrd, Encode, EncodeValue, Error, FixedTag, Header, Length, Reader, Tag,
    ValueOrd, Writer, ord::iter_cmp,
};
use core::cmp::Ordering;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

impl<T: Encode> EncodeValue for [T] {
    fn value_len(&self) -> Result<Length, Error> {
        self.iter()
            .try_fold(Length::ZERO, |len, elem| len + elem.encoded_len()?)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), Error> {
        for elem in self {
            elem.encode(writer)?;
        }

        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl<'a, T> DecodeValue<'a> for Vec<T>
where
    T: Decode<'a>,
{
    type Error = T::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> Result<Self, Self::Error> {
        let mut sequence_of = Vec::<T>::new();

        while !reader.is_finished() {
            sequence_of.push(T::decode(reader)?);
        }

        Ok(sequence_of)
    }
}

#[cfg(feature = "alloc")]
impl<T> EncodeValue for Vec<T>
where
    T: Encode,
{
    fn value_len(&self) -> Result<Length, Error> {
        self.iter()
            .try_fold(Length::ZERO, |len, elem| len + elem.encoded_len()?)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), Error> {
        self.as_slice().encode_value(writer)
    }
}

#[cfg(feature = "alloc")]
impl<T> FixedTag for Vec<T> {
    const TAG: Tag = Tag::Sequence;
}

#[cfg(feature = "alloc")]
impl<T> ValueOrd for Vec<T>
where
    T: DerOrd,
{
    fn value_cmp(&self, other: &Self) -> Result<Ordering, Error> {
        iter_cmp(self.iter(), other.iter())
    }
}
