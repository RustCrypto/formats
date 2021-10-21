//! ASN.1 `SET OF` support.

use crate::{
    arrayvec, ArrayVec, Decodable, DecodeValue, Decoder, Encodable, EncodeValue, Encoder,
    ErrorKind, Length, Result, Tag, Tagged,
};

#[cfg(feature = "alloc")]
use {
    crate::{asn1::Any, Error},
    alloc::collections::BTreeSet,
};

/// ASN.1 `SET OF` backed by an array.
///
/// This type implements an append-only `SET OF` type which is stack-based
/// and does not depend on `alloc` support.
// TODO(tarcieri): use `ArrayVec` when/if it's merged into `core`
// See: https://github.com/rust-lang/rfcs/pull/2990
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct SetOf<T, const N: usize>
where
    T: Clone + Ord,
{
    inner: ArrayVec<T, N>,
}

impl<T, const N: usize> SetOf<T, N>
where
    T: Clone + Ord,
{
    /// Create a new [`SetOf`].
    pub fn new() -> Self {
        Self {
            inner: ArrayVec::default(),
        }
    }

    /// Add an element to this [`SetOf`].
    ///
    /// Items MUST be added in lexicographical order according to the `Ord`
    /// impl on `T`.
    pub fn add(&mut self, element: T) -> Result<()> {
        // Ensure set elements are lexicographically ordered
        if let Some(elem) = self.inner.last() {
            if elem >= &element {
                return Err(ErrorKind::Ordering.into());
            }
        }

        self.inner.add(element)
    }

    /// Iterate over the elements of this [`SetOf`].
    pub fn iter(&self) -> SetOfIter<'_, T> {
        SetOfIter {
            inner: self.inner.iter(),
        }
    }
}

impl<T, const N: usize> Default for SetOf<T, N>
where
    T: Clone + Ord,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, T, const N: usize> DecodeValue<'a> for SetOf<T, N>
where
    T: Clone + Decodable<'a> + Ord,
{
    fn decode_value(decoder: &mut Decoder<'a>, length: Length) -> Result<Self> {
        let end_pos = (decoder.position() + length)?;
        let mut result = Self::new();

        while decoder.position() < end_pos {
            result.add(decoder.decode()?)?;
        }

        if decoder.position() != end_pos {
            decoder.error(ErrorKind::Length { tag: Self::TAG });
        }

        Ok(result)
    }
}

impl<'a, T, const N: usize> EncodeValue for SetOf<T, N>
where
    T: 'a + Clone + Decodable<'a> + Encodable + Ord,
{
    fn value_len(&self) -> Result<Length> {
        self.iter()
            .fold(Ok(Length::ZERO), |len, elem| len + elem.encoded_len()?)
    }

    fn encode_value(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        for elem in self.iter() {
            elem.encode(encoder)?;
        }

        Ok(())
    }
}

impl<'a, T, const N: usize> Tagged for SetOf<T, N>
where
    T: Clone + Decodable<'a> + Ord,
{
    const TAG: Tag = Tag::Set;
}

/// Iterator over the elements of an [`SetOf`].
#[derive(Clone, Debug)]
pub struct SetOfIter<'a, T> {
    /// Inner iterator.
    inner: arrayvec::Iter<'a, T>,
}

impl<'a, T> Iterator for SetOfIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        self.inner.next()
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<'a, T> DecodeValue<'a> for BTreeSet<T>
where
    T: Clone + Decodable<'a> + Ord,
{
    fn decode_value(decoder: &mut Decoder<'a>, length: Length) -> Result<Self> {
        let end_pos = (decoder.position() + length)?;
        let mut result = BTreeSet::new();
        let mut last_value = None;

        while decoder.position() < end_pos {
            let value = decoder.decode()?;

            if let Some(last) = last_value.take() {
                if last >= value {
                    return Err(Self::TAG.non_canonical_error());
                }

                result.insert(last);
            }

            last_value = Some(value);
        }

        if decoder.position() != end_pos {
            decoder.error(ErrorKind::Length { tag: Self::TAG });
        }

        if let Some(last) = last_value {
            result.insert(last);
        }

        Ok(result)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<'a, T> EncodeValue for BTreeSet<T>
where
    T: Clone + Decodable<'a> + Encodable + Ord,
{
    fn value_len(&self) -> Result<Length> {
        self.iter()
            .fold(Ok(Length::ZERO), |acc, val| acc? + val.encoded_len()?)
    }

    fn encode_value(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        for value in self.iter() {
            encoder.encode(value)?;
        }

        Ok(())
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<'a, T> TryFrom<Any<'a>> for BTreeSet<T>
where
    T: Clone + Decodable<'a> + Ord,
{
    type Error = Error;

    fn try_from(any: Any<'a>) -> Result<Self> {
        any.decode_into()
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<'a, T> Tagged for BTreeSet<T>
where
    T: Clone + Decodable<'a> + Ord,
{
    const TAG: Tag = Tag::Set;
}
