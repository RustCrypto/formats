//! ASN.1 `SET OF` support.

use crate::{
    ArrayVec, Decodable, DecodeValue, Decoder, Encodable, EncodeValue, Encoder, ErrorKind, Length,
    Result, Tag, Tagged,
};

#[cfg(feature = "alloc")]
use {
    crate::{asn1::Any, Error},
    alloc::collections::{btree_set, BTreeSet},
    core::convert::TryFrom,
};

/// ASN.1 `SET OF` denotes a collection of zero or more occurrences of a
/// given type.
///
/// When encoded as DER, `SET OF` is lexicographically ordered. To implement
/// that requirement, types `T` which are elements of [`SetOf`] MUST provide
/// an impl of `Ord` which ensures that the corresponding DER encodings of
/// a given type are ordered.
pub trait SetOf<'a, 'b, T: 'b>: Decodable<'a>
where
    T: Clone + Decodable<'a> + Ord,
{
    /// Iterator over the elements of the set.
    ///
    /// The iterator type MUST maintain the invariant that messages are
    /// lexicographically ordered.
    ///
    /// See toplevel documentation about `Ord` trait requirements for
    /// more information.
    type Iter: Iterator<Item = &'b T>;

    /// Iterate over the elements of the set.
    fn elements(&'b self) -> Self::Iter;
}

/// ASN.1 `SET OF` backed by an array.
///
/// This type implements an append-only `SET OF` type which is stack-based
/// and does not depend on `alloc` support.
// TODO(tarcieri): use `ArrayVec` when/if it's merged into `core`
// See: https://github.com/rust-lang/rfcs/pull/2990
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct SetOfArray<T, const N: usize>
where
    T: Clone + Ord,
{
    inner: ArrayVec<T, N>,
}

impl<T, const N: usize> SetOfArray<T, N>
where
    T: Clone + Ord,
{
    /// Create a new [`SetOfArray`].
    pub fn new() -> Self {
        Self {
            inner: ArrayVec::default(),
        }
    }

    /// Add an element to this [`SetOfArray`].
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

    /// Iterate over the elements of this [`SetOfArray`].
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        SetOfArrayIter::new(self.inner.elements())
    }
}

impl<T, const N: usize> Default for SetOfArray<T, N>
where
    T: Clone + Ord,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, T, const N: usize> DecodeValue<'a> for SetOfArray<T, N>
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

impl<'a, T, const N: usize> EncodeValue for SetOfArray<T, N>
where
    T: 'a + Clone + Decodable<'a> + Encodable + Ord,
{
    fn value_len(&self) -> Result<Length> {
        self.elements()
            .fold(Ok(Length::ZERO), |len, elem| len + elem.encoded_len()?)
    }

    fn encode_value(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        for elem in self.elements() {
            elem.encode(encoder)?;
        }

        Ok(())
    }
}

impl<'a, T, const N: usize> Tagged for SetOfArray<T, N>
where
    T: Clone + Decodable<'a> + Ord,
{
    const TAG: Tag = Tag::Set;
}

impl<'a, 'b, T: 'a + 'b, const N: usize> SetOf<'a, 'b, T> for SetOfArray<T, N>
where
    T: Clone + Decodable<'a> + Ord,
{
    type Iter = SetOfArrayIter<'b, T>;

    fn elements(&'b self) -> Self::Iter {
        SetOfArrayIter::new(self.inner.elements())
    }
}

/// Iterator over the elements of an [`SetOfArray`].
pub struct SetOfArrayIter<'a, T> {
    /// Decoder which iterates over the elements of the message.
    elements: &'a [Option<T>],

    /// Position within the iterator.
    position: usize,
}

impl<'a, T> SetOfArrayIter<'a, T> {
    pub(crate) fn new(elements: &'a [Option<T>]) -> Self {
        Self {
            elements,
            position: 0,
        }
    }
}

impl<'a, T> Iterator for SetOfArrayIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        if let Some(Some(res)) = self.elements.get(self.position) {
            self.position += 1;
            Some(res)
        } else {
            None
        }
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
impl<'a, 'b, T: 'b> SetOf<'a, 'b, T> for BTreeSet<T>
where
    T: Clone + Decodable<'a> + Ord,
{
    type Iter = btree_set::Iter<'b, T>;

    fn elements(&'b self) -> Self::Iter {
        self.iter()
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
