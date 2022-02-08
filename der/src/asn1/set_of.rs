//! ASN.1 `SET OF` support.

use crate::{
    arrayvec, ord::iter_cmp, ArrayVec, Decodable, DecodeValue, Decoder, DerOrd, Encodable,
    EncodeValue, Encoder, ErrorKind, FixedTag, Header, Length, Result, Tag, ValueOrd,
};
use core::cmp::Ordering;

#[cfg(feature = "alloc")]
use {crate::Error, alloc::vec::Vec, core::slice};

/// ASN.1 `SET OF` backed by an array.
///
/// This type implements an append-only `SET OF` type which is stack-based
/// and does not depend on `alloc` support.
// TODO(tarcieri): use `ArrayVec` when/if it's merged into `core`
// See: https://github.com/rust-lang/rfcs/pull/2990
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct SetOf<T, const N: usize>
where
    T: Clone + DerOrd,
{
    inner: ArrayVec<T, N>,
}

impl<T, const N: usize> SetOf<T, N>
where
    T: Clone + DerOrd,
{
    /// Create a new [`SetOf`].
    pub fn new() -> Self {
        Self {
            inner: ArrayVec::default(),
        }
    }

    /// Add an element to this [`SetOf`].
    ///
    /// Items MUST be added in lexicographical order according to the
    /// [`DerOrd`] impl on `T`.
    pub fn add(&mut self, new_elem: T) -> Result<()> {
        // Ensure set elements are lexicographically ordered
        if let Some(last_elem) = self.inner.last() {
            if new_elem.der_cmp(last_elem)? != Ordering::Greater {
                return Err(ErrorKind::SetOrdering.into());
            }
        }

        self.inner.add(new_elem)
    }

    /// Get the nth element from this [`SetOf`].
    pub fn get(&self, index: usize) -> Option<&T> {
        self.inner.get(index)
    }

    /// Iterate over the elements of this [`SetOf`].
    pub fn iter(&self) -> SetOfIter<'_, T> {
        SetOfIter {
            inner: self.inner.iter(),
        }
    }

    /// Is this [`SetOf`] empty?
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Number of elements in this [`SetOf`].
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<T, const N: usize> Default for SetOf<T, N>
where
    T: Clone + DerOrd,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, T, const N: usize> DecodeValue<'a> for SetOf<T, N>
where
    T: Clone + Decodable<'a> + DerOrd,
{
    fn decode_value(decoder: &mut Decoder<'a>, header: Header) -> Result<Self> {
        let end_pos = (decoder.position() + header.length)?;
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
    T: 'a + Clone + Decodable<'a> + Encodable + DerOrd,
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

impl<'a, T, const N: usize> FixedTag for SetOf<T, N>
where
    T: Clone + Decodable<'a> + DerOrd,
{
    const TAG: Tag = Tag::Set;
}

impl<T, const N: usize> ValueOrd for SetOf<T, N>
where
    T: Clone + DerOrd,
{
    fn value_cmp(&self, other: &Self) -> Result<Ordering> {
        iter_cmp(self.iter(), other.iter())
    }
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

impl<'a, T> ExactSizeIterator for SetOfIter<'a, T> {}

/// ASN.1 `SET OF` backed by a [`Vec`].
///
/// This type implements an append-only `SET OF` type which is heap-backed
/// and depends on `alloc` support.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct SetOfVec<T>
where
    T: Clone + DerOrd,
{
    inner: Vec<T>,
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<T> SetOfVec<T>
where
    T: Clone + DerOrd,
{
    /// Create a new [`SetOfVec`].
    pub fn new() -> Self {
        Self {
            inner: Vec::default(),
        }
    }

    /// Add an element to this [`SetOfVec`].
    ///
    /// Items MUST be added in lexicographical order according to the
    /// [`DerOrd`] impl on `T`.
    pub fn add(&mut self, new_elem: T) -> Result<()> {
        // Ensure set elements are lexicographically ordered
        if let Some(last_elem) = self.inner.last() {
            if new_elem.der_cmp(last_elem)? != Ordering::Greater {
                return Err(ErrorKind::SetOrdering.into());
            }
        }

        self.inner.push(new_elem);
        Ok(())
    }

    /// Get the nth element from this [`SetOfVec`].
    pub fn get(&self, index: usize) -> Option<&T> {
        self.inner.get(index)
    }

    /// Convert this [`SetOfVec`] into the inner [`Vec`].
    pub fn into_vec(self) -> Vec<T> {
        self.inner
    }

    /// Iterate over the elements of this [`SetOfVec`].
    pub fn iter(&self) -> slice::Iter<'_, T> {
        self.inner.iter()
    }

    /// Is this [`SetOfVec`] empty?
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Number of elements in this [`SetOfVec`].
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<T> AsRef<[T]> for SetOfVec<T>
where
    T: Clone + DerOrd,
{
    fn as_ref(&self) -> &[T] {
        &self.inner
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<'a, T> DecodeValue<'a> for SetOfVec<T>
where
    T: Clone + Decodable<'a> + DerOrd,
{
    fn decode_value(decoder: &mut Decoder<'a>, header: Header) -> Result<Self> {
        let end_pos = (decoder.position() + header.length)?;
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

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<'a, T> EncodeValue for SetOfVec<T>
where
    T: 'a + Clone + Decodable<'a> + Encodable + DerOrd,
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

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<T> FixedTag for SetOfVec<T>
where
    T: Clone + DerOrd,
{
    const TAG: Tag = Tag::Set;
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<T> From<SetOfVec<T>> for Vec<T>
where
    T: Clone + DerOrd,
{
    fn from(set: SetOfVec<T>) -> Vec<T> {
        set.into_vec()
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<T> TryFrom<Vec<T>> for SetOfVec<T>
where
    T: Clone + DerOrd,
{
    type Error = Error;

    fn try_from(mut vec: Vec<T>) -> Result<SetOfVec<T>> {
        if vec.len() > 1 {
            // Use `Ordering::Less` as a placeholder in the event of comparison failure
            vec.sort_by(|a, b| a.der_cmp(b).unwrap_or(Ordering::Less));

            // Perform a pass over the elements to ensure they're sorted
            for i in 0..(vec.len() - 1) {
                match vec.get(i..(i + 2)) {
                    Some([a, b]) => match a.der_cmp(b) {
                        Ok(Ordering::Less) | Ok(Ordering::Equal) => (),
                        _ => return Err(ErrorKind::SetOrdering.into()),
                    },
                    _ => return Err(ErrorKind::SetOrdering.into()),
                }
            }
        }

        Ok(SetOfVec { inner: vec })
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl<T> ValueOrd for SetOfVec<T>
where
    T: Clone + DerOrd,
{
    fn value_cmp(&self, other: &Self) -> Result<Ordering> {
        iter_cmp(self.iter(), other.iter())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use super::SetOfVec;

    #[cfg(feature = "alloc")]
    #[test]
    fn setofvec_tryfrom_vec() {
        let vec = vec![3u16, 2, 1, 65535, 0];
        let set = SetOfVec::try_from(vec).unwrap();
        assert_eq!(set.as_ref(), &[0, 1, 2, 3, 65535]);
    }
}
