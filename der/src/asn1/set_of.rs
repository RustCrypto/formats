//! ASN.1 `SET OF` support.
//!
//! # Ordering Notes
//!
//! Some DER serializer implementations fail to properly sort elements of a `SET OF`. This is
//! technically non-canonical, but occurs frequently enough that most DER decoders tolerate it.
//!
//! When decoding with `EncodingRules::Der`, this implementation sorts the elements of `SET OF` at
//! decode-time to ensure reserializations are canonical.

#![cfg(any(feature = "alloc", feature = "heapless"))]

use crate::{
    AnyRef, Decode, DecodeValue, DerOrd, Encode, EncodeValue, Error, ErrorKind, FixedTag, Header,
    Length, Reader, SliceReader, Tag, ValueOrd, Writer, ord::iter_cmp, ord::iter_cmp_owned,
};
use core::cmp::Ordering;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(any(feature = "alloc", feature = "heapless"))]
use core::slice;

/// ASN.1 `SET OF` backed by an array.
///
/// This type implements an append-only `SET OF` type which is stack-based
/// and does not depend on `alloc` support.
// TODO(tarcieri): use `ArrayVec` when/if it's merged into `core` (rust-lang/rfcs#3316)
#[cfg(feature = "heapless")]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct SetOf<T, const N: usize>
where
    T: DerOrd,
{
    inner: heapless::Vec<T, N>,
}

// Inner reference of a SetOfRef
//
// An internal reference can either be bytes when constructed during decoding
// or a slice of items of the generic type T.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
enum InnerRef<'a, T> {
    BytesRef(&'a [u8], usize),
    ObjectsRef(&'a [T]),
}

/// ASN.1 `SET OF` with a reference to an array.
///
/// This type implements a viewer in a `SET OF` type
/// and does not depend on `alloc` support.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SetOfRef<'a, T>
where
    T: DerOrd,
{
    inner: InnerRef<'a, T>,
}

#[cfg(feature = "heapless")]
impl<T, const N: usize> SetOf<T, N>
where
    T: DerOrd,
{
    /// Create a new [`SetOf`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: heapless::Vec::default(),
        }
    }

    /// Insert an item into this [`SetOf`].
    ///
    /// # Errors
    /// If there's a sorting error.
    pub fn insert(&mut self, item: T) -> Result<(), Error> {
        self.try_push(item)?;
        der_sort(self.inner.as_mut())
    }

    /// Insert an item into this [`SetOf`].
    ///
    /// Items MUST be added in lexicographical order according to the [`DerOrd`] impl on `T`.
    ///
    /// # Errors
    /// If items are added out-of-order or there isn't sufficient space.
    pub fn insert_ordered(&mut self, item: T) -> Result<(), Error> {
        // Ensure set elements are lexicographically ordered
        if let Some(last) = self.inner.last() {
            check_der_ordering(last, &item)?;
        }

        self.try_push(item)
    }

    /// Borrow the elements of this [`SetOf`] as a slice.
    pub fn as_slice(&self) -> &[T] {
        self.inner.as_slice()
    }

    /// Get the nth element from this [`SetOf`].
    pub fn get(&self, index: usize) -> Option<&T> {
        self.inner.get(index)
    }

    /// Extract the inner `heapless::Vec`.
    pub fn into_inner(self) -> heapless::Vec<T, N> {
        self.inner
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

    /// Attempt to push an element onto the [`SetOf`].
    ///
    /// Does not perform ordering or uniqueness checks.
    fn try_push(&mut self, item: T) -> Result<(), Error> {
        self.inner
            .push(item)
            .map_err(|_| ErrorKind::Overlength.into())
    }
}

#[cfg(feature = "heapless")]
impl<T, const N: usize> AsRef<[T]> for SetOf<T, N>
where
    T: DerOrd,
{
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<'a, T> SetOfRef<'a, T>
where
    T: Decode<'a> + 'a,
    T: Clone + DerOrd,
{
    /// Creates a [`SetOfRef`] by parsing the *contents* of a DER-encoded `SET OF` —
    /// that is, the raw bytes after the tag and length bytes have been stripped.
    fn from_bytes(v: &'a [u8]) -> Result<Self, Error> {
        // Make sure we can decode valid objects from the bytes
        let mut reader = SliceReader::new(v)?;

        let mut iter_len = 0;
        while !reader.is_finished() {
            AnyRef::decode(&mut reader).map_err(|_| Error::from_kind(ErrorKind::Failed))?;
            iter_len += 1;
        }

        // Generate the set as a byte reference
        let new_set = Self {
            inner: InnerRef::BytesRef(v, iter_len),
        };

        // Assert the constructed set obeys ordering rules
        new_set
            .iter()
            .is_sorted_by(|a, b| !matches!(a.der_cmp(b), Ok(Ordering::Greater)))
            .then_some(new_set)
            .ok_or_else(|| Error::from_kind(ErrorKind::SetOrdering))
    }

    /// Get the nth element from this [`SetOfRef`].
    #[must_use]
    pub fn get(&self, index: usize) -> Option<T>
    where
        T: Decode<'a> + 'a,
        T: Clone,
    {
        self.iter().nth(index)
    }

    /// Iterate over the elements of this [`SetOfRef`].
    ///
    /// # Panics
    ///
    /// Panics if the inner byte slice contains invalid data that cannot be
    /// parsed by [`SliceReader`].
    #[must_use]
    pub fn iter(&self) -> SetOfRefIter<'a, T>
    where
        T: Decode<'a> + 'a,
    {
        match self.inner {
            InnerRef::BytesRef(inner, length) => SetOfRefIter {
                inner: InnerIterRef::<'a, T>::BytesRef(
                    SliceReader::new(inner).expect("Invalid data"),
                ),
                length,
            },
            InnerRef::ObjectsRef(inner) => SetOfRefIter {
                inner: InnerIterRef::<'a, T>::ObjectsRef(inner),
                length: inner.len(),
            },
        }
    }

    /// Is this [`SetOfRef`] empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self.inner {
            InnerRef::BytesRef(inner, _) => inner.is_empty(),
            InnerRef::ObjectsRef(inner) => inner.is_empty(),
        }
    }

    /// Number of elements in this [`SetOfRef`].
    #[must_use]
    pub fn len(&self) -> usize
    where
        T: Decode<'a> + 'a,
        T: Clone,
    {
        self.iter().len()
    }
}

#[cfg(feature = "heapless")]
impl<T, const N: usize> Default for SetOf<T, N>
where
    T: DerOrd,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "heapless")]
impl<'a, T, const N: usize> DecodeValue<'a> for SetOf<T, N>
where
    T: Decode<'a> + DerOrd,
{
    type Error = T::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> Result<Self, Self::Error> {
        let mut result = Self::new();

        while !reader.is_finished() {
            result.try_push(T::decode(reader)?)?;
        }

        if reader.encoding_rules().is_der() {
            // Ensure elements of the `SetOf` are sorted and will serialize as valid DER
            der_sort(result.inner.as_mut())?;
        }

        Ok(result)
    }
}

impl<'a, T> DecodeValue<'a> for SetOfRef<'a, T>
where
    T: Clone,
    T: Decode<'a> + DerOrd,
{
    type Error = Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self, Self::Error> {
        let inner_slice: &'a [u8] = reader.read_slice(header.length())?;
        SetOfRef::<'a, T>::from_bytes(inner_slice)
    }
}

#[cfg(feature = "heapless")]
impl<T, const N: usize> EncodeValue for SetOf<T, N>
where
    T: Encode + DerOrd,
{
    fn value_len(&self) -> Result<Length, Error> {
        self.iter()
            .try_fold(Length::ZERO, |len, elem| len + elem.encoded_len()?)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), Error> {
        for elem in self.iter() {
            elem.encode(writer)?;
        }

        Ok(())
    }
}

impl<'a, T> EncodeValue for SetOfRef<'a, T>
where
    T: Decode<'a> + Encode + DerOrd,
    T: Clone,
{
    fn value_len(&self) -> Result<Length, Error> {
        self.iter()
            .try_fold(Length::ZERO, |len, elem| len + elem.encoded_len()?)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), Error> {
        for elem in self.iter() {
            elem.encode(writer)?;
        }

        Ok(())
    }
}

#[cfg(feature = "heapless")]
impl<T, const N: usize> FixedTag for SetOf<T, N>
where
    T: DerOrd,
{
    const TAG: Tag = Tag::Set;
}

impl<'a, T> FixedTag for SetOfRef<'a, T>
where
    T: DerOrd,
{
    const TAG: Tag = Tag::Set;
}

#[cfg(feature = "heapless")]
impl<T, const N: usize> TryFrom<[T; N]> for SetOf<T, N>
where
    T: DerOrd,
{
    type Error = Error;

    fn try_from(mut arr: [T; N]) -> Result<SetOf<T, N>, Error> {
        der_sort(&mut arr)?;

        let mut result = SetOf::new();

        for elem in arr {
            result.insert_ordered(elem)?;
        }

        Ok(result)
    }
}

impl<'a, T> TryFrom<&'a [T]> for SetOfRef<'a, T>
where
    T: DerOrd,
{
    type Error = Error;

    fn try_from(arr: &'a [T]) -> Result<SetOfRef<'a, T>, Error> {
        arr.iter()
            .is_sorted_by(|a, b| !matches!(a.der_cmp(b), Ok(Ordering::Greater)))
            .then_some(SetOfRef {
                inner: InnerRef::ObjectsRef(arr),
            })
            .ok_or_else(|| Error::from_kind(ErrorKind::SetOrdering))
    }
}

impl<'a, T> From<&SetOfRef<'a, T>> for SetOfRef<'a, T>
where
    T: Clone + DerOrd,
{
    fn from(value: &SetOfRef<'a, T>) -> SetOfRef<'a, T> {
        value.clone()
    }
}

#[cfg(feature = "heapless")]
impl<T, const N: usize> ValueOrd for SetOf<T, N>
where
    T: DerOrd,
{
    fn value_cmp(&self, other: &Self) -> Result<Ordering, Error> {
        iter_cmp(self.iter(), other.iter())
    }
}

impl<'a, T> ValueOrd for SetOfRef<'a, T>
where
    T: Decode<'a> + DerOrd + 'a,
    T: Clone,
{
    fn value_cmp(&self, other: &Self) -> Result<Ordering, Error> {
        iter_cmp_owned(self.iter(), other.iter())
    }
}

/// Iterator over the elements of an [`SetOf`].
#[derive(Clone, Debug)]
pub struct SetOfIter<'a, T> {
    /// Inner iterator.
    inner: slice::Iter<'a, T>,
}

impl<'a, T: 'a> Iterator for SetOfIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'a, T: 'a> ExactSizeIterator for SetOfIter<'a, T> {}

// Inner reference of a SetOfRefIter
//
// An internal reference can either be a slice reader when constructed during decoding
// or a slice of items of the generic type T.
#[derive(Clone, Debug)]
enum InnerIterRef<'a, T> {
    BytesRef(SliceReader<'a>),
    ObjectsRef(&'a [T]),
}

/// Iterator over the elements of an [`SetOfRef`].
#[derive(Clone, Debug)]
pub struct SetOfRefIter<'a, T>
where
    T: Decode<'a>,
{
    /// Inner iterator.
    inner: InnerIterRef<'a, T>,
    length: usize,
}

impl<'a, T> Iterator for SetOfRefIter<'a, T>
where
    T: Decode<'a> + 'a,
    T: Clone,
{
    type Item = T;

    fn next(&mut self) -> Option<T> {
        match &mut self.inner {
            InnerIterRef::BytesRef(inner_reader) => {
                if inner_reader.is_finished() {
                    return None;
                }

                let next_val = T::decode(inner_reader).ok()?;
                self.length -= 1;
                Some(next_val)
            }
            InnerIterRef::ObjectsRef(inner_slice) => {
                let next_val = inner_slice.first()?;
                self.inner = InnerIterRef::ObjectsRef(&inner_slice[1..]);
                self.length -= 1;

                Some(next_val.clone())
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.length, Some(self.length))
    }
}

impl<'a, T> ExactSizeIterator for SetOfRefIter<'a, T>
where
    T: Decode<'a> + 'a,
    T: Clone,
{
}

/// ASN.1 `SET OF` backed by a [`Vec`].
///
/// This type implements an append-only `SET OF` type which is heap-backed
/// and depends on `alloc` support.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct SetOfVec<T>
where
    T: DerOrd,
{
    inner: Vec<T>,
}

#[cfg(feature = "alloc")]
impl<T: DerOrd> Default for SetOfVec<T> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
        }
    }
}

#[cfg(feature = "alloc")]
impl<T> SetOfVec<T>
where
    T: DerOrd,
{
    /// Create a new [`SetOfVec`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Vec::default(),
        }
    }

    /// Create a new [`SetOfVec`] from the given iterator.
    ///
    /// Note: this is an inherent method instead of an impl of the [`FromIterator`] trait in order
    /// to be fallible.
    ///
    /// # Errors
    /// If a sorting error occurred.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = T>,
    {
        Vec::from_iter(iter).try_into()
    }

    /// Extend a [`SetOfVec`] using an iterator.
    ///
    /// Note: this is an inherent method instead of an impl of the [`Extend`] trait in order to
    /// be fallible.
    ///
    /// # Errors
    /// If a sorting error occurred.
    pub fn extend<I>(&mut self, iter: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = T>,
    {
        self.inner.extend(iter);
        der_sort(&mut self.inner)
    }

    /// Insert an item into this [`SetOfVec`]. Must be unique.
    ///
    /// # Errors
    /// If a sorting error occurred.
    pub fn insert(&mut self, item: T) -> Result<(), Error> {
        self.inner.push(item);
        der_sort(&mut self.inner)
    }

    /// Insert an item into this [`SetOfVec`]. Must be unique.
    ///
    /// Items MUST be added in lexicographical order according to the [`DerOrd`] impl on `T`.
    ///
    /// # Errors
    /// If a sorting error occurred.
    pub fn insert_ordered(&mut self, item: T) -> Result<(), Error> {
        // Ensure set elements are lexicographically ordered
        if let Some(last) = self.inner.last() {
            check_der_ordering(last, &item)?;
        }

        self.inner.push(item);
        Ok(())
    }

    /// Borrow the elements of this [`SetOfVec`] as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        self.inner.as_slice()
    }

    /// Get the nth element from this [`SetOfVec`].
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&T> {
        self.inner.get(index)
    }

    /// Convert this [`SetOfVec`] into the inner [`Vec`].
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.inner
    }

    /// Iterate over the elements of this [`SetOfVec`].
    #[must_use]
    pub fn iter(&self) -> SetOfIter<'_, T> {
        SetOfIter {
            inner: self.inner.iter(),
        }
    }

    /// Is this [`SetOfVec`] empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Number of elements in this [`SetOfVec`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(feature = "alloc")]
impl<T> AsRef<[T]> for SetOfVec<T>
where
    T: DerOrd,
{
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}

#[cfg(feature = "alloc")]
impl<'a, T> DecodeValue<'a> for SetOfVec<T>
where
    T: Decode<'a> + DerOrd,
{
    type Error = T::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> Result<Self, Self::Error> {
        let mut inner = Vec::new();

        while !reader.is_finished() {
            inner.push(T::decode(reader)?);
        }

        if reader.encoding_rules().is_der() {
            der_sort(inner.as_mut())?;
        }

        Ok(Self { inner })
    }
}

#[cfg(feature = "alloc")]
impl<T> EncodeValue for SetOfVec<T>
where
    T: Encode + DerOrd,
{
    fn value_len(&self) -> Result<Length, Error> {
        self.iter()
            .try_fold(Length::ZERO, |len, elem| len + elem.encoded_len()?)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), Error> {
        for elem in self.iter() {
            elem.encode(writer)?;
        }

        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl<T> FixedTag for SetOfVec<T>
where
    T: DerOrd,
{
    const TAG: Tag = Tag::Set;
}

#[cfg(feature = "alloc")]
impl<T> From<SetOfVec<T>> for Vec<T>
where
    T: DerOrd,
{
    fn from(set: SetOfVec<T>) -> Vec<T> {
        set.into_vec()
    }
}

#[cfg(feature = "alloc")]
impl<T> TryFrom<Vec<T>> for SetOfVec<T>
where
    T: DerOrd,
{
    type Error = Error;

    fn try_from(mut vec: Vec<T>) -> Result<SetOfVec<T>, Error> {
        // TODO(tarcieri): use `[T]::sort_by` here?
        der_sort(vec.as_mut_slice())?;
        Ok(SetOfVec { inner: vec })
    }
}

#[cfg(feature = "alloc")]
impl<T, const N: usize> TryFrom<[T; N]> for SetOfVec<T>
where
    T: DerOrd,
{
    type Error = Error;

    fn try_from(arr: [T; N]) -> Result<SetOfVec<T>, Error> {
        Vec::from(arr).try_into()
    }
}

#[cfg(feature = "alloc")]
impl<T> ValueOrd for SetOfVec<T>
where
    T: DerOrd,
{
    fn value_cmp(&self, other: &Self) -> Result<Ordering, Error> {
        iter_cmp(self.iter(), other.iter())
    }
}

// Implement by hand because custom derive would create invalid values.
// Use the conversion from Vec to create a valid value.
#[cfg(feature = "arbitrary")]
impl<'a, T> arbitrary::Arbitrary<'a> for SetOfVec<T>
where
    T: DerOrd + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Self::try_from(u.arbitrary_iter()?.collect::<Result<Vec<_>, _>>()?)
            .map_err(|_| arbitrary::Error::IncorrectFormat)
    }

    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        (0, None)
    }
}

/// Ensure set elements are lexicographically ordered using [`DerOrd`].
fn check_der_ordering<T: DerOrd>(a: &T, b: &T) -> Result<(), Error> {
    if a.der_cmp(b)? == Ordering::Greater {
        return Err(ErrorKind::SetOrdering.into());
    }

    Ok(())
}

/// Sort a mut slice according to its [`DerOrd`], returning any errors which
/// might occur during the comparison.
///
/// The algorithm is insertion sort, which should perform well when the input
/// is mostly sorted to begin with.
///
/// This function is used rather than Rust's built-in `[T]::sort_by` in order
/// to support heapless `no_std` targets as well as to enable bubbling up
/// sorting errors.
#[allow(clippy::arithmetic_side_effects)]
fn der_sort<T: DerOrd>(slice: &mut [T]) -> Result<(), Error> {
    for i in 0..slice.len() {
        let mut j = i;

        while j > 0 {
            if slice[j - 1].der_cmp(&slice[j])? == Ordering::Greater {
                slice.swap(j - 1, j);
                j -= 1;
            } else {
                break;
            }
        }
    }

    Ok(())
}

#[cfg(feature = "alloc")]
mod allocating {
    use super::*;
    use crate::referenced::*;

    impl<'a, T> RefToOwned<'a> for SetOfRef<'a, T>
    where
        T: Decode<'a> + EncodeValue + 'a,
        T: DerOrd + FixedTag,
        T: Clone,
    {
        type Owned = SetOfVec<T>;
        fn ref_to_owned(&self) -> Self::Owned {
            SetOfVec::from_iter(self.iter()).expect("SetOfVec: Could not sort inner slice")
        }
    }

    impl<T> OwnedToRef for SetOfVec<T>
    where
        T: Encode,
        T: DerOrd,
    {
        type Borrowed<'a>
            = SetOfRef<'a, T>
        where
            T: 'a;

        fn owned_to_ref(&self) -> Self::Borrowed<'_> {
            SetOfRef::<T>::try_from(self.inner.as_slice()).expect("Unsorted slice")
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {

    use crate::ErrorKind;
    #[cfg(feature = "alloc")]
    use {
        super::SetOfVec,
        crate::{Decode, Encode, EncodeValue, SliceWriter},
        alloc::vec,
    };

    #[cfg(feature = "heapless")]
    use super::SetOf;
    #[cfg(any(feature = "alloc", feature = "heapless"))]
    use {super::SetOfRef, crate::DerOrd};

    #[cfg(feature = "heapless")]
    #[test]
    fn setof_insert() {
        let mut setof = SetOf::<u8, 10>::new();
        setof.insert(42).unwrap();
        assert_eq!(setof.len(), 1);
        assert_eq!(*setof.iter().next().unwrap(), 42);
    }

    #[cfg(feature = "heapless")]
    #[test]
    fn setof_insert_duplicate() {
        let mut setof = SetOf::<u8, 10>::new();
        setof.insert(42).unwrap();
        assert_eq!(setof.len(), 1);

        setof.insert(42).unwrap();

        let mut iter = setof.iter();

        assert_eq!(setof.len(), 2);
        assert_eq!(*iter.next().unwrap(), 42);
        assert_eq!(*iter.next().unwrap(), 42);
    }

    #[cfg(feature = "heapless")]
    #[test]
    fn setof_tryfrom_array() {
        let arr = [3u16, 2, 1, 65535, 0];
        let set = SetOf::try_from(arr).unwrap();
        assert!(set.iter().copied().eq([0, 1, 2, 3, 65535]));
    }

    #[cfg(feature = "heapless")]
    #[test]
    fn setof_valueord_value_cmp() {
        use core::cmp::Ordering;

        let arr1 = [3u16, 2, 1, 5, 0];
        let arr2 = [3u16, 2, 1, 4, 0];
        let set1 = SetOf::try_from(arr1).unwrap();
        let set2 = SetOf::try_from(arr2).unwrap();
        assert_eq!(set1.der_cmp(&set2), Ok(Ordering::Greater));
    }

    #[test]
    fn setofref_tryfrom_array() {
        let arr = [0u16, 1, 2, 3, 65535];
        let set = SetOfRef::try_from(arr.as_ref()).unwrap();
        assert!(set.iter().eq([0, 1, 2, 3, 65535]));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn setofref_tryfrom_der() {
        let arr = SetOfVec::try_from([0u16, 1, 2, 3, 65535])
            .unwrap()
            .to_der()
            .unwrap();
        let set = SetOfRef::<u16>::from_der(arr.as_ref()).unwrap();
        assert!(set.iter().eq([0, 1, 2, 3, 65535]));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn setofref_tryfrom_bytes() {
        let arr = SetOfVec::try_from([0u16, 1, 2, 3, 65535]).unwrap();

        let mut encoded = vec![0u8; arr.value_len().unwrap().try_into().unwrap()];
        let mut writer = SliceWriter::new(&mut encoded);
        arr.encode_value(&mut writer).unwrap();

        let decoded = SetOfRef::<u16>::from_bytes(writer.finish().unwrap()).unwrap();

        assert!(decoded.iter().eq([0, 1, 2, 3, 65535]));
    }

    #[test]
    fn setofref_tryfrom_array_reject_unsorted() {
        let arr = [3u16, 2, 1, 65535, 0];
        let err = SetOfRef::try_from(arr.as_ref()).err().unwrap();
        assert_eq!(err.kind(), ErrorKind::SetOrdering);
    }

    #[test]
    fn setofref_tryfrom_array_allow_duplicates() {
        let arr = [1u16, 1];
        let set = SetOfRef::try_from(arr.as_ref()).unwrap();
        assert!(set.iter().eq([1, 1]));
    }

    #[test]
    fn setofref_valueord_value_cmp() {
        use core::cmp::Ordering;

        let arr1 = [0u16, 1, 2, 3, 5];
        let arr2 = [0u16, 1, 2, 3, 4];
        let set1 = SetOfRef::try_from(arr1.as_ref()).unwrap();
        let set2 = SetOfRef::try_from(arr2.as_ref()).unwrap();
        assert_eq!(set1.der_cmp(&set2), Ok(Ordering::Greater));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn setofvec_insert() {
        let mut setof = SetOfVec::new();
        setof.insert(42).unwrap();
        assert_eq!(setof.len(), 1);

        setof.insert(46).unwrap();

        let mut iter = setof.iter();

        assert_eq!(setof.len(), 2);
        assert_eq!(*iter.next().unwrap(), 42);
        assert_eq!(*iter.next().unwrap(), 46);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn setofvec_tryfrom_array() {
        let arr = [3u16, 2, 1, 65535, 0];
        let set = SetOfVec::try_from(arr).unwrap();
        assert_eq!(set.as_ref(), &[0, 1, 2, 3, 65535]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn setofvec_tryfrom_vec() {
        let vec = vec![3u16, 2, 1, 65535, 0];
        let set = SetOfVec::try_from(vec).unwrap();
        assert_eq!(set.as_ref(), &[0, 1, 2, 3, 65535]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn setofvec_tryfrom_vec_allow_duplicates() {
        let vec = vec![1u16, 1];
        let set = SetOfVec::try_from(vec).unwrap();
        assert_eq!(set.as_ref(), &[1, 1]);
    }
}
