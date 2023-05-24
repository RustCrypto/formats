//! Ordering trait.

use crate::{EncodeValue, ErrorKind, Result, Tagged};
use core::{cmp::Ordering, marker::PhantomData};

/// DER ordering trait.
///
/// Compares the ordering of two values based on their ASN.1 DER
/// serializations.
///
/// This is used by the DER encoding for `SET OF` in order to establish an
/// ordering for the elements of sets.
pub trait DerOrd {
    /// Return an [`Ordering`] between `self` and `other` when serialized as
    /// ASN.1 DER.
    fn der_cmp(&self, other: &Self) -> Result<Ordering>;
}

/// DER value ordering trait.
///
/// Compares the ordering of the value portion of TLV-encoded DER productions.
pub trait ValueOrd {
    /// Return an [`Ordering`] between value portion of TLV-encoded `self` and
    /// `other` when serialized as ASN.1 DER.
    fn value_cmp(&self, other: &Self) -> Result<Ordering>;
}

impl<T> DerOrd for T
where
    T: EncodeValue + ValueOrd + Tagged,
{
    fn der_cmp(&self, other: &Self) -> Result<Ordering> {
        match self.header()?.der_cmp(&other.header()?)? {
            Ordering::Equal => self.value_cmp(other),
            ordering => Ok(ordering),
        }
    }
}

/// Marker trait for types whose `Ord` impl can be used as `ValueOrd`.
///
/// This means the `Ord` impl will sort values in the same order as their DER
/// encodings.
pub trait OrdIsValueOrd: Ord {}

impl<T> ValueOrd for T
where
    T: OrdIsValueOrd,
{
    fn value_cmp(&self, other: &Self) -> Result<Ordering> {
        Ok(self.cmp(other))
    }
}

/// Compare the order of two iterators using [`DerCmp`] on the values.
pub(crate) fn iter_cmp<'a, I, T: 'a>(a: I, b: I) -> Result<Ordering>
where
    I: Iterator<Item = &'a T> + ExactSizeIterator,
    T: DerOrd,
{
    let length_ord = a.len().cmp(&b.len());

    for (value1, value2) in a.zip(b) {
        match value1.der_cmp(value2)? {
            Ordering::Equal => (),
            other => return Ok(other),
        }
    }

    Ok(length_ord)
}

/// Provide a no-op implementation for PhantomData
impl<T> ValueOrd for PhantomData<T> {
    fn value_cmp(&self, _other: &Self) -> Result<Ordering> {
        Ok(Ordering::Equal)
    }
}

/// Provide a no-op implementation for PhantomData
impl<T> DerOrd for PhantomData<T> {
    fn der_cmp(&self, _other: &Self) -> Result<Ordering> {
        Ok(Ordering::Equal)
    }
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
#[allow(clippy::integer_arithmetic)]
pub fn der_sort<T: DerOrd>(slice: &mut [T]) -> Result<()> {
    for i in 0..slice.len() {
        let mut j = i;

        while j > 0 {
            match slice[j - 1].der_cmp(&slice[j])? {
                Ordering::Less => break,
                Ordering::Equal => return Err(ErrorKind::SetDuplicate.into()),
                Ordering::Greater => {
                    slice.swap(j - 1, j);
                    j -= 1;
                }
            }
        }
    }

    Ok(())
}
