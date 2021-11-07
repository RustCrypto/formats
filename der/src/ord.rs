//! Ordering trait.

use crate::{EncodeValue, Result, Tagged};
use core::cmp::Ordering;

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
