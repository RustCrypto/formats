//! ASN.1 `BIT STRING` support.

use crate::{Length, Result, Tag};
use core::{
    cell::UnsafeCell,
    fmt::{self, Debug},
    ptr, slice,
};

/// Inaccessible placeholder ZST which is sound to construct in any length.
///
/// Using [`UnsafeCell`] prevents the compiler from reasoning about aliasing of the unknown type.
type Inner = UnsafeCell<()>;

/// ASN.1 `BIT STRING` reference type.
///
/// This type contains a sequence of any number of bits.
///
/// This is a zero-copy reference type which borrows from the input data.
#[repr(transparent)]
pub struct BitStringRef2 {
    /// Fat pointer which represents the bit string as a slice with a given number of bits.
    inner: [Inner],
}

impl BitStringRef2 {
    /// Create a new ASN.1 `BIT STRING` from a byte slice.
    ///
    /// Accepts an optional number of "unused bits" (0-7) which are omitted from the final octet.
    /// This number is 0 if the value is octet-aligned.
    ///
    /// # Errors
    /// Returns an error if any of the following occur:
    /// - `unused_bits` is invalid
    /// - `bytes` is too long
    /// - an overflow occurred calculating the bit length
    #[allow(unsafe_code)]
    pub fn new<'a>(unused_bits: u8, bytes: &'a [u8]) -> Result<&'a Self> {
        let bits = bit_length(unused_bits, bytes)?;

        // Create a slice that stores the original pointer to `bytes` and `bits` as its length.
        // SAFETY: `Inner` is a ZST so we can construct slices of any length so long as the pointer
        // is valid.
        let slice = unsafe { slice::from_raw_parts::<'a, Inner>(bytes.as_ptr().cast(), bits) };

        // SAFETY: `Self` is a `repr(transparent)` newtype for `[UnsafeCell<()>]`.
        Ok(unsafe { &*(ptr::from_ref(slice) as *const Self) })
    }

    /// Create a new ASN.1 `BIT STRING` from the given bytes.
    ///
    /// The "unused bits" are set to 0.
    ///
    /// # Errors
    /// Has the same error cases as [`BitStringRef2::new`].
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        Self::new(0, bytes)
    }

    /// Borrow the inner byte slice.
    ///
    /// Returns `None` if the number of unused bits is *not* equal to zero, i.e. if the `BIT STRING`
    /// is not octet aligned.
    ///
    /// Use [`BitStringRef2::raw_bytes`] to obtain access to the raw value regardless of the presence
    /// of unused bits.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        if self.has_unused_bits() {
            None
        } else {
            Some(self.raw_bytes())
        }
    }

    /// Borrow the raw bytes of this `BIT STRING`.
    ///
    /// Note that the byte string may contain extra unused bits in the final octet.
    ///
    /// If the number of unused bits is expected to be 0, the [`BitStringRef2::as_bytes`] function
    /// can be used instead.
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        // SAFETY: `byte_length` computes the original length of the byte slice this `BitStringRef`
        // was constructed from, and `inner` contains the original pointer.
        #[allow(unsafe_code)]
        unsafe {
            slice::from_raw_parts(self.inner.as_ptr().cast(), byte_length(self.inner.len()))
        }
    }

    /// Returns `Some(bit)` if index is valid.
    #[must_use]
    pub fn get(&self, position: usize) -> Option<bool> {
        if position >= self.bit_len() {
            return None;
        }

        let byte = self.raw_bytes().get(position / 8)?;
        let bitmask = 1u8 << (7 - (position % 8));
        Some(byte & bitmask != 0)
    }

    /// Get the length of this `BIT STRING` in bits.
    #[must_use]
    pub fn bit_len(&self) -> usize {
        self.inner.len()
    }

    /// Get the length of this `BIT STRING` in bytes.
    #[must_use]
    #[allow(clippy::missing_panics_doc, reason = "should not panic in practice")]
    pub fn byte_len(&self) -> Length {
        Length::new_usize(byte_length(self.bit_len())).expect("arithmetic error")
    }

    /// Get the number of unused bits in this byte slice.
    #[must_use]
    pub fn unused_bits(&self) -> u8 {
        match self.unaligned_bits() {
            0 => 0,
            n => 8 - n,
        }
    }

    /// Is the number of unused bits a value other than 0?
    #[must_use]
    pub fn has_unused_bits(&self) -> bool {
        self.unaligned_bits() != 0
    }

    /// Is this bit string empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get the number of bits which aren't aligned to a byte.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, reason = "masked to fit")]
    fn unaligned_bits(&self) -> u8 {
        (self.bit_len() & 0b111) as u8
    }
}

impl Debug for BitStringRef2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitStringRef2")
            .field("inner", &self.raw_bytes())
            .field("unused_bits", &self.unused_bits())
            .finish_non_exhaustive()
    }
}

/// Compute the length of a `BIT STRING` in bits given `unused_bits` and its `bytes`.
fn bit_length(unused_bits: u8, bytes: &[u8]) -> Result<usize> {
    match bytes
        .len()
        .checked_mul(8)
        .and_then(|b| b.checked_sub(unused_bits.into()))
    {
        Some(bits) if unused_bits < 8 => Ok(bits),
        _ => Err(Tag::BitString.value_error().into()),
    }
}

/// Compute the length of a `BIT STRING` in bytes from its length in bits.
fn byte_length(bits: usize) -> usize {
    bits.div_ceil(8)
}

#[cfg(test)]
mod tests {
    use super::BitStringRef2;

    #[test]
    fn bits() {
        let bytes = [0u8, 1, 2];
        let aligned = BitStringRef2::new(0, &bytes).unwrap();
        assert_eq!(aligned.bit_len(), 24);
        assert_eq!(aligned.byte_len(), bytes.len().try_into().unwrap());
        assert_eq!(aligned.unused_bits(), 0);
        assert!(!aligned.has_unused_bits());

        let unaligned = BitStringRef2::new(1, &bytes).unwrap();
        assert_eq!(unaligned.bit_len(), 23);
        assert_eq!(aligned.byte_len(), bytes.len().try_into().unwrap());
        assert_eq!(unaligned.unused_bits(), 1);
        assert!(unaligned.has_unused_bits());
    }

    #[test]
    fn raw_bytes() {
        let bytes = [0u8, 1, 2];
        let aligned = BitStringRef2::new(0, &bytes).unwrap();
        assert_eq!(aligned.raw_bytes(), &bytes);

        let unaligned = BitStringRef2::new(1, &bytes).unwrap();
        assert_eq!(unaligned.raw_bytes(), &bytes);
    }

    #[test]
    fn too_many_unused_bits() {
        assert!(BitStringRef2::new(1, &[]).is_err());
        assert!(BitStringRef2::new(8, &[0, 1, 2]).is_err());
    }
}
