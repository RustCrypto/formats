//! Base32 alphabets.

pub(crate) mod base32;
pub(crate) mod base32upper;

use core::fmt::Debug;

/// Core encoder/decoder functions for a particular Base64 alphabet
pub trait Alphabet: 'static + Copy + Debug + Eq + Send + Sized + Sync {
    /// Is this encoding padded?
    const PADDED: bool;

    /// Use bitwise operators instead of table-lookups to turn 5-bit integers
    /// into 8-bit integers.
    fn decode_5bits(byte: u8) -> i16;

    /// Use bitwise operators instead of table-lookups to turn 8-bit integers
    /// into 5-bit integers.
    fn encode_5bits(src: u8) -> u8;
}
