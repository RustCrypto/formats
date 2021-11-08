//! The [`Sequence`] trait simplifies writing decoders/encoders which map ASN.1
//! `SEQUENCE`s to Rust structs.

use crate::{Decodable, Encodable, Result};

/// ASN.1 `to be signed` trait.
///
/// Types which impl this trait receive blanket impls for the [`Decodable`],
/// [`Encodable`], and [`Tagged`] traits.
pub trait Coverage<'a>: Decodable<'a> {
    /// Call the provided function with a slice of [`Encodable`] trait objects
    /// representing the fields of this `SEQUENCE`.
    ///
    /// This method uses a callback because structs with fields which aren't
    /// directly [`Encodable`] may need to construct temporary values from
    /// their fields prior to encoding.
    fn fields<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> Result<T>;
}
