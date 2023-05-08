//! Trait definition for [`Decode`].

use crate::{Error, FixedTag, Header, Reader, SliceReader};
use core::marker::PhantomData;

#[cfg(feature = "pem")]
use crate::{pem::PemLabel, PemReader};

#[cfg(doc)]
use crate::{Length, Tag};

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

/// Decoding trait.
///
/// This trait provides the core abstraction upon which all decoding operations
/// are based.
pub trait Decode<'a>: Sized + 'a {
    /// Type returned in the event of a decoding error.
    type Error: From<Error> + 'static;

    /// Attempt to decode this message using the provided decoder.
    fn decode<R: Reader<'a>>(decoder: &mut R) -> Result<Self, Self::Error>;

    /// Parse `Self` from the provided DER-encoded byte slice.
    fn from_der(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let mut reader = SliceReader::new(bytes)?;
        let result = Self::decode(&mut reader)?;
        Ok(reader.finish(result)?)
    }
}

impl<'a, T> Decode<'a> for T
where
    T: DecodeValue<'a> + FixedTag + 'a,
{
    type Error = <T as DecodeValue<'a>>::Error;

    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<T, <T as DecodeValue<'a>>::Error> {
        let header = Header::decode(reader)?;
        header.tag.assert_eq(T::TAG)?;
        T::decode_value(reader, header)
    }
}

/// Dummy implementation for [`PhantomData`] which allows deriving
/// implementations on structs with phantom fields.
impl<'a, T> Decode<'a> for PhantomData<T>
where
    T: ?Sized + 'a,
{
    type Error = Error;

    fn decode<R: Reader<'a>>(_reader: &mut R) -> Result<PhantomData<T>, Error> {
        Ok(PhantomData)
    }
}

/// Marker trait for data structures that can be decoded from DER without
/// borrowing any data from the decoder.
///
/// This is primarily useful for trait bounds on functions which require that
/// no data is borrowed from the decoder, for example a PEM decoder which needs
/// to first decode data from Base64.
///
/// This trait is inspired by the [`DeserializeOwned` trait from `serde`](https://docs.rs/serde/latest/serde/de/trait.DeserializeOwned.html).
pub trait DecodeOwned: for<'a> Decode<'a> {}

impl<T> DecodeOwned for T where T: for<'a> Decode<'a> {}

/// PEM decoding trait.
///
/// This trait is automatically impl'd for any type which impls both
/// [`DecodeOwned`] and [`PemLabel`].
#[cfg(feature = "pem")]
pub trait DecodePem: DecodeOwned + PemLabel {
    /// Try to decode this type from PEM.
    fn from_pem(pem: impl AsRef<[u8]>) -> Result<Self, <Self as Decode<'static>>::Error>;
}

#[cfg(feature = "pem")]
impl<T: DecodeOwned<Error = Error> + PemLabel> DecodePem for T {
    fn from_pem(pem: impl AsRef<[u8]>) -> Result<T, Error> {
        let mut reader = PemReader::new(pem.as_ref())?;
        Self::validate_pem_label(reader.type_label()).map_err(Error::from)?;
        T::decode(&mut reader)
    }
}

/// Decode the value part of a Tag-Length-Value encoded field, sans the [`Tag`]
/// and [`Length`].
pub trait DecodeValue<'a>: Sized {
    /// Type returned in the event of a decoding error.
    type Error: From<Error> + 'static;

    /// Attempt to decode this message using the provided [`Reader`].
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self, Self::Error>;
}

#[cfg(feature = "alloc")]
impl<'a, T> DecodeValue<'a> for Box<T>
where
    T: DecodeValue<'a>,
{
    type Error = T::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self, Self::Error> {
        Ok(Box::new(T::decode_value(reader, header)?))
    }
}
