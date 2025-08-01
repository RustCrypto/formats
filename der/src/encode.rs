//! Trait definition for [`Encode`].

use crate::{Header, Length, Result, SliceWriter, Tagged, Writer};
use core::marker::PhantomData;

#[cfg(feature = "alloc")]
use {alloc::boxed::Box, alloc::vec::Vec};

#[cfg(feature = "pem")]
use {
    crate::PemWriter,
    alloc::string::String,
    pem_rfc7468::{self as pem, LineEnding, PemLabel},
};

#[cfg(any(feature = "alloc", feature = "pem"))]
use crate::ErrorKind;

#[cfg(doc)]
use crate::Tag;

/// Encoding trait.
#[diagnostic::on_unimplemented(
    note = "Consider adding impls of `EncodeValue` and `FixedTag` to `{Self}`"
)]
pub trait Encode {
    /// Compute the length of this value in bytes when encoded as ASN.1 DER.
    fn encoded_len(&self) -> Result<Length>;

    /// Encode this value as ASN.1 DER using the provided [`Writer`].
    fn encode(&self, encoder: &mut impl Writer) -> Result<()>;

    /// Encode this value to the provided byte slice, returning a sub-slice
    /// containing the encoded message.
    fn encode_to_slice<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8]> {
        let mut writer = SliceWriter::new(buf);
        self.encode(&mut writer)?;
        writer.finish()
    }

    /// Encode this message as ASN.1 DER, appending it to the provided
    /// byte vector.
    #[cfg(feature = "alloc")]
    fn encode_to_vec(&self, buf: &mut Vec<u8>) -> Result<Length> {
        let expected_len = usize::try_from(self.encoded_len()?)?;
        let initial_len = buf.len();
        buf.resize(initial_len + expected_len, 0u8);

        let buf_slice = &mut buf[initial_len..];
        let actual_len = self.encode_to_slice(buf_slice)?.len();

        if expected_len != actual_len {
            return Err(ErrorKind::Incomplete {
                expected_len: expected_len.try_into()?,
                actual_len: actual_len.try_into()?,
            }
            .into());
        }

        actual_len.try_into()
    }

    /// Encode this type as DER, returning a byte vector.
    #[cfg(feature = "alloc")]
    fn to_der(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.encode_to_vec(&mut buf)?;
        Ok(buf)
    }
}

impl<T> Encode for T
where
    T: EncodeValue + Tagged + ?Sized,
{
    /// Compute the length of this value in bytes when encoded as ASN.1 DER.
    fn encoded_len(&self) -> Result<Length> {
        self.value_len().and_then(|len| len.for_tlv(self.tag()))
    }

    /// Encode this value as ASN.1 DER using the provided [`Writer`].
    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.header()?.encode(writer)?;
        self.encode_value(writer)
    }
}

/// Dummy implementation for [`PhantomData`] which allows deriving
/// implementations on structs with phantom fields.
impl<T> Encode for PhantomData<T>
where
    T: ?Sized,
{
    fn encoded_len(&self) -> Result<Length> {
        Ok(Length::ZERO)
    }

    fn encode(&self, _writer: &mut impl Writer) -> Result<()> {
        Ok(())
    }
}

/// PEM encoding trait.
///
/// This trait is automatically impl'd for any type which impls both
/// [`Encode`] and [`PemLabel`].
#[cfg(feature = "pem")]
#[diagnostic::on_unimplemented(
    note = "`EncodePem` is auto-impl'd for types which impl both `Encode` and `PemLabel`"
)]
pub trait EncodePem: Encode + PemLabel {
    /// Try to encode this type as PEM.
    fn to_pem(&self, line_ending: LineEnding) -> Result<String>;
}

#[cfg(feature = "pem")]
impl<T> EncodePem for T
where
    T: Encode + PemLabel + ?Sized,
{
    fn to_pem(&self, line_ending: LineEnding) -> Result<String> {
        let der_len = usize::try_from(self.encoded_len()?)?;
        let pem_len = pem::encapsulated_len(Self::PEM_LABEL, line_ending, der_len)?;

        let mut buf = vec![0u8; pem_len];
        let mut writer = PemWriter::new(Self::PEM_LABEL, line_ending, &mut buf)?;
        self.encode(&mut writer)?;

        let actual_len = writer.finish()?;
        buf.truncate(actual_len);
        Ok(String::from_utf8(buf)?)
    }
}

/// Encode the value part of a Tag-Length-Value encoded field, sans the [`Tag`]
/// and [`Length`].
pub trait EncodeValue {
    /// Get the [`Header`] used to encode this value.
    fn header(&self) -> Result<Header>
    where
        Self: Tagged,
    {
        Ok(Header::new(self.tag(), self.value_len()?))
    }

    /// Compute the length of this value (sans [`Tag`]+[`Length`] header) when
    /// encoded as ASN.1 DER.
    fn value_len(&self) -> Result<Length>;

    /// Encode value (sans [`Tag`]+[`Length`] header) as ASN.1 DER using the
    /// provided [`Writer`].
    fn encode_value(&self, encoder: &mut impl Writer) -> Result<()>;
}

#[cfg(feature = "alloc")]
impl<T> EncodeValue for Box<T>
where
    T: EncodeValue,
{
    fn value_len(&self) -> Result<Length> {
        T::value_len(self)
    }
    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        T::encode_value(self, writer)
    }
}

/// Encodes value only (without tag + length) to a slice.
pub(crate) fn encode_value_to_slice<'a, T>(buf: &'a mut [u8], value: &T) -> Result<&'a [u8]>
where
    T: EncodeValue,
{
    let mut encoder = SliceWriter::new(buf);
    value.encode_value(&mut encoder)?;
    encoder.finish()
}
