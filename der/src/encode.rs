//! Trait definition for [`Encode`].

use crate::{Encoder, Header, Length, Result, Tagged, Writer};

#[cfg(feature = "alloc")]
use {alloc::vec::Vec, core::iter};

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
pub trait Encode {
    /// Compute the length of this value in bytes when encoded as ASN.1 DER.
    fn encoded_len(&self) -> Result<Length>;

    /// Encode this value as ASN.1 DER using the provided [`Encoder`].
    fn encode(&self, encoder: &mut dyn Writer) -> Result<()>;

    /// Encode this value to the provided byte slice, returning a sub-slice
    /// containing the encoded message.
    fn encode_to_slice<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8]> {
        let mut encoder = Encoder::new(buf);
        self.encode(&mut encoder)?;
        encoder.finish()
    }

    /// Encode this message as ASN.1 DER, appending it to the provided
    /// byte vector.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn encode_to_vec(&self, buf: &mut Vec<u8>) -> Result<Length> {
        let expected_len = usize::try_from(self.encoded_len()?)?;
        buf.reserve(expected_len);
        buf.extend(iter::repeat(0).take(expected_len));

        let mut encoder = Encoder::new(buf);
        self.encode(&mut encoder)?;
        let actual_len = encoder.finish()?.len();

        if expected_len != actual_len {
            return Err(ErrorKind::Incomplete {
                expected_len: expected_len.try_into()?,
                actual_len: actual_len.try_into()?,
            }
            .into());
        }

        actual_len.try_into()
    }

    /// Serialize this message as a byte vector.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn to_vec(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.encode_to_vec(&mut buf)?;
        Ok(buf)
    }
}

impl<T> Encode for T
where
    T: EncodeValue + Tagged,
{
    /// Compute the length of this value in bytes when encoded as ASN.1 DER.
    fn encoded_len(&self) -> Result<Length> {
        self.value_len().and_then(|len| len.for_tlv())
    }

    /// Encode this value as ASN.1 DER using the provided [`Encoder`].
    fn encode(&self, writer: &mut dyn Writer) -> Result<()> {
        self.header()?.encode(writer)?;
        self.encode_value(writer)
    }
}

/// PEM encoding trait.
///
/// This trait is automatically impl'd for any type which impls both
/// [`Encode`] and [`PemLabel`].
#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
pub trait EncodePem: Encode + PemLabel {
    /// Try to encode this type as PEM.
    fn to_pem(&self, line_ending: LineEnding) -> Result<String>;
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl<T: Encode + PemLabel> EncodePem for T {
    #[allow(clippy::integer_arithmetic)]
    fn to_pem(&self, line_ending: LineEnding) -> Result<String> {
        // TODO(tarcieri): checked arithmetic, maybe extract this into `base64ct::base64_len`?
        let der_len = usize::try_from(self.encoded_len()?)?;
        let mut base64_len = (((der_len * 4) / 3) + 3) & !3;

        // Add the length of the line endings which will be inserted when
        // encoded Base64 is line wrapped
        // TODO(tarcieri): factor this logic into `pem-rfc7468`
        base64_len += base64_len
            .saturating_sub(1)
            .checked_div(64)
            .and_then(|len| len.checked_add(line_ending.len()))
            .ok_or(ErrorKind::Overflow)?;

        let pem_len = pem::encapsulated_len(Self::PEM_LABEL, line_ending, base64_len)?;

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
        Header::new(self.tag(), self.value_len()?)
    }

    /// Compute the length of this value (sans [`Tag`]+[`Length`] header) when
    /// encoded as ASN.1 DER.
    fn value_len(&self) -> Result<Length>;

    /// Encode value (sans [`Tag`]+[`Length`] header) as ASN.1 DER using the
    /// provided [`Encoder`].
    fn encode_value(&self, encoder: &mut dyn Writer) -> Result<()>;
}
