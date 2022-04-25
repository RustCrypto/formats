//! Trait definition for [`Encode`].

use crate::{Encoder, Header, Length, Result, Tagged, Writer};

#[cfg(feature = "alloc")]
use {crate::ErrorKind, alloc::vec::Vec, core::iter};

#[cfg(feature = "pem")]
use {
    alloc::string::String,
    pem_rfc7468::{self as pem, LineEnding, PemLabel},
    zeroize::Zeroizing,
};

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
    fn to_pem(&self, line_ending: LineEnding) -> Result<String> {
        // TODO(tarcieri): support for encoding directly from PEM (instead of two-pass)
        let der = Zeroizing::new(self.to_vec()?);
        Ok(pem::encode_string(Self::PEM_LABEL, line_ending, &der)?)
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
