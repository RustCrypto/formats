//! PKCS#1 OtherPrimeInfo support.

use der::{Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence, Writer};

/// PKCS#1 OtherPrimeInfo as defined in [RFC 8017 Appendix 1.2].
///
/// ASN.1 structure containing an additional prime in a multi-prime RSA key.
///
/// ```text
/// OtherPrimeInfo ::= SEQUENCE {
///     prime             INTEGER,  -- ri
///     exponent          INTEGER,  -- di
///     coefficient       INTEGER   -- ti
/// }
/// ```
///
/// [RFC 8017 Appendix 1.2]: https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.2
#[derive(Clone)]
pub struct OtherPrimeInfo<U> {
    /// Prime factor `r_i` of `n`, where `i` >= 3.
    pub prime: U,

    /// Exponent: `d_i = d mod (r_i - 1)`.
    pub exponent: U,

    /// CRT coefficient: `t_i = (r_1 * r_2 * ... * r_(i-1))^(-1) mod r_i`.
    pub coefficient: U,
}

impl<'a, U> DecodeValue<'a> for OtherPrimeInfo<U>
where
    U: Decode<'a, Error = der::Error>,
{
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        Ok(Self {
            prime: reader.decode()?,
            exponent: reader.decode()?,
            coefficient: reader.decode()?,
        })
    }
}

impl<U> EncodeValue for OtherPrimeInfo<U>
where
    U: Encode,
{
    fn value_len(&self) -> der::Result<Length> {
        self.prime.encoded_len()? + self.exponent.encoded_len()? + self.coefficient.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.prime.encode(writer)?;
        self.exponent.encode(writer)?;
        self.coefficient.encode(writer)?;
        Ok(())
    }
}

impl<U> Sequence<'_> for OtherPrimeInfo<U> {}
