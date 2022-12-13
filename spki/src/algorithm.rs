//! X.509 `AlgorithmIdentifier`

use crate::{Error, Result};
use core::cmp::Ordering;
use der::{
    asn1::{AnyRef, Choice, ObjectIdentifier},
    Decode, DecodeValue, DerOrd, Encode, Header, Reader, Sequence, ValueOrd,
};

#[cfg(feature = "alloc")]
use der::asn1::Any;

/// X.509 `AlgorithmIdentifier` as defined in [RFC 5280 Section 4.1.1.2].
///
/// ```text
/// AlgorithmIdentifier  ::=  SEQUENCE  {
///      algorithm               OBJECT IDENTIFIER,
///      parameters              ANY DEFINED BY algorithm OPTIONAL  }
/// ```
///
/// [RFC 5280 Section 4.1.1.2]: https://tools.ietf.org/html/rfc5280#section-4.1.1.2
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct AlgorithmIdentifier<Params> {
    /// Algorithm OID, i.e. the `algorithm` field in the `AlgorithmIdentifier`
    /// ASN.1 schema.
    pub oid: ObjectIdentifier,

    /// Algorithm `parameters`.
    pub parameters: Option<Params>,
}

impl<'a, Params> DecodeValue<'a> for AlgorithmIdentifier<Params>
where
    Params: Choice<'a>,
{
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            Ok(Self {
                oid: reader.decode()?,
                parameters: reader.decode()?,
            })
        })
    }
}

impl<'a, Params> Sequence<'a> for AlgorithmIdentifier<Params>
where
    Params: Choice<'a> + Encode,
{
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encode]) -> der::Result<T>,
    {
        f(&[&self.oid, &self.parameters])
    }
}

impl<'a, Params> TryFrom<&'a [u8]> for AlgorithmIdentifier<Params>
where
    Params: Choice<'a> + Encode,
{
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(Self::from_der(bytes)?)
    }
}

impl<Params> ValueOrd for AlgorithmIdentifier<Params>
where
    Params: DerOrd,
{
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        match self.oid.der_cmp(&other.oid)? {
            Ordering::Equal => self.parameters.der_cmp(&other.parameters),
            other => Ok(other),
        }
    }
}

/// `AlgorithmIdentifier` reference which has `AnyRef` parameters.
pub type AlgorithmIdentifierRef<'a> = AlgorithmIdentifier<AnyRef<'a>>;

/// `AlgorithmIdentifierOwned` reference which has `Any` parameters.
#[cfg(feature = "alloc")]
pub type AlgorithmIdentifierOwned = AlgorithmIdentifier<Any>;

impl<'a> AlgorithmIdentifierRef<'a> {
    /// Assert the `algorithm` OID is an expected value.
    pub fn assert_algorithm_oid(&self, expected_oid: ObjectIdentifier) -> Result<ObjectIdentifier> {
        if self.oid == expected_oid {
            Ok(expected_oid)
        } else {
            Err(Error::OidUnknown { oid: expected_oid })
        }
    }

    /// Assert `parameters` is an OID and has the expected value.
    pub fn assert_parameters_oid(
        &self,
        expected_oid: ObjectIdentifier,
    ) -> Result<ObjectIdentifier> {
        let actual_oid = self.parameters_oid()?;

        if actual_oid == expected_oid {
            Ok(actual_oid)
        } else {
            Err(Error::OidUnknown { oid: expected_oid })
        }
    }

    /// Assert the values of the `algorithm` and `parameters` OIDs.
    pub fn assert_oids(
        &self,
        algorithm: ObjectIdentifier,
        parameters: ObjectIdentifier,
    ) -> Result<()> {
        self.assert_algorithm_oid(algorithm)?;
        self.assert_parameters_oid(parameters)?;
        Ok(())
    }

    /// Get the `parameters` field as an [`AnyRef`].
    ///
    /// Returns an error if `parameters` are `None`.
    pub fn parameters_any(&self) -> Result<AnyRef<'a>> {
        self.parameters.ok_or(Error::AlgorithmParametersMissing)
    }

    /// Get the `parameters` field as an [`ObjectIdentifier`].
    ///
    /// Returns an error if it is absent or not an OID.
    pub fn parameters_oid(&self) -> Result<ObjectIdentifier> {
        Ok(ObjectIdentifier::try_from(self.parameters_any()?)?)
    }

    /// Convert to a pair of [`ObjectIdentifier`]s.
    ///
    /// This method is helpful for decomposing in match statements. Note in
    /// particular that `NULL` parameters are treated the same as missing
    /// parameters.
    ///
    /// Returns an error if parameters are present but not an OID.
    pub fn oids(&self) -> der::Result<(ObjectIdentifier, Option<ObjectIdentifier>)> {
        Ok((
            self.oid,
            match self.parameters {
                None => None,
                Some(p) => match p {
                    AnyRef::NULL => None,
                    _ => Some(p.oid()?),
                },
            },
        ))
    }

    /// Convert to an [`AlgorithmIdentifierOwned`]
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifier {
            oid: self.oid,
            parameters: self.parameters.map(|p| p.into()),
        }
    }
}
