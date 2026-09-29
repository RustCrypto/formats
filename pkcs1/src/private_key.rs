//! PKCS#1 RSA Private Keys.

#[cfg(feature = "alloc")]
pub(crate) mod other_prime_info;

use crate::{Error, Result, RsaPublicKeyRef, Version};
use core::fmt;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence, Tag, Writer,
    asn1::{AsUintRef, OctetStringRef, UintRef},
};

#[cfg(feature = "alloc")]
use {self::other_prime_info::OtherPrimeInfo, alloc::vec::Vec, der::SecretDocument};

#[cfg(feature = "alloc")]
use der::asn1::Uint;

#[cfg(feature = "pem")]
use der::pem::PemLabel;

/// PKCS#1 RSA Private Keys as defined in [RFC 8017 Appendix 1.2].
pub type RsaPrivateKeyRef<'a> = RsaPrivateKey<UintRef<'a>>;

/// PKCS#1 RSA Private Keys as defined in [RFC 8017 Appendix 1.2].
#[cfg(feature = "alloc")]
pub type RsaPrivateKeyOwned = RsaPrivateKey<Uint>;

/// PKCS#1 RSA Private Keys as defined in [RFC 8017 Appendix 1.2].
///
/// ASN.1 structure containing a serialized RSA private key:
///
/// ```text
/// RSAPrivateKey ::= SEQUENCE {
///     version           Version,
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER,  -- e
///     privateExponent   INTEGER,  -- d
///     prime1            INTEGER,  -- p
///     prime2            INTEGER,  -- q
///     exponent1         INTEGER,  -- d mod (p-1)
///     exponent2         INTEGER,  -- d mod (q-1)
///     coefficient       INTEGER,  -- (inverse of q) mod p
///     otherPrimeInfos   OtherPrimeInfos OPTIONAL
/// }
/// ```
///
/// Note: the `version` field is selected automatically based on the absence or
/// presence of the `other_prime_infos` field.
///
/// [RFC 8017 Appendix 1.2]: https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.2
#[derive(Clone)]
pub struct RsaPrivateKey<U> {
    /// `n`: RSA modulus.
    pub modulus: U,

    /// `e`: RSA public exponent.
    pub public_exponent: U,

    /// `d`: RSA private exponent.
    pub private_exponent: U,

    /// `p`: first prime factor of `n`.
    pub prime1: U,

    /// `q`: Second prime factor of `n`.
    pub prime2: U,

    /// First exponent: `d mod (p-1)`.
    pub exponent1: U,

    /// Second exponent: `d mod (q-1)`.
    pub exponent2: U,

    /// CRT coefficient: `(inverse of q) mod p`.
    pub coefficient: U,

    /// Additional primes `r_3`, ..., `r_u`, in order, if this is a multi-prime
    /// RSA key (i.e. `version` is `multi`).
    pub other_prime_infos: Option<OtherPrimeInfos<U>>,
}

impl<U> RsaPrivateKey<U>
where
    U: AsUintRef,
{
    /// Get the public key that corresponds to this [`RsaPrivateKey`].
    pub fn public_key<'a>(&'a self) -> RsaPublicKeyRef<'a> {
        RsaPublicKeyRef {
            modulus: self.modulus.as_uint_ref(),
            public_exponent: self.public_exponent.as_uint_ref(),
        }
    }
}

impl<U> RsaPrivateKey<U> {
    /// Get the [`Version`] for this key.
    ///
    /// Determined by the presence or absence of the
    /// [`RsaPrivateKey::other_prime_infos`] field.
    pub fn version(&self) -> Version {
        if self.other_prime_infos.is_some() {
            Version::Multi
        } else {
            Version::TwoPrime
        }
    }
}

impl<'a, U> DecodeValue<'a> for RsaPrivateKey<U>
where
    U: Decode<'a, Error = der::Error>,
{
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let version = Version::decode(reader)?;

        let result = Self {
            modulus: reader.decode()?,
            public_exponent: reader.decode()?,
            private_exponent: reader.decode()?,
            prime1: reader.decode()?,
            prime2: reader.decode()?,
            exponent1: reader.decode()?,
            exponent2: reader.decode()?,
            coefficient: reader.decode()?,
            other_prime_infos: reader.decode()?,
        };

        // Ensure version is set correctly for two-prime vs multi-prime key.
        if version.is_multi() != result.other_prime_infos.is_some() {
            return Err(reader.error(der::ErrorKind::Value { tag: Tag::Integer }));
        }

        Ok(result)
    }
}

impl<U> EncodeValue for RsaPrivateKey<U>
where
    U: Encode,
{
    fn value_len(&self) -> der::Result<Length> {
        self.version().encoded_len()?
            + self.modulus.encoded_len()?
            + self.public_exponent.encoded_len()?
            + self.private_exponent.encoded_len()?
            + self.prime1.encoded_len()?
            + self.prime2.encoded_len()?
            + self.exponent1.encoded_len()?
            + self.exponent2.encoded_len()?
            + self.coefficient.encoded_len()?
            + self.other_prime_infos.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.version().encode(writer)?;
        self.modulus.encode(writer)?;
        self.public_exponent.encode(writer)?;
        self.private_exponent.encode(writer)?;
        self.prime1.encode(writer)?;
        self.prime2.encode(writer)?;
        self.exponent1.encode(writer)?;
        self.exponent2.encode(writer)?;
        self.coefficient.encode(writer)?;
        self.other_prime_infos.encode(writer)?;
        Ok(())
    }
}

impl<U> Sequence<'_> for RsaPrivateKey<U> {}

impl<'a, U> From<&'a RsaPrivateKey<U>> for RsaPublicKeyRef<'a>
where
    U: AsUintRef,
{
    fn from(private_key: &'a RsaPrivateKey<U>) -> RsaPublicKeyRef<'a> {
        private_key.public_key()
    }
}

impl<'a, U> TryFrom<&'a [u8]> for RsaPrivateKey<U>
where
    U: Decode<'a, Error = der::Error>,
{
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(Self::from_der(bytes)?)
    }
}

impl<'a, U> TryFrom<&'a OctetStringRef> for RsaPrivateKey<U>
where
    U: Decode<'a, Error = der::Error>,
{
    type Error = Error;

    fn try_from(bytes: &'a OctetStringRef) -> Result<Self> {
        Ok(Self::from_der(bytes.as_bytes())?)
    }
}

impl<U> fmt::Debug for RsaPrivateKey<U>
where
    U: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPrivateKey")
            .field("version", &self.version())
            .field("modulus", &self.modulus)
            .field("public_exponent", &self.public_exponent)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "alloc")]
impl<U> TryFrom<RsaPrivateKey<U>> for SecretDocument
where
    U: Encode,
{
    type Error = Error;

    fn try_from(private_key: RsaPrivateKey<U>) -> Result<SecretDocument> {
        SecretDocument::try_from(&private_key)
    }
}

#[cfg(feature = "alloc")]
impl<U> TryFrom<&RsaPrivateKey<U>> for SecretDocument
where
    U: Encode,
{
    type Error = Error;

    fn try_from(private_key: &RsaPrivateKey<U>) -> Result<SecretDocument> {
        Ok(Self::encode_msg(private_key)?)
    }
}

#[cfg(feature = "pem")]
impl<U> PemLabel for RsaPrivateKey<U> {
    const PEM_LABEL: &'static str = "RSA PRIVATE KEY";
}

/// Placeholder struct for `OtherPrimeInfos` in the no-`alloc` case.
///
/// This type is unconstructable by design, but supports the same traits.
#[cfg(not(feature = "alloc"))]
#[derive(Clone)]
#[non_exhaustive]
pub struct OtherPrimeInfos<U> {
    _marker: core::marker::PhantomData<U>,
}

#[cfg(not(feature = "alloc"))]
impl<'a, U> DecodeValue<'a> for OtherPrimeInfos<U> {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        // Placeholder decoder that always returns an error.
        // Uses `Tag::Integer` to signal an unsupported version.
        Err(reader.error(der::ErrorKind::Value { tag: Tag::Integer }))
    }
}

#[cfg(not(feature = "alloc"))]
impl<U> EncodeValue for OtherPrimeInfos<U> {
    fn value_len(&self) -> der::Result<Length> {
        // Placeholder decoder that always returns an error.
        // Uses `Tag::Integer` to signal an unsupported version.
        Err(der::ErrorKind::Value { tag: Tag::Integer }.into())
    }

    fn encode_value(&self, _writer: &mut impl Writer) -> der::Result<()> {
        // Placeholder decoder that always returns an error.
        // Uses `Tag::Integer` to signal an unsupported version.
        Err(der::ErrorKind::Value { tag: Tag::Integer }.into())
    }
}

#[cfg(not(feature = "alloc"))]
impl<U> der::FixedTag for OtherPrimeInfos<U> {
    const TAG: Tag = Tag::Sequence;
}

/// Additional RSA prime info in a multi-prime RSA key.
#[cfg(feature = "alloc")]
pub type OtherPrimeInfos<U> = Vec<OtherPrimeInfo<U>>;
