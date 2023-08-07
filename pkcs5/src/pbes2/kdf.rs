//! Key derivation functions.

use crate::{AlgorithmIdentifierRef, Error, Result};
use der::{
    asn1::{AnyRef, ObjectIdentifier, OctetStringRef},
    Decode, DecodeValue, Encode, EncodeValue, ErrorKind, Length, Reader, Sequence, Tag, Tagged,
    Writer,
};

/// Password-Based Key Derivation Function (PBKDF2) OID.
pub const PBKDF2_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.12");

/// HMAC-SHA1 (for use with PBKDF2)
pub const HMAC_WITH_SHA1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.7");

/// HMAC-SHA-224 (for use with PBKDF2)
pub const HMAC_WITH_SHA224_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.2.8");

/// HMAC-SHA-256 (for use with PBKDF2)
pub const HMAC_WITH_SHA256_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.2.9");

/// HMAC-SHA-384 (for use with PBKDF2)
pub const HMAC_WITH_SHA384_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.2.10");

/// HMAC-SHA-512 (for use with PBKDF2)
pub const HMAC_WITH_SHA512_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.2.11");

/// `id-scrypt` ([RFC 7914])
///
/// [RFC 7914]: https://datatracker.ietf.org/doc/html/rfc7914#section-7
pub const SCRYPT_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11591.4.11");

/// Type used for expressing scrypt cost
type ScryptCost = u64;

/// Password-based key derivation function.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KdfInner<Salt> {
    /// Password-Based Key Derivation Function 2 (PBKDF2).
    Pbkdf2(Pbkdf2ParamsInner<Salt>),

    /// scrypt sequential memory-hard password hashing function.
    Scrypt(ScryptParamsInner<Salt>),
}

impl<Salt> KdfInner<Salt> {
    /// Get derived key length in bytes, if defined.
    // TODO(tarcieri): rename to `key_size` to match `EncryptionScheme::key_size`?
    pub fn key_length(&self) -> Option<u16> {
        match self {
            Self::Pbkdf2(params) => params.key_length,
            Self::Scrypt(params) => params.key_length,
        }
    }

    /// Get the [`ObjectIdentifier`] (a.k.a OID) for this algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            Self::Pbkdf2(_) => PBKDF2_OID,
            Self::Scrypt(_) => SCRYPT_OID,
        }
    }

    /// Get [`Pbkdf2Params`] if it is the selected algorithm.
    pub fn pbkdf2(&self) -> Option<&Pbkdf2ParamsInner<Salt>> {
        match self {
            Self::Pbkdf2(params) => Some(params),
            _ => None,
        }
    }

    /// Get [`ScryptParams`] if it is the selected algorithm.
    pub fn scrypt(&self) -> Option<&ScryptParamsInner<Salt>> {
        match self {
            Self::Scrypt(params) => Some(params),
            _ => None,
        }
    }

    /// Is the selected KDF PBKDF2?
    pub fn is_pbkdf2(&self) -> bool {
        self.pbkdf2().is_some()
    }

    /// Is the selected KDF scrypt?
    pub fn is_scrypt(&self) -> bool {
        self.scrypt().is_some()
    }

    /// Convenience function to turn the OID (see [`oid`](Self::oid))
    /// of this [`Kdf`] into error case [`Error::AlgorithmParametersInvalid`]
    pub fn to_alg_params_invalid(&self) -> Error {
        Error::AlgorithmParametersInvalid { oid: self.oid() }
    }
}

impl<'a, Salt> DecodeValue<'a> for KdfInner<Salt>
where
    Salt: From<&'a [u8]>,
{
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        AlgorithmIdentifierRef::decode_value(reader, header)?.try_into()
    }
}

impl<'a, Salt> EncodeValue for KdfInner<Salt>
where
    Salt: AsRef<[u8]> + From<&'a [u8]>,
{
    fn value_len(&self) -> der::Result<Length> {
        self.oid().encoded_len()?
            + match self {
                Self::Pbkdf2(params) => params.encoded_len()?,
                Self::Scrypt(params) => params.encoded_len()?,
            }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.oid().encode(writer)?;

        match self {
            Self::Pbkdf2(params) => params.encode(writer)?,
            Self::Scrypt(params) => params.encode(writer)?,
        }

        Ok(())
    }
}

impl<'a, Salt> Sequence<'a> for KdfInner<Salt> where Salt: AsRef<[u8]> + From<&'a [u8]> {}

impl<Salt> From<Pbkdf2ParamsInner<Salt>> for KdfInner<Salt> {
    fn from(params: Pbkdf2ParamsInner<Salt>) -> Self {
        Self::Pbkdf2(params)
    }
}

impl<Salt> From<ScryptParamsInner<Salt>> for KdfInner<Salt> {
    fn from(params: ScryptParamsInner<Salt>) -> Self {
        Self::Scrypt(params)
    }
}

impl<'a, Salt> TryFrom<AlgorithmIdentifierRef<'a>> for KdfInner<Salt>
where
    Salt: From<&'a [u8]>,
{
    type Error = der::Error;

    fn try_from(alg: AlgorithmIdentifierRef<'a>) -> der::Result<Self> {
        if let Some(params) = alg.parameters {
            match alg.oid {
                PBKDF2_OID => params.try_into().map(Self::Pbkdf2),
                SCRYPT_OID => params.try_into().map(Self::Scrypt),
                oid => Err(ErrorKind::OidUnknown { oid }.into()),
            }
        } else {
            Err(Tag::OctetString.value_error())
        }
    }
}

/// [`KdfInner`] with `&[u8]` salt.
pub type Kdf<'a> = KdfInner<&'a [u8]>;

/// Password-Based Key Derivation Scheme 2 parameters as defined in
/// [RFC 8018 Appendix A.2].
///
/// ```text
/// PBKDF2-params ::= SEQUENCE {
///     salt CHOICE {
///         specified OCTET STRING,
///         otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
///     },
///     iterationCount INTEGER (1..MAX),
///     keyLength INTEGER (1..MAX) OPTIONAL,
///     prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT
///     algid-hmacWithSHA1 }
/// ```
///
/// [RFC 8018 Appendix A.2]: https://tools.ietf.org/html/rfc8018#appendix-A.2
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Pbkdf2ParamsInner<Salt> {
    /// PBKDF2 salt
    // TODO(tarcieri): support `CHOICE` with `otherSource`
    pub salt: Salt,

    /// PBKDF2 iteration count
    pub iteration_count: u32,

    /// PBKDF2 output length
    pub key_length: Option<u16>,

    /// Pseudo-random function to use with PBKDF2
    pub prf: Pbkdf2Prf,
}

impl<Salt> Pbkdf2ParamsInner<Salt> {
    /// Implementation defined maximum iteration count of 100,000,000.
    ///
    /// > For especially critical keys, or
    /// > for very powerful systems or systems where user-perceived
    /// > performance is not critical, an iteration count of 10,000,000 may
    /// > be appropriate.
    ///
    /// See [RFC 8018, §4.2](https://datatracker.ietf.org/doc/html/rfc8018#section-4.2)
    /// and [RFC 8018, §A.2](https://datatracker.ietf.org/doc/html/rfc8018#appendix-A.2)
    pub const MAX_ITERATION_COUNT: u32 = 100_000_000;

    const INVALID_ERR: Error = Error::AlgorithmParametersInvalid { oid: PBKDF2_OID };

    /// Initialize PBKDF2-SHA256 with the given iteration count and salt
    pub fn hmac_with_sha256(iteration_count: u32, salt: Salt) -> Result<Self> {
        if iteration_count > Self::MAX_ITERATION_COUNT {
            return Err(Self::INVALID_ERR);
        }
        Ok(Self {
            salt,
            iteration_count,
            key_length: None,
            prf: Pbkdf2Prf::HmacWithSha256,
        })
    }
}

impl<'a, Salt> DecodeValue<'a> for Pbkdf2ParamsInner<Salt>
where
    Salt: From<&'a [u8]>,
{
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        AnyRef::decode_value(reader, header)?.try_into()
    }
}

impl<'a, Salt> EncodeValue for Pbkdf2ParamsInner<Salt>
where
    Salt: AsRef<[u8]> + From<&'a [u8]>,
{
    fn value_len(&self) -> der::Result<Length> {
        let len = OctetStringRef::new(self.salt.as_ref())?.encoded_len()?
            + self.iteration_count.encoded_len()?
            + self.key_length.encoded_len()?;

        if self.prf == Pbkdf2Prf::default() {
            len
        } else {
            len + self.prf.encoded_len()?
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        OctetStringRef::new(self.salt.as_ref())?.encode(writer)?;
        self.iteration_count.encode(writer)?;
        self.key_length.encode(writer)?;

        if self.prf == Pbkdf2Prf::default() {
            Ok(())
        } else {
            self.prf.encode(writer)
        }
    }
}

impl<'a, Salt> Sequence<'a> for Pbkdf2ParamsInner<Salt> where Salt: From<&'a [u8]> + AsRef<[u8]> {}

impl<'a, Salt> TryFrom<AnyRef<'a>> for Pbkdf2ParamsInner<Salt>
where
    Salt: From<&'a [u8]>,
{
    type Error = der::Error;

    fn try_from(any: AnyRef<'a>) -> der::Result<Self> {
        any.sequence(|reader| {
            // TODO(tarcieri): support salt `CHOICE` w\ `AlgorithmIdentifier`
            Ok(Self {
                salt: OctetStringRef::decode(reader)?.as_bytes().into(),
                iteration_count: reader.decode()?,
                key_length: reader.decode()?,
                prf: Option::<AlgorithmIdentifierRef<'_>>::decode(reader)?
                    .map(TryInto::try_into)
                    .transpose()?
                    .unwrap_or_default(),
            })
        })
    }
}

/// [`Pbkdf2ParamsInner`] with `&[u8]` salt.
pub type Pbkdf2Params<'a> = Pbkdf2ParamsInner<&'a [u8]>;

/// Pseudo-random function used by PBKDF2.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Pbkdf2Prf {
    /// HMAC with SHA1
    HmacWithSha1,

    /// HMAC with SHA-224
    HmacWithSha224,

    /// HMAC with SHA-256
    HmacWithSha256,

    /// HMAC with SHA-384
    HmacWithSha384,

    /// HMAC with SHA-512
    HmacWithSha512,
}

impl Pbkdf2Prf {
    /// Get the [`ObjectIdentifier`] (a.k.a OID) for this algorithm.
    pub fn oid(self) -> ObjectIdentifier {
        match self {
            Self::HmacWithSha1 => HMAC_WITH_SHA1_OID,
            Self::HmacWithSha224 => HMAC_WITH_SHA224_OID,
            Self::HmacWithSha256 => HMAC_WITH_SHA256_OID,
            Self::HmacWithSha384 => HMAC_WITH_SHA384_OID,
            Self::HmacWithSha512 => HMAC_WITH_SHA512_OID,
        }
    }
}

/// Default PRF as specified in RFC 8018 Appendix A.2:
///
/// ```text
/// prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1
/// ```
///
/// Note that modern usage should avoid the use of SHA-1, despite it being
/// the "default" here.
impl Default for Pbkdf2Prf {
    fn default() -> Self {
        Self::HmacWithSha1
    }
}

impl<'a> TryFrom<AlgorithmIdentifierRef<'a>> for Pbkdf2Prf {
    type Error = der::Error;

    fn try_from(alg: AlgorithmIdentifierRef<'a>) -> der::Result<Self> {
        if let Some(params) = alg.parameters {
            // TODO(tarcieri): support non-NULL parameters?
            if !params.is_null() {
                return Err(params.tag().value_error());
            }
        } else {
            // TODO(tarcieri): support OPTIONAL parameters?
            return Err(Tag::Null.value_error());
        }

        match alg.oid {
            HMAC_WITH_SHA1_OID => Ok(Self::HmacWithSha1),
            HMAC_WITH_SHA224_OID => Ok(Self::HmacWithSha224),
            HMAC_WITH_SHA256_OID => Ok(Self::HmacWithSha256),
            HMAC_WITH_SHA384_OID => Ok(Self::HmacWithSha384),
            HMAC_WITH_SHA512_OID => Ok(Self::HmacWithSha512),
            oid => Err(ErrorKind::OidUnknown { oid }.into()),
        }
    }
}

impl<'a> From<Pbkdf2Prf> for AlgorithmIdentifierRef<'a> {
    fn from(prf: Pbkdf2Prf) -> Self {
        // TODO(tarcieri): support non-NULL parameters?
        let parameters = der::asn1::Null;

        AlgorithmIdentifierRef {
            oid: prf.oid(),
            parameters: Some(parameters.into()),
        }
    }
}

impl Encode for Pbkdf2Prf {
    fn encoded_len(&self) -> der::Result<Length> {
        AlgorithmIdentifierRef::try_from(*self)?.encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> der::Result<()> {
        AlgorithmIdentifierRef::try_from(*self)?.encode(writer)
    }
}

/// scrypt parameters as defined in [RFC 7914 Section 7.1].
///
/// ```text
/// scrypt-params ::= SEQUENCE {
///     salt OCTET STRING,
///     costParameter INTEGER (1..MAX),
///     blockSize INTEGER (1..MAX),
///     parallelizationParameter INTEGER (1..MAX),
///     keyLength INTEGER (1..MAX) OPTIONAL
/// }
/// ```
///
/// [RFC 7914 Section 7.1]: https://datatracker.ietf.org/doc/html/rfc7914#section-7.1
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScryptParamsInner<Salt> {
    /// scrypt salt
    pub salt: Salt,

    /// CPU/Memory cost parameter `N`.
    pub cost_parameter: ScryptCost,

    /// Block size parameter `r`.
    pub block_size: u16,

    /// Parallelization parameter `p`.
    pub parallelization: u16,

    /// PBKDF2 output length
    pub key_length: Option<u16>,
}

impl<Salt> ScryptParamsInner<Salt> {
    #[cfg(feature = "pbes2")]
    const INVALID_ERR: Error = Error::AlgorithmParametersInvalid { oid: SCRYPT_OID };

    /// Get the [`ScryptParams`] for the provided upstream [`scrypt::Params`]
    /// and a provided salt string.
    // TODO(tarcieri): encapsulate `scrypt::Params`?
    #[cfg(feature = "pbes2")]
    pub fn from_params_and_salt(params: scrypt::Params, salt: Salt) -> Result<Self> {
        Ok(Self {
            salt,
            cost_parameter: 1 << params.log_n(),
            block_size: params.r().try_into().map_err(|_| Self::INVALID_ERR)?,
            parallelization: params.p().try_into().map_err(|_| Self::INVALID_ERR)?,
            key_length: None,
        })
    }
}

impl<'a, Salt> DecodeValue<'a> for ScryptParamsInner<Salt>
where
    Salt: From<&'a [u8]>,
{
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        AnyRef::decode_value(reader, header)?.try_into()
    }
}

impl<Salt> EncodeValue for ScryptParamsInner<Salt>
where
    Salt: AsRef<[u8]>,
{
    fn value_len(&self) -> der::Result<Length> {
        OctetStringRef::new(self.salt.as_ref())?.encoded_len()?
            + self.cost_parameter.encoded_len()?
            + self.block_size.encoded_len()?
            + self.parallelization.encoded_len()?
            + self.key_length.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        OctetStringRef::new(self.salt.as_ref())?.encode(writer)?;
        self.cost_parameter.encode(writer)?;
        self.block_size.encode(writer)?;
        self.parallelization.encode(writer)?;
        self.key_length.encode(writer)?;
        Ok(())
    }
}

impl<'a, Salt> Sequence<'a> for ScryptParamsInner<Salt> where Salt: From<&'a [u8]> + AsRef<[u8]> {}

impl<'a, Salt> TryFrom<AnyRef<'a>> for ScryptParamsInner<Salt>
where
    Salt: From<&'a [u8]>,
{
    type Error = der::Error;

    fn try_from(any: AnyRef<'a>) -> der::Result<Self> {
        any.sequence(|reader| {
            Ok(Self {
                salt: OctetStringRef::decode(reader)?.as_bytes().into(),
                cost_parameter: reader.decode()?,
                block_size: reader.decode()?,
                parallelization: reader.decode()?,
                key_length: reader.decode()?,
            })
        })
    }
}

#[cfg(feature = "pbes2")]
impl<Salt> TryFrom<ScryptParamsInner<Salt>> for scrypt::Params {
    type Error = Error;

    fn try_from(params: ScryptParamsInner<Salt>) -> Result<scrypt::Params> {
        scrypt::Params::try_from(&params)
    }
}

#[cfg(feature = "pbes2")]
impl<Salt> TryFrom<&ScryptParamsInner<Salt>> for scrypt::Params {
    type Error = Error;

    fn try_from(params: &ScryptParamsInner<Salt>) -> Result<scrypt::Params> {
        let n = params.cost_parameter;

        // Compute log2 and verify its correctness
        let log_n = ((8 * core::mem::size_of::<ScryptCost>() as u32) - n.leading_zeros() - 1) as u8;

        if 1 << log_n != n {
            return Err(ScryptParamsInner::<Salt>::INVALID_ERR);
        }

        scrypt::Params::new(
            log_n,
            params.block_size.into(),
            params.parallelization.into(),
            scrypt::Params::RECOMMENDED_LEN,
        )
        .map_err(|_| ScryptParamsInner::<Salt>::INVALID_ERR)
    }
}

/// [`ScryptParamsInner`] with `&[u8]` Salt parameter.
pub type ScryptParams<'a> = ScryptParamsInner<&'a [u8]>;
