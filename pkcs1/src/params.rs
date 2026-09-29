//! PKCS#1 RSA parameters.

use crate::{Error, Result};
#[cfg(feature = "alloc")]
use der::Any;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Length, Reader, Sequence, Tag, TagMode,
    TagNumber, Writer,
    asn1::{AnyRef, ContextSpecificRef, ObjectIdentifier},
    oid::AssociatedOid,
};
use spki::{AlgorithmIdentifier, AlgorithmIdentifierRef, AsAlgorithmIdentifierRef};

const OID_SHA_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_MGF_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
const OID_PSPECIFIED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.9");

const SHA_1_AI: AlgorithmIdentifierRef<'_> = AlgorithmIdentifierRef {
    oid: OID_SHA_1,
    parameters: Some(AnyRef::NULL),
};

/// `TrailerField` as defined in [RFC 8017 Appendix 2.3].
/// ```text
/// TrailerField ::= INTEGER { trailerFieldBC(1) }
/// ```
/// [RFC 8017 Appendix 2.3]: https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.2.3
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum TrailerField {
    /// the only supported value (0xbc, default)
    #[default]
    BC = 1,
}

impl<'a> DecodeValue<'a> for TrailerField {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        match u8::decode_value(reader, header)? {
            1 => Ok(TrailerField::BC),
            _ => Err(reader.error(Self::TAG.value_error())),
        }
    }
}

impl EncodeValue for TrailerField {
    fn value_len(&self) -> der::Result<Length> {
        Ok(Length::ONE)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        (*self as u8).encode_value(writer)
    }
}

impl FixedTag for TrailerField {
    const TAG: Tag = Tag::Integer;
}

/// PKCS#1 RSASSA-PSS parameters as defined in [RFC 8017 Appendix 2.3]
pub type RsaPssParamsRef<'a> = RsaPssParams<AnyRef<'a>>;

/// PKCS#1 RSASSA-PSS parameters as defined in [RFC 8017 Appendix 2.3]
#[cfg(feature = "alloc")]
pub type RsaPssParamsOwned = RsaPssParams<Any>;

/// PKCS#1 RSASSA-PSS parameters as defined in [RFC 8017 Appendix 2.3]
///
/// ASN.1 structure containing a serialized RSASSA-PSS parameters:
/// ```text
/// RSASSA-PSS-params ::= SEQUENCE {
///     hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
///     maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
///     saltLength         [2] INTEGER            DEFAULT 20,
///     trailerField       [3] TrailerField       DEFAULT trailerFieldBC
/// }
/// HashAlgorithm ::= AlgorithmIdentifier
/// MaskGenAlgorithm ::= AlgorithmIdentifier
/// ```
///
/// [RFC 8017 Appendix 2.3]: https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.2.3
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RsaPssParams<Params> {
    /// Hash Algorithm
    pub hash: AlgorithmIdentifier<Params>,

    /// Mask Generation Function (MGF)
    pub mask_gen: AlgorithmIdentifier<AlgorithmIdentifier<Params>>,

    /// Salt length
    pub salt_len: u8,

    /// Trailer field (i.e. [`TrailerField::BC`])
    pub trailer_field: TrailerField,
}

impl<Params> RsaPssParams<Params> {
    /// Default RSA PSS Salt length in RsaPssParams
    pub const SALT_LEN_DEFAULT: u8 = 20;

    fn context_specific_salt_len(&self) -> Option<ContextSpecificRef<'_, u8>> {
        if self.salt_len == Self::SALT_LEN_DEFAULT {
            None
        } else {
            Some(ContextSpecificRef {
                tag_number: TagNumber(2),
                tag_mode: TagMode::Explicit,
                value: &self.salt_len,
            })
        }
    }

    fn context_specific_trailer_field(&self) -> Option<ContextSpecificRef<'_, TrailerField>> {
        if self.trailer_field == TrailerField::default() {
            None
        } else {
            Some(ContextSpecificRef {
                tag_number: TagNumber(3),
                tag_mode: TagMode::Explicit,
                value: &self.trailer_field,
            })
        }
    }
}

impl<'a> RsaPssParamsRef<'a> {
    /// Create new [`RsaPssParams`] for the provided digest and salt len
    pub fn new<D>(salt_len: u8) -> Self
    where
        D: AssociatedOid,
    {
        Self {
            hash: AlgorithmIdentifierRef {
                oid: D::OID,
                parameters: Some(AnyRef::NULL),
            },
            mask_gen: AlgorithmIdentifier {
                oid: OID_MGF_1,
                parameters: Some(AlgorithmIdentifierRef {
                    oid: D::OID,
                    parameters: Some(AnyRef::NULL),
                }),
            },
            salt_len,
            trailer_field: Default::default(),
        }
    }
}

impl<Params> RsaPssParams<Params>
where
    AlgorithmIdentifier<Params>: AsAlgorithmIdentifierRef,
    AlgorithmIdentifier<Params>: From<AlgorithmIdentifier<AnyRef<'static>>>,
    Params: PartialEq,
{
    fn context_specific_hash(&self) -> Option<ContextSpecificRef<'_, AlgorithmIdentifier<Params>>> {
        if self.hash.as_algo_ref() == SHA_1_AI {
            None
        } else {
            Some(ContextSpecificRef {
                tag_number: TagNumber(0),
                tag_mode: TagMode::Explicit,
                value: &self.hash,
            })
        }
    }

    fn context_specific_mask_gen(
        &self,
    ) -> Option<ContextSpecificRef<'_, AlgorithmIdentifier<AlgorithmIdentifier<Params>>>> {
        if self.mask_gen == default_mgf1_sha1::<Params>() {
            None
        } else {
            Some(ContextSpecificRef {
                tag_number: TagNumber(1),
                tag_mode: TagMode::Explicit,
                value: &self.mask_gen,
            })
        }
    }
}

impl<Params> Default for RsaPssParams<Params>
where
    AlgorithmIdentifier<Params>: From<AlgorithmIdentifierRef<'static>>,
{
    fn default() -> Self {
        Self {
            hash: SHA_1_AI.into(),
            mask_gen: default_mgf1_sha1(),
            salt_len: RsaPssParams::<Params>::SALT_LEN_DEFAULT,
            trailer_field: Default::default(),
        }
    }
}

impl<'a, Params> DecodeValue<'a> for RsaPssParams<Params>
where
    AlgorithmIdentifier<Params>: DecodeValue<'a, Error = der::Error> + FixedTag,
    AlgorithmIdentifier<AlgorithmIdentifier<Params>>:
        DecodeValue<'a, Error = der::Error> + FixedTag,
    AlgorithmIdentifier<Params>: From<AlgorithmIdentifierRef<'static>>,
    Params: 'a,
{
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        Ok(Self {
            hash: reader
                .context_specific(TagNumber(0), TagMode::Explicit)?
                .unwrap_or_else(|| SHA_1_AI.into()),
            mask_gen: reader
                .context_specific(TagNumber(1), TagMode::Explicit)?
                .unwrap_or_else(default_mgf1_sha1),
            salt_len: reader
                .context_specific(TagNumber(2), TagMode::Explicit)?
                .unwrap_or(RsaPssParams::<Params>::SALT_LEN_DEFAULT),
            trailer_field: reader
                .context_specific(TagNumber(3), TagMode::Explicit)?
                .unwrap_or_default(),
        })
    }
}

impl<Params> EncodeValue for RsaPssParams<Params>
where
    AlgorithmIdentifier<Params>: AsAlgorithmIdentifierRef,
    for<'b> Option<ContextSpecificRef<'b, AlgorithmIdentifier<Params>>>: Encode,
    for<'b> Option<ContextSpecificRef<'b, AlgorithmIdentifier<AlgorithmIdentifier<Params>>>>:
        Encode,
    AlgorithmIdentifier<Params>: From<AlgorithmIdentifierRef<'static>>,
    Params: PartialEq,
{
    fn value_len(&self) -> der::Result<Length> {
        self.context_specific_hash().encoded_len()?
            + self.context_specific_mask_gen().encoded_len()?
            + self.context_specific_salt_len().encoded_len()?
            + self.context_specific_trailer_field().encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.context_specific_hash().encode(writer)?;
        self.context_specific_mask_gen().encode(writer)?;
        self.context_specific_salt_len().encode(writer)?;
        self.context_specific_trailer_field().encode(writer)?;
        Ok(())
    }
}

impl<'a, Params> Sequence<'a> for RsaPssParams<Params> {}

impl<'a, Params> TryFrom<&'a [u8]> for RsaPssParams<Params>
where
    AlgorithmIdentifier<Params>: DecodeValue<'a, Error = der::Error> + FixedTag,
    AlgorithmIdentifier<AlgorithmIdentifier<Params>>:
        DecodeValue<'a, Error = der::Error> + FixedTag,
    AlgorithmIdentifier<Params>: From<AlgorithmIdentifierRef<'static>>,
    Params: 'a,
{
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(Self::from_der(bytes)?)
    }
}

/// Default Mask Generation Function (MGF): SHA-1.
fn default_mgf1_sha1<Params>() -> AlgorithmIdentifier<AlgorithmIdentifier<Params>>
where
    AlgorithmIdentifier<Params>: From<AlgorithmIdentifierRef<'static>>,
{
    AlgorithmIdentifier::<AlgorithmIdentifier<Params>> {
        oid: OID_MGF_1,
        parameters: Some(SHA_1_AI.into()),
    }
}

/// [`RsaOaepParams`] with [`AlgorithmIdentifier<AnyRef>`]
pub type RsaOaepParamsRef<'a> = RsaOaepParams<AnyRef<'a>>;

/// [`RsaOaepParams`] with allocating [`AlgorithmIdentifier<Any>`]
#[cfg(feature = "alloc")]
pub type RsaOaepParamsOwned = RsaOaepParams<Any>;

/// PKCS#1 RSAES-OAEP parameters as defined in [RFC 8017 Appendix 2.1]
///
/// ASN.1 structure containing a serialized RSAES-OAEP parameters:
/// ```text
/// RSAES-OAEP-params ::= SEQUENCE {
///     hashAlgorithm      [0] HashAlgorithm     DEFAULT sha1,
///     maskGenAlgorithm   [1] MaskGenAlgorithm  DEFAULT mgf1SHA1,
///     pSourceAlgorithm   [2] PSourceAlgorithm  DEFAULT pSpecifiedEmpty
/// }
/// HashAlgorithm ::= AlgorithmIdentifier
/// MaskGenAlgorithm ::= AlgorithmIdentifier
/// PSourceAlgorithm ::= AlgorithmIdentifier
/// ```
///
/// [RFC 8017 Appendix 2.1]: https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.2.1
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RsaOaepParams<Params> {
    /// Hash Algorithm
    pub hash: AlgorithmIdentifier<Params>,

    /// Mask Generation Function (MGF)
    pub mask_gen: AlgorithmIdentifier<AlgorithmIdentifier<Params>>,

    /// The source (and possibly the value) of the label L
    pub p_source: AlgorithmIdentifier<Params>,
}

impl<Params> RsaOaepParams<Params>
where
    AlgorithmIdentifier<Params>: AsAlgorithmIdentifierRef,
{
    fn context_specific_hash(&self) -> Option<ContextSpecificRef<'_, AlgorithmIdentifier<Params>>> {
        if self.hash.as_algo_ref() == SHA_1_AI {
            None
        } else {
            Some(ContextSpecificRef {
                tag_number: TagNumber(0),
                tag_mode: TagMode::Explicit,
                value: &self.hash,
            })
        }
    }

    fn context_specific_p_source(
        &self,
    ) -> Option<ContextSpecificRef<'_, AlgorithmIdentifier<Params>>> {
        if self.p_source.as_algo_ref() == default_pempty_string() {
            None
        } else {
            Some(ContextSpecificRef {
                tag_number: TagNumber(2),
                tag_mode: TagMode::Explicit,
                value: &self.p_source,
            })
        }
    }
}

impl<Params> RsaOaepParams<Params>
where
    AlgorithmIdentifier<Params>: AsAlgorithmIdentifierRef,
    AlgorithmIdentifier<Params>: From<AlgorithmIdentifierRef<'static>>,
    Params: PartialEq,
{
    fn context_specific_mask_gen(
        &self,
    ) -> Option<ContextSpecificRef<'_, AlgorithmIdentifier<AlgorithmIdentifier<Params>>>> {
        if self.mask_gen == default_mgf1_sha1::<Params>() {
            None
        } else {
            Some(ContextSpecificRef {
                tag_number: TagNumber(1),
                tag_mode: TagMode::Explicit,
                value: &self.mask_gen,
            })
        }
    }
}

impl<'a> RsaOaepParamsRef<'a> {
    /// Create new [`RsaOaepParams`] for the provided digest and default (empty) label
    pub fn new<D>() -> Self
    where
        D: AssociatedOid,
    {
        Self::new_with_label::<D>(&[])
    }

    /// Create new [`RsaOaepParams`] for the provided digest and specified label
    pub fn new_with_label<D>(label: &'a impl AsRef<[u8]>) -> RsaOaepParamsRef<'a>
    where
        D: AssociatedOid,
    {
        Self {
            hash: AlgorithmIdentifier {
                oid: D::OID,
                parameters: Some(AnyRef::NULL),
            },
            mask_gen: AlgorithmIdentifier {
                oid: OID_MGF_1,
                parameters: Some(AlgorithmIdentifier {
                    oid: D::OID,
                    parameters: Some(AnyRef::NULL),
                }),
            },
            p_source: pspecified_algorithm_identifier(label),
        }
    }
}

impl<Params> Default for RsaOaepParams<Params>
where
    AlgorithmIdentifier<Params>: From<AlgorithmIdentifierRef<'static>>,
{
    fn default() -> Self {
        Self {
            hash: SHA_1_AI.into(),
            mask_gen: default_mgf1_sha1(),
            p_source: default_pempty_string().into(),
        }
    }
}

impl<'a, Params> DecodeValue<'a> for RsaOaepParams<Params>
where
    AlgorithmIdentifier<Params>: DecodeValue<'a, Error = der::Error> + FixedTag,
    AlgorithmIdentifier<AlgorithmIdentifier<Params>>:
        DecodeValue<'a, Error = der::Error> + FixedTag,
    AlgorithmIdentifier<Params>: From<AlgorithmIdentifierRef<'static>>,
    Params: 'a,
{
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        Ok(Self {
            hash: reader
                .context_specific(TagNumber(0), TagMode::Explicit)?
                .unwrap_or_else(|| SHA_1_AI.into()),
            mask_gen: reader
                .context_specific(TagNumber(1), TagMode::Explicit)?
                .unwrap_or_else(default_mgf1_sha1),
            p_source: reader
                .context_specific(TagNumber(2), TagMode::Explicit)?
                .unwrap_or_else(|| default_pempty_string().into()),
        })
    }
}

impl<Params> EncodeValue for RsaOaepParams<Params>
where
    AlgorithmIdentifier<Params>: AsAlgorithmIdentifierRef,
    for<'b> Option<ContextSpecificRef<'b, AlgorithmIdentifier<Params>>>: Encode,
    for<'b> Option<ContextSpecificRef<'b, AlgorithmIdentifier<AlgorithmIdentifier<Params>>>>:
        Encode,
    AlgorithmIdentifier<Params>: From<AlgorithmIdentifierRef<'static>>,
    Params: PartialEq,
{
    fn value_len(&self) -> der::Result<Length> {
        self.context_specific_hash().encoded_len()?
            + self.context_specific_mask_gen().encoded_len()?
            + self.context_specific_p_source().encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.context_specific_hash().encode(writer)?;
        self.context_specific_mask_gen().encode(writer)?;
        self.context_specific_p_source().encode(writer)?;
        Ok(())
    }
}

impl<'a, Params> Sequence<'a> for RsaOaepParams<Params> {}

impl<'a, Params> TryFrom<&'a [u8]> for RsaOaepParams<Params>
where
    AlgorithmIdentifier<Params>: DecodeValue<'a, Error = der::Error> + FixedTag,
    AlgorithmIdentifier<AlgorithmIdentifier<Params>>:
        DecodeValue<'a, Error = der::Error> + FixedTag,
    AlgorithmIdentifier<Params>: From<AlgorithmIdentifierRef<'static>>,
    Params: 'a,
{
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(Self::from_der(bytes)?)
    }
}

fn pspecified_algorithm_identifier(label: &impl AsRef<[u8]>) -> AlgorithmIdentifierRef<'_> {
    AlgorithmIdentifierRef {
        oid: OID_PSPECIFIED,
        parameters: Some(
            AnyRef::new(Tag::OctetString, label.as_ref()).expect("error creating OAEP params"),
        ),
    }
}

/// Default Source Algorithm, empty string
fn default_pempty_string<'a>() -> AlgorithmIdentifierRef<'a> {
    pspecified_algorithm_identifier(&[])
}
