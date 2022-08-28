//! PKCS#1 RSA parameters.

use crate::{Error, Result};
use der::asn1::{AnyRef, ObjectIdentifier};
use der::{
    asn1::ContextSpecificRef, Decode, DecodeValue, Encode, EncodeValue, FixedTag, Reader, Sequence,
    Tag, TagMode, TagNumber, Writer,
};
use spki::AlgorithmIdentifier;

const OID_SHA_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_MGF_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");

// TODO(tarcieri): make `AlgorithmIdentifier` generic around params; use `OID_SHA_1`
const SEQ_OID_SHA_1_DER: &[u8] = &[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a];

const SHA_1_AI: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: OID_SHA_1,
    parameters: None,
};

const SALT_LEN_DEFAULT: u8 = 20;

/// `TrailerField` as defined in [RFC 8017 Appendix 2.3].
/// ```text
/// TrailerField ::= INTEGER { trailerFieldBC(1) }
/// ```
/// [RFC 8017 Appendix 2.3]: https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.2.3
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrailerField {
    /// the only supported value (0xbc, default)
    BC = 1,
}

impl Default for TrailerField {
    fn default() -> Self {
        Self::BC
    }
}

impl<'a> DecodeValue<'a> for TrailerField {
    fn decode_value<R: Reader<'a>>(decoder: &mut R, header: der::Header) -> der::Result<Self> {
        match u8::decode_value(decoder, header)? {
            1 => Ok(TrailerField::BC),
            _ => Err(Self::TAG.value_error()),
        }
    }
}

impl EncodeValue for TrailerField {
    fn value_len(&self) -> der::Result<der::Length> {
        Ok(der::Length::ONE)
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> der::Result<()> {
        (*self as u8).encode_value(writer)
    }
}

impl FixedTag for TrailerField {
    const TAG: Tag = Tag::Integer;
}

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
pub struct RsaPssParams<'a> {
    /// Hash Algorithm
    pub hash: AlgorithmIdentifier<'a>,

    /// Mask Generation Function (MGF)
    pub mask_gen: AlgorithmIdentifier<'a>,

    /// Salt length
    pub salt_len: u8,

    /// Trailer field (i.e. [`TrailerField::BC`])
    pub trailer_field: TrailerField,
}

impl<'a> Default for RsaPssParams<'a> {
    fn default() -> Self {
        Self {
            hash: SHA_1_AI,
            mask_gen: default_mgf1_sha1(),
            salt_len: SALT_LEN_DEFAULT,
            trailer_field: Default::default(),
        }
    }
}

impl<'a> DecodeValue<'a> for RsaPssParams<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            Ok(Self {
                hash: reader
                    .context_specific(TagNumber::N0, TagMode::Explicit)?
                    .unwrap_or(SHA_1_AI),
                mask_gen: reader
                    .context_specific(TagNumber::N1, TagMode::Explicit)?
                    .unwrap_or_else(default_mgf1_sha1),
                salt_len: reader
                    .context_specific(TagNumber::N2, TagMode::Explicit)?
                    .unwrap_or(SALT_LEN_DEFAULT),
                trailer_field: reader
                    .context_specific(TagNumber::N3, TagMode::Explicit)?
                    .unwrap_or_default(),
            })
        })
    }
}

impl<'a> Sequence<'a> for RsaPssParams<'a> {
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encode]) -> der::Result<T>,
    {
        f(&[
            &if self.hash == SHA_1_AI {
                None
            } else {
                Some(ContextSpecificRef {
                    tag_number: TagNumber::N0,
                    tag_mode: TagMode::Explicit,
                    value: &self.hash,
                })
            },
            &if self.mask_gen == default_mgf1_sha1() {
                None
            } else {
                Some(ContextSpecificRef {
                    tag_number: TagNumber::N1,
                    tag_mode: TagMode::Explicit,
                    value: &self.mask_gen,
                })
            },
            &if self.salt_len == SALT_LEN_DEFAULT {
                None
            } else {
                Some(ContextSpecificRef {
                    tag_number: TagNumber::N2,
                    tag_mode: TagMode::Explicit,
                    value: &self.salt_len,
                })
            },
            &if self.trailer_field == TrailerField::default() {
                None
            } else {
                Some(ContextSpecificRef {
                    tag_number: TagNumber::N3,
                    tag_mode: TagMode::Explicit,
                    value: &self.trailer_field,
                })
            },
        ])
    }
}

impl<'a> TryFrom<&'a [u8]> for RsaPssParams<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(Self::from_der(bytes)?)
    }
}

/// Default Mask Generation Function (MGF): SHA-1.
fn default_mgf1_sha1<'a>() -> AlgorithmIdentifier<'a> {
    AlgorithmIdentifier {
        oid: OID_MGF_1,
        parameters: Some(
            AnyRef::new(Tag::Sequence, SEQ_OID_SHA_1_DER)
                .expect("error creating default MGF1 params"),
        ),
    }
}
