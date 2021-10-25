//! `encrypted-data` content type [RFC 2315 § 13](https://datatracker.ietf.org/doc/html/rfc2315#section-13)

use crate::enveloped_data_content::EncryptedContentInfo;
use der::{
    Decodable, DecodeValue, Decoder, Encodable, EncodeValue, Encoder, Length, Sequence, Tag, Tagged,
};

/// Syntax version of the `encrypted-data` content type.
///
/// ```text
/// Version ::= Integer
/// ```
///
/// The only supported version is 0.
/// See [RFC 2315 § 13](https://datatracker.ietf.org/doc/html/rfc2315#section-13).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    /// syntax version 0 for [EncryptedDataContent].
    V0 = 0,
}

impl Tagged for Version {
    const TAG: Tag = Tag::Integer;
}

impl From<Version> for u8 {
    fn from(version: Version) -> Self {
        version as u8
    }
}

impl TryFrom<u8> for Version {
    type Error = der::Error;
    fn try_from(byte: u8) -> der::Result<Version> {
        match byte {
            0 => Ok(Version::V0),
            _ => Err(Self::TAG.value_error()),
        }
    }
}

impl<'a> DecodeValue<'a> for Version {
    fn decode_value(decoder: &mut Decoder<'a>, length: Length) -> der::Result<Version> {
        Version::try_from(u8::decode_value(decoder, length)?)
    }
}

impl EncodeValue for Version {
    fn value_len(&self) -> der::Result<Length> {
        u8::from(*self).value_len()
    }

    fn encode_value(&self, encoder: &mut Encoder<'_>) -> der::Result<()> {
        u8::from(*self).encode_value(encoder)
    }
}

/// Encrypted-data content type [RFC 2315 § 13](https://datatracker.ietf.org/doc/html/rfc2315#section-13)
///
/// ```text
/// EncryptedData ::= SEQUENCE {
///   version Version,
///   encryptedContentInfo EncryptedContentInfo }
/// ```
///
/// The encrypted-data content type consists of encrypted content of any
/// type. Unlike the enveloped-data content type, the encrypted-data
/// content type has neither recipients nor encrypted content-encryption
/// keys. Keys are assumed to be managed by other means.
///
/// The fields of type EncryptedData have the following meanings:
///   - [`version`](EncryptedDataContent::version) is the syntax version number.
///   - [`encrypted_content_info`](EncryptedDataContent::encrypted_content_info) is the encrypted content
///     information, as in [EncryptedContentInfo].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct EncryptedDataContent<'a> {
    /// the syntax version number.
    pub version: Version,

    /// the encrypted content information.
    pub encrypted_content_info: EncryptedContentInfo<'a>,
}

impl<'a> Decodable<'a> for EncryptedDataContent<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<EncryptedDataContent<'a>> {
        decoder.sequence(|decoder| {
            Ok(EncryptedDataContent {
                version: decoder.decode()?,
                encrypted_content_info: decoder.decode()?,
            })
        })
    }
}

impl<'a> Sequence<'a> for EncryptedDataContent<'a> {
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        f(&[&self.version, &self.encrypted_content_info])
    }
}
