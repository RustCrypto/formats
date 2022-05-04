//! `encrypted-data` content type [RFC 5652 § 8](https://datatracker.ietf.org/doc/html/rfc5652#section-8)

use crate::enveloped_data_content::EncryptedContentInfo;
use der::{
    DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag, Writer,
};

/// Syntax version of the `encrypted-data` content type.
///
/// ```text
/// Version ::= Integer
/// ```
///
/// The only version supported by this library is `0`.
/// See [RFC 5652 § 8](https://datatracker.ietf.org/doc/html/rfc5652#section-8).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    /// syntax version 0 for [EncryptedDataContent].
    V0 = 0,
}

impl FixedTag for Version {
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
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Version> {
        Version::try_from(u8::decode_value(reader, header)?)
    }
}

impl EncodeValue for Version {
    fn value_len(&self) -> der::Result<Length> {
        u8::from(*self).value_len()
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> der::Result<()> {
        u8::from(*self).encode_value(writer)
    }
}

/// Encrypted-data content type [RFC 5652 § 8](https://datatracker.ietf.org/doc/html/rfc5652#section-8)
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

impl<'a> DecodeValue<'a> for EncryptedDataContent<'a> {
    fn decode_value<R: Reader<'a>>(
        reader: &mut R,
        header: Header,
    ) -> der::Result<EncryptedDataContent<'a>> {
        reader.read_nested(header.length, |reader| {
            Ok(EncryptedDataContent {
                version: reader.decode()?,
                encrypted_content_info: reader.decode()?,
            })
        })
    }
}

impl<'a> Sequence<'a> for EncryptedDataContent<'a> {
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encode]) -> der::Result<T>,
    {
        f(&[&self.version, &self.encrypted_content_info])
    }
}
