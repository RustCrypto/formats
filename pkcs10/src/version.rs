//! Certification request information version identifier.

use der::{Decodable, Decoder, Encodable, Encoder, FixedTag, Tag};

/// Version identifier for certification request information.
///
/// (RFC 2986 designates `0` as the only valid version)
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum Version {
    /// Denotes PKCS#8 v1
    V1 = 0,
}

impl Decodable<'_> for Version {
    fn decode(decoder: &mut Decoder<'_>) -> der::Result<Self> {
        Version::try_from(u8::decode(decoder)?).map_err(|_| Self::TAG.value_error())
    }
}

impl Encodable for Version {
    fn encoded_len(&self) -> der::Result<der::Length> {
        der::Length::from(1u8).for_tlv()
    }

    fn encode(&self, encoder: &mut Encoder<'_>) -> der::Result<()> {
        u8::from(*self).encode(encoder)
    }
}

impl From<Version> for u8 {
    fn from(version: Version) -> Self {
        version as u8
    }
}

impl TryFrom<u8> for Version {
    type Error = der::Error;

    fn try_from(byte: u8) -> Result<Version, der::Error> {
        match byte {
            0 => Ok(Version::V1),
            _ => Err(Self::TAG.value_error()),
        }
    }
}

impl FixedTag for Version {
    const TAG: Tag = Tag::Integer;
}
