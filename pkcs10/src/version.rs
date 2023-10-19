//! PKCS#10 version identifier.

use crate::Error;
use der::{Decode, Encode, FixedTag, Reader, Tag, Writer};

/// Version identifier for CertificationRequestInfo.
///
/// RFC 2986 states that version is the version number, for compatibility with future
/// revisions of this document.  It shall be 0 for this version of the standard
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum Version {
    /// The only accepted version now. Version 1 has value 0
    V1 = 0,
}

impl Version {
    /// Is this version expected to have a public key?
    pub fn has_public_key(self) -> bool {
        match self {
            Version::V1 => false,
        }
    }
}

impl<'a> Decode<'a> for Version {
    fn decode<R: Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        Version::try_from(u8::decode(decoder)?).map_err(|_| Self::TAG.value_error())
    }
}

impl Encode for Version {
    fn encoded_len(&self) -> der::Result<der::Length> {
        der::Length::from(1u8).for_tlv()
    }

    fn encode(&self, writer: &mut impl Writer) -> der::Result<()> {
        u8::from(*self).encode(writer)
    }
}

impl From<Version> for u8 {
    fn from(version: Version) -> Self {
        version as u8
    }
}

impl TryFrom<u8> for Version {
    type Error = Error;
    fn try_from(byte: u8) -> Result<Version, Error> {
        match byte {
            0 => Ok(Version::V1),
            _ => Err(Self::TAG.value_error().into()),
        }
    }
}

impl FixedTag for Version {
    const TAG: Tag = Tag::Integer;
}
