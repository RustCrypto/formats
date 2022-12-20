use der::{FixedTag, Tag, DecodeValue, EncodeValue, Length, Writer, Reader, Header};



/// The CMSVersion type gives a syntax version number, for compatibility
/// with future revisions of this specification.
/// ```text
/// CMSVersion ::= INTEGER
///     { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
/// ```
///
/// See [RFC 5652 10.2.5](https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CMSVersion {
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5
}

impl FixedTag for CMSVersion {
    const TAG: Tag = Tag::Integer;
}

impl From<CMSVersion> for u8 {
    fn from(version: CMSVersion) -> Self {
        version as u8
    }
}

impl TryFrom<u8> for CMSVersion {
    type Error = der::Error;
    fn try_from(byte: u8) -> der::Result<CMSVersion> {
        match byte {
            0 => Ok(CMSVersion::V0),
            1 => Ok(CMSVersion::V1),
            2 => Ok(CMSVersion::V2),
            3 => Ok(CMSVersion::V3),
            4 => Ok(CMSVersion::V4),
            5 => Ok(CMSVersion::V5),
            _ => Err(Self::TAG.value_error()),
        }
    }
}

impl<'a> DecodeValue<'a> for CMSVersion {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<CMSVersion> {
        CMSVersion::try_from(u8::decode_value(reader, header)?)
    }
}

impl EncodeValue for CMSVersion {
    fn value_len(&self) -> der::Result<Length> {
        u8::from(*self).value_len()
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> der::Result<()> {
        u8::from(*self).encode_value(writer)
    }
}