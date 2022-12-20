use der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Tag, Writer};

/// The CMSVersion type gives a syntax version number, for compatibility
/// with future revisions of this specification.
/// ```text
/// CMSVersion ::= INTEGER
///     { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
/// ```
///
/// See [RFC 5652 10.2.5](https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CmsVersion {
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
}

impl FixedTag for CmsVersion {
    const TAG: Tag = Tag::Integer;
}

impl From<CmsVersion> for u8 {
    fn from(version: CmsVersion) -> Self {
        version as u8
    }
}

impl TryFrom<u8> for CmsVersion {
    type Error = der::Error;
    fn try_from(byte: u8) -> der::Result<CmsVersion> {
        match byte {
            0 => Ok(CmsVersion::V0),
            1 => Ok(CmsVersion::V1),
            2 => Ok(CmsVersion::V2),
            3 => Ok(CmsVersion::V3),
            4 => Ok(CmsVersion::V4),
            5 => Ok(CmsVersion::V5),
            _ => Err(Self::TAG.value_error()),
        }
    }
}

impl<'a> DecodeValue<'a> for CmsVersion {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<CmsVersion> {
        CmsVersion::try_from(u8::decode_value(reader, header)?)
    }
}

impl EncodeValue for CmsVersion {
    fn value_len(&self) -> der::Result<Length> {
        u8::from(*self).value_len()
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> der::Result<()> {
        u8::from(*self).encode_value(writer)
    }
}
