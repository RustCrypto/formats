//! ASN.1 tags.

mod class;
mod number;

pub use self::{class::Class, number::TagNumber};

use crate::{Decodable, Decoder, Encodable, Encoder, Error, ErrorKind, Length, Result};
use core::{convert::TryFrom, fmt};

/// Indicator bit for constructed form encoding (i.e. vs primitive form)
const CONSTRUCTED_FLAG: u8 = 0b100000;

/// Indicates whether or not this type is constructed
type Constructed = bool;

/// Types with an associated ASN.1 [`Tag`].
pub trait Tagged {
    /// ASN.1 tag
    const TAG: Tag;
}

/// ASN.1 tags.
///
/// Tags are the leading identifier octet of the Tag-Length-Value encoding
/// used by ASN.1 DER and identify the type of the subsequent value.
///
/// They are described in X.690 Section 8.1.2: Identifier octets, and
/// structured as follows:
///
/// ```text
/// | Class | P/C | Tag Number |
/// ```
///
/// - Bits 8/7: [`Class`]
/// - Bit 6: primitive (0) or constructed (1)
/// - Bits 5-1: tag number
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Tag {
    /// `BOOLEAN` tag: 0x01
    Boolean,

    /// `INTEGER` tag: 0x02
    Integer,

    /// `BIT STRING` tag: 0x03
    BitString,

    /// `OCTET STRING` tag: 0x04
    OctetString,

    /// `NULL` tag: 0x05
    Null,

    /// `OBJECT IDENTIFIER` tag: 0x06
    ObjectIdentifier,

    /// `UTF8String` tag: 0x0C
    Utf8String,

    /// `SEQUENCE` tag: 0x10
    Sequence,

    /// `SET` and `SET OF` tag: 0x11
    Set,

    /// `PrintableString` tag: 0x13
    PrintableString,

    /// `IA5String` tag: 0x16
    Ia5String,

    /// `UTCTime` tag: 0x17
    UtcTime,

    /// `GeneralizedTime` tag: 0x18
    GeneralizedTime,

    /// Application tag.
    Application(TagNumber, Constructed),

    /// Context-specific tag.
    ContextSpecific(TagNumber, Constructed),

    /// Private tag number.
    Private(TagNumber, Constructed),
}

impl Tag {
    /// Assert that this [`Tag`] matches the provided expected tag.
    ///
    /// On mismatch, returns an [`Error`] with [`ErrorKind::UnexpectedTag`].
    pub fn assert_eq(self, expected: Tag) -> Result<Tag> {
        if self == expected {
            Ok(self)
        } else {
            Err(self.unexpected_error(Some(expected)))
        }
    }

    /// Get the [`Class`] that corresponds to this [`Tag`].
    pub fn class(self) -> Class {
        match self {
            Tag::Application(_, _) => Class::Application,
            Tag::ContextSpecific(_, _) => Class::ContextSpecific,
            Tag::Private(_, _) => Class::Private,
            _ => Class::Universal,
        }
    }

    /// Get the octet encoding for this [`Tag`].
    pub fn octet(self) -> u8 {
        match self {
            Tag::Boolean => 0x01,
            Tag::Integer => 0x02,
            Tag::BitString => 0x03,
            Tag::OctetString => 0x04,
            Tag::Null => 0x05,
            Tag::ObjectIdentifier => 0x06,
            Tag::Utf8String => 0x0C,
            Tag::Sequence => 0x10 | CONSTRUCTED_FLAG,
            Tag::Set => 0x11 | CONSTRUCTED_FLAG,
            Tag::PrintableString => 0x13,
            Tag::Ia5String => 0x16,
            Tag::UtcTime => 0x17,
            Tag::GeneralizedTime => 0x18,
            Tag::Application(number, constructed)
            | Tag::ContextSpecific(number, constructed)
            | Tag::Private(number, constructed) => self.class().octet(number, constructed),
        }
    }

    /// Create an [`Error`] for an non-canonical value with the ASN.1 type
    /// identified by this tag.
    pub fn non_canonical_error(self) -> Error {
        ErrorKind::Value { tag: self }.into()
    }

    /// Create an [`Error`] because the current tag was unexpected, with an
    /// optional expected tag.
    pub fn unexpected_error(self, expected: Option<Self>) -> Error {
        ErrorKind::UnexpectedTag {
            expected,
            actual: self,
        }
        .into()
    }

    /// Create an [`Error`] for an invalid value with the ASN.1 type identified
    /// by this tag.
    pub fn value_error(self) -> Error {
        ErrorKind::Value { tag: self }.into()
    }
}

impl TryFrom<u8> for Tag {
    type Error = Error;

    fn try_from(byte: u8) -> Result<Tag> {
        match byte {
            0x01 => Ok(Tag::Boolean),
            0x02 => Ok(Tag::Integer),
            0x03 => Ok(Tag::BitString),
            0x04 => Ok(Tag::OctetString),
            0x05 => Ok(Tag::Null),
            0x06 => Ok(Tag::ObjectIdentifier),
            0x0C => Ok(Tag::Utf8String),
            0x13 => Ok(Tag::PrintableString),
            0x16 => Ok(Tag::Ia5String),
            0x17 => Ok(Tag::UtcTime),
            0x18 => Ok(Tag::GeneralizedTime),
            0x30 => Ok(Tag::Sequence), // constructed
            0x31 => Ok(Tag::Set),      // constructed
            0x40..=0x5E => Ok(Tag::Application(TagNumber(byte & 0b11111), false)), // primitive
            0x60..=0x7E => Ok(Tag::Application(TagNumber(byte & 0b11111), true)), // constructed
            0x80..=0x9E => Ok(Tag::ContextSpecific(TagNumber(byte & 0b11111), false)), // primitive
            0xA0..=0xBE => Ok(Tag::ContextSpecific(TagNumber(byte & 0b11111), true)), // constructed
            0xC0..=0xDE => Ok(Tag::Private(TagNumber(byte & 0b11111), false)), //primitive
            0xE0..=0xFE => Ok(Tag::Private(TagNumber(byte & 0b11111), true)), // constructed
            _ => Err(ErrorKind::UnknownTag { byte }.into()),
        }
    }
}

impl From<Tag> for u8 {
    fn from(tag: Tag) -> u8 {
        tag.octet()
    }
}

impl From<&Tag> for u8 {
    fn from(tag: &Tag) -> u8 {
        u8::from(*tag)
    }
}

impl Decodable<'_> for Tag {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self> {
        decoder.byte().and_then(Self::try_from)
    }
}

impl Encodable for Tag {
    fn encoded_len(&self) -> Result<Length> {
        Ok(Length::ONE)
    }

    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        encoder.byte(self.into())
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tag::Boolean => f.write_str("BOOLEAN"),
            Tag::Integer => f.write_str("INTEGER"),
            Tag::BitString => f.write_str("BIT STRING"),
            Tag::OctetString => f.write_str("OCTET STRING"),
            Tag::Null => f.write_str("NULL"),
            Tag::ObjectIdentifier => f.write_str("OBJECT IDENTIFIER"),
            Tag::Utf8String => f.write_str("UTF8String"),
            Tag::Set => f.write_str("SET"),
            Tag::PrintableString => f.write_str("PrintableString"),
            Tag::Ia5String => f.write_str("IA5String"),
            Tag::UtcTime => f.write_str("UTCTime"),
            Tag::GeneralizedTime => f.write_str("GeneralizedTime"),
            Tag::Sequence => f.write_str("SEQUENCE"),
            Tag::Application(n, c) => write!(f, "APPLICATION {} CONSTRUCTED {}", n, *c as u8),
            Tag::ContextSpecific(n, c) => {
                write!(f, "CONTEXT-SPECIFIC {} CONSTRUCTED {}", n, *c as u8)
            }
            Tag::Private(n, c) => write!(f, "PRIVATE {} CONSTRUCTED {}", n, *c as u8),
        }
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag(0x{:02x}: {})", u8::from(*self), self)
    }
}

#[cfg(test)]
mod tests {
    use super::TagNumber;
    use super::{Class, Tag};

    #[test]
    fn tag_class() {
        assert_eq!(Tag::Boolean.class(), Class::Universal);
        assert_eq!(Tag::Integer.class(), Class::Universal);
        assert_eq!(Tag::BitString.class(), Class::Universal);
        assert_eq!(Tag::OctetString.class(), Class::Universal);
        assert_eq!(Tag::Null.class(), Class::Universal);
        assert_eq!(Tag::ObjectIdentifier.class(), Class::Universal);
        assert_eq!(Tag::Utf8String.class(), Class::Universal);
        assert_eq!(Tag::Set.class(), Class::Universal);
        assert_eq!(Tag::PrintableString.class(), Class::Universal);
        assert_eq!(Tag::Ia5String.class(), Class::Universal);
        assert_eq!(Tag::UtcTime.class(), Class::Universal);
        assert_eq!(Tag::GeneralizedTime.class(), Class::Universal);
        assert_eq!(Tag::Sequence.class(), Class::Universal);

        for num in 0..=30 {
            let tag_num = TagNumber::new(num);
            assert_eq!(Tag::Application(tag_num, true).class(), Class::Application);
            assert_eq!(Tag::Application(tag_num, false).class(), Class::Application);
            assert_eq!(
                Tag::ContextSpecific(tag_num, true).class(),
                Class::ContextSpecific
            );
            assert_eq!(
                Tag::ContextSpecific(tag_num, false).class(),
                Class::ContextSpecific
            );
            assert_eq!(Tag::Private(tag_num, true).class(), Class::Private);
            assert_eq!(Tag::Private(tag_num, false).class(), Class::Private);
        }
    }
}
