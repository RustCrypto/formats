//! Tests for handling of nested messages.

use der::{Decode, Error, ErrorKind, Header, Reader, SliceReader, Tag, asn1::AnyRef};

// This is the expected maximum depth.
// TODO(tarcieri): expose this as a constant in the public API?
const MAX_DEPTH: usize = 64;

fn walk<'a>(reader: &mut SliceReader<'a>) -> Result<AnyRef<'a>, Error> {
    let header = Header::peek(reader)?;
    if header.tag() == Tag::Sequence {
        reader.sequence(|r| walk(r)) // der::read_nested recursion
    } else {
        AnyRef::decode(reader)
    }
}

#[test]
#[allow(clippy::cast_possible_truncation, reason = "test")]
fn returns_nesting_depth_error_when_max_depth_encountered() {
    let depth = MAX_DEPTH + 1;

    let mut buf = vec![0x05, 0x00]; // innermost NULL
    for _ in 0..depth {
        let len = buf.len();
        let mut next = Vec::with_capacity(len + 5);
        next.push(0x30);
        if len < 0x80 {
            next.push(len as u8);
        } else if len <= 0xFF {
            next.push(0x81);
            next.push(len as u8);
        } else if len <= 0xFFFF {
            next.push(0x82);
            next.push((len >> 8) as u8);
            next.push(len as u8);
        } else {
            next.push(0x83);
            next.push((len >> 16) as u8);
            next.push((len >> 8) as u8);
            next.push(len as u8);
        }
        next.extend_from_slice(&buf);
        buf = next;
    }

    let mut reader = SliceReader::new(&buf).unwrap();
    let err = walk(&mut reader).expect_err("should return ErrorKind::NestingDepth");
    assert_eq!(err.kind(), ErrorKind::NestingDepth);
}
