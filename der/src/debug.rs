#![cfg(all(debug_assertions, feature = "std"))]

use std::{print, println};

use crate::{
    asn1, oid, Decode as _, DecodeValue as _, Encode as _, ErrorKind, Header, IndefiniteLength,
    Length, Reader, Result, SliceReader, Tag,
};

/// Length of end-of-content (eoc) markers
const EOC_LENGTH: Length = Length::new(2);
/// end-of-content (eoc) marker
const EOC_MARKER: &[u8; 2] = &[0u8; 2];

fn read_eoc<'i, 'r, R: Reader<'r>>(r: &'i mut R) -> Result<()> {
    // consume the last two bytes
    if r.peek_byte() == Some(0) {
        let eoc = r.read_slice(EOC_LENGTH)?;
        if eoc.ne(EOC_MARKER) {
            Err(ErrorKind::Failed.at(r.position().saturating_sub(Length::ONE)))
        } else {
            Ok(())
        }
    } else {
        // first of reserved two bytes are non zero
        Err(ErrorKind::Failed.at(r.position()))
    }
}

fn debug_def<'i, 'r, R: Reader<'r>>(
    r: &'i mut R,
    tag: Tag,
    length: Length,
    depth: usize,
) -> Result<()> {
    let header = Header::new(tag, length)?;
    let header_len = header.encoded_len()?;

    print!(
        "{:>4}:d={:<2} hl={} l={:>4} {}{:<prefix$}{:<suffix$}",
        usize::try_from((r.position() - header_len)?)?, // offset
        depth,                                          // depth, thus identation
        usize::try_from(header_len)?,                   // header length (TL of TLV)
        usize::try_from(length)?,
        if tag.octet() & 0b100000 != 0 {
            "cons"
        } else {
            "prim"
        },
        ":",
        format!("{}", tag),
        prefix = depth + 2,
        suffix = 32 - depth,
    );

    match tag {
        Tag::Sequence | Tag::Set | Tag::BitString | Tag::OctetString if tag.is_constructed() => {
            println!();
            let limit = (r.position() + length)?;
            while r.position() < limit {
                debug_1(r, depth + 1)?;
            }
        }
        Tag::Application { constructed, .. }
        | Tag::Private { constructed, .. }
        | Tag::ContextSpecific { constructed, .. } => {
            if constructed {
                println!();
                debug_1(r, depth + 1)?;
            } else {
                print!(" [HEX DUMP]:");
                for byte in r.read_slice(length)? {
                    print!("{:02X?}", byte);
                }
                println!();
            }
        }
        Tag::Boolean => println!(":{}", bool::decode_value(r, header)?),
        Tag::Integer => {
            print!(":");
            for byte in asn1::Int::decode_value(r, header)?.as_bytes().iter() {
                print!("{:02X?}", byte);
            }
            println!();
        }
        Tag::BitString => {
            print!(" [HEX DUMP]:");
            for byte in asn1::BitString::decode_value(r, header)?.raw_bytes().iter() {
                print!("{:02X?}", byte);
            }
            println!();
        }
        Tag::OctetString => {
            print!(" [HEX DUMP]:");
            for byte in asn1::OctetString::decode_value(r, header)?
                .as_bytes()
                .iter()
            {
                print!("{:02X?}", byte);
            }
            println!();
        }
        Tag::ObjectIdentifier => println!(":{}", oid::ObjectIdentifier::decode_value(r, header)?),
        Tag::Utf8String => println!(
            ":{}",
            asn1::Utf8StringRef::decode_value(r, header)?.as_str()
        ),
        Tag::PrintableString => println!(
            ":{}",
            asn1::PrintableString::decode_value(r, header)?.as_str()
        ),
        Tag::TeletexString => println!(
            ":{}",
            asn1::TeletexString::decode_value(r, header)?.as_str()
        ),
        Tag::VideotexString => println!(
            ":{}",
            asn1::VideotexStringRef::decode_value(r, header)?.as_str()
        ),
        Tag::Ia5String => println!(":{}", asn1::Ia5String::decode_value(r, header)?.as_str()),
        Tag::BmpString => println!(":{}", asn1::BmpString::decode_value(r, header)?),
        Tag::UtcTime => println!(
            ":{}Z",
            asn1::UtcTime::decode_value(r, header)?
                .to_unix_duration()
                .as_secs()
        ),
        Tag::GeneralizedTime => println!(
            ":{}Z",
            asn1::GeneralizedTime::decode_value(r, header)?
                .to_unix_duration()
                .as_secs()
        ),
        Tag::Null => println!(),
        Tag::Enumerated => unimplemented!(),
        Tag::NumericString => unimplemented!(),
        Tag::Real => unimplemented!(),
        Tag::VisibleString => unimplemented!(),
        _ => unimplemented!(),
    }

    Ok(())
}

fn debug_indef<'i, 'r, R: Reader<'r>>(
    r: &'i mut R,
    tag: Tag,
    length: IndefiniteLength,
    depth: usize,
) -> Result<()> {
    if length.is_definite() {
        debug_def(r, tag, length.try_into()?, depth)
    } else {
        print!(
            "{:>4}:d={:<2} hl={} l=inf  {}{:<prefix$}{:<suffix$}",
            usize::try_from((r.position() - Length::new(2))?)?, // offset
            depth,                                              // depth, thus identation
            usize::try_from((tag.encoded_len()? + length.encoded_len()?)?)?, // header length (TL of TLV)
            if tag.octet() & 0b100000 != 0 {
                "cons"
            } else {
                "prim"
            },
            ":",
            format!("{}", tag),
            prefix = depth + 2,
            suffix = 32 - depth,
        );

        if tag.is_constructed() {
            println!();
            while r.peek_byte() != Some(0) {
                debug_1(r, depth + 1)?;
            }
            let end_pos = r.position();
            read_eoc(r)?;

            println!(
                "{:>4}:d={:<2} hl=2 l=   0 prim{:<prefix$}{:<suffix$}",
                usize::try_from(end_pos)?, // offset
                depth,
                ":",
                "EOC",
                prefix = depth + 2,
                suffix = 32 - depth,
            );
            Ok(())
        } else {
            unimplemented!();
        }
    }
}

fn debug_1<'i, 'r, R: Reader<'r>>(r: &'i mut R, depth: usize) -> Result<()> {
    let tag = Tag::decode(r).map_err(|e| e.kind().at(r.position()))?;
    let length = IndefiniteLength::decode(r)?;
    debug_indef(r, tag, length, depth)
}

/// Print to stdout in the style of OpenSSL asn1parse
pub fn debug_print(bytes: &[u8]) -> Result<()> {
    let mut r = SliceReader::new(bytes)?;
    debug_1(&mut r, 0)?;
    r.finish(())
}
