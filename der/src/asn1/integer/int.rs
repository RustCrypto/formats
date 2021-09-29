//! Support for encoding negative integers

use super::is_highest_bit_set;
use crate::{Encodable, Encoder, ErrorKind, Header, Length, Result, Tag};
use core::convert::TryFrom;

/// Decode an unsigned integer of the specified size.
///
/// Returns a byte array of the requested size containing a big endian integer.
pub(super) fn decode_to_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    let offset = N.checked_sub(bytes.len()).ok_or(ErrorKind::Truncated)?;
    let mut output = [0xFFu8; N];
    output[offset..].copy_from_slice(bytes);
    Ok(output)
}

/// Encode the given big endian bytes representing an integer as ASN.1 DER.
pub(super) fn encode_bytes(encoder: &mut Encoder<'_>, bytes: &[u8]) -> Result<()> {
    let bytes = strip_leading_ones(bytes);
    let len = Length::try_from(bytes.len())?;
    Header::new(Tag::Integer, len)?.encode(encoder)?;
    encoder.bytes(bytes)
}

/// Get the encoded length for the given unsigned integer serialized as bytes.
#[inline]
pub(super) fn encoded_len(bytes: &[u8]) -> Result<Length> {
    Length::try_from(strip_leading_ones(bytes).len())
}

/// Strip the leading all-ones bytes from the given byte slice.
fn strip_leading_ones(mut bytes: &[u8]) -> &[u8] {
    while let Some((byte, rest)) = bytes.split_first() {
        if *byte == 0xFF && is_highest_bit_set(rest) {
            bytes = rest;
            continue;
        }

        break;
    }

    bytes
}
