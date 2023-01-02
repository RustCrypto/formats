//! Support for encoding negative integers

use super::is_highest_bit_set;
use crate::{ErrorKind, Length, Result, Tag, Writer};

pub(super) fn decode_to_slice(bytes: &[u8]) -> Result<&[u8]> {
    // We only support decoding canonicalized negative integers here.
    match bytes {
        [] => Err(Tag::Integer.non_canonical_error()),

        // Non-canonical forms are not allowed.
        [0x00, byte, ..] if *byte < 0x80 => Err(Tag::Integer.non_canonical_error()),
        [0xFF, byte, ..] if *byte >= 0x80 => Err(Tag::Integer.non_canonical_error()),

        // Positive integers are not allowed.
        [byte, ..] if *byte < 0x80 && *byte > 0 => Err(Tag::Integer.value_error()),
        [0x00, _, ..] => Err(Tag::Integer.value_error()),
        [0xFF, rest @ ..] => Ok(rest),
        _ => Ok(bytes),
    }
}

/// Decode an signed integer of the specified size.
///
/// Returns a byte array of the requested size containing a big endian integer.
pub(super) fn decode_to_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    match N.checked_sub(bytes.len()) {
        Some(offset) => {
            let mut output = [0xFFu8; N];
            output[offset..].copy_from_slice(bytes);
            Ok(output)
        }
        None => {
            let expected_len = Length::try_from(N)?;
            let actual_len = Length::try_from(bytes.len())?;

            Err(ErrorKind::Incomplete {
                expected_len,
                actual_len,
            }
            .into())
        }
    }
}

/// Encode the given big endian bytes representing an integer as ASN.1 DER.
pub(super) fn encode_bytes<W>(writer: &mut W, bytes: &[u8]) -> Result<()>
where
    W: Writer + ?Sized,
{
    writer.write(strip_leading_ones(bytes))
}

/// Get the encoded length for the given signed integer serialized as bytes.
#[inline]
pub(super) fn encoded_len(bytes: &[u8]) -> Result<Length> {
    let bytes = strip_leading_ones(bytes);
    Length::try_from(bytes.len())? + u8::from(needs_leading_one(bytes))
}

/// Strip the leading all-ones bytes from the given byte slice.
pub(crate) fn strip_leading_ones(mut bytes: &[u8]) -> &[u8] {
    while let Some((byte, rest)) = bytes.split_first() {
        if *byte == 0xFF && is_highest_bit_set(rest) {
            bytes = rest;
            continue;
        }

        break;
    }

    bytes
}

/// Does the given integer need a leading one?
fn needs_leading_one(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(byte) if *byte < 0x80 && *byte > 0)
}

#[cfg(test)]
mod tests {
    use super::decode_to_slice;

    #[test]
    fn decode_to_slice_non_canonical() {
        // Empty integers are always non-canonical.
        assert!(decode_to_slice(&[]).is_err());

        // Positives with excessive zero extension are non-canonical.
        assert!(decode_to_slice(&[0x00, 0x00]).is_err());

        // Negatives with excessive sign extension are non-canonical.
        assert!(decode_to_slice(&[0xFF, 0x80]).is_err());

        // Any positives are non-canonical.
        assert!(decode_to_slice(&[0x01]).is_err());
        assert!(decode_to_slice(&[0x01, 0x02]).is_err());
        assert!(decode_to_slice(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn decode_to_slice_canonical() {
        assert_eq!(decode_to_slice(&[0xFF, 0x01]).unwrap(), &[0x01]);
        assert_eq!(decode_to_slice(&[0x00]).unwrap(), &[0x00])
    }
}
