//! Unsigned integer decoders/encoders.

use crate::{Encoder, Length, Result, Tag};

/// Decode an unsigned integer into a big endian byte slice with all leading
/// zeroes removed.
///
/// Returns a byte array of the requested size containing a big endian integer.
pub(super) fn decode_to_slice(bytes: &[u8]) -> Result<&[u8]> {
    // The `INTEGER` type always encodes a signed value, so for unsigned
    // values the leading `0x00` byte may need to be removed.
    //
    // We also disallow a leading byte which would overflow a signed ASN.1
    // integer (since we're decoding an unsigned integer).
    // We expect all such cases to have a leading `0x00` byte.
    match bytes {
        [] => Err(Tag::Integer.non_canonical_error()),
        [0] => Ok(bytes),
        [0, byte, ..] if *byte < 0x80 => Err(Tag::Integer.non_canonical_error()),
        [0, rest @ ..] => Ok(rest),
        [byte, ..] if *byte >= 0x80 => Err(Tag::Integer.value_error()),
        _ => Ok(bytes),
    }
}

/// Decode an unsigned integer into a byte array of the requested size
/// containing a big endian integer.
pub(super) fn decode_to_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    let input = decode_to_slice(bytes)?;

    // Compute number of leading zeroes to add
    let num_zeroes = N
        .checked_sub(input.len())
        .ok_or_else(|| Tag::Integer.length_error())?;

    // Copy input into `N`-sized output buffer with leading zeroes
    let mut output = [0u8; N];
    output[num_zeroes..].copy_from_slice(input);
    Ok(output)
}

/// Encode the given big endian bytes representing an integer as ASN.1 DER.
pub(super) fn encode_bytes(encoder: &mut Encoder<'_>, bytes: &[u8]) -> Result<()> {
    let bytes = strip_leading_zeroes(bytes);

    if needs_leading_zero(bytes) {
        encoder.byte(0)?;
    }

    encoder.bytes(bytes)
}

/// Get the encoded length for the given unsigned integer serialized as bytes.
#[inline]
pub(super) fn encoded_len(bytes: &[u8]) -> Result<Length> {
    let bytes = strip_leading_zeroes(bytes);
    Length::try_from(bytes.len())? + needs_leading_zero(bytes) as u8
}

/// Strip the leading zeroes from the given byte slice
pub(super) fn strip_leading_zeroes(mut bytes: &[u8]) -> &[u8] {
    while let Some((byte, rest)) = bytes.split_first() {
        if *byte == 0 && !rest.is_empty() {
            bytes = rest;
        } else {
            break;
        }
    }

    bytes
}

/// Does the given integer need a leading zero?
fn needs_leading_zero(bytes: &[u8]) -> bool {
    matches!(bytes.get(0), Some(byte) if *byte >= 0x80)
}

#[cfg(test)]
mod tests {
    use super::decode_to_array;
    use crate::{ErrorKind, Tag};

    #[test]
    fn decode_to_array_no_leading_zero() {
        let arr = decode_to_array::<4>(&[1, 2]).unwrap();
        assert_eq!(arr, [0, 0, 1, 2]);
    }

    #[test]
    fn decode_to_array_leading_zero() {
        let arr = decode_to_array::<4>(&[0x00, 0xFF, 0xFE]).unwrap();
        assert_eq!(arr, [0x00, 0x00, 0xFF, 0xFE]);
    }

    #[test]
    fn decode_to_array_oversized_input() {
        let err = decode_to_array::<1>(&[1, 2, 3]).err().unwrap();
        assert_eq!(err.kind(), ErrorKind::Length { tag: Tag::Integer });
    }
}
