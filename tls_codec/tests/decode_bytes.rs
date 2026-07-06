use tls_codec::{
    DeserializeBytes, Error, Size, TlsByteVecU8, TlsByteVecU16, TlsByteVecU24, TlsByteVecU32,
    TlsVecU8,
};

#[test]
fn deserialize_tls_byte_vec_u8() {
    let bytes = [3, 2, 1, 0];
    let (result, rest) = TlsByteVecU8::tls_deserialize_bytes(&bytes).unwrap();
    let expected_result = [2, 1, 0];
    assert_eq!(result.as_slice(), expected_result);
    assert_eq!(rest, []);
}

#[test]
fn deserialize_tls_byte_vec_u16() {
    let bytes = [0, 3, 2, 1, 0];
    let (result, rest) = TlsByteVecU16::tls_deserialize_bytes(&bytes).unwrap();
    let expected_result = [2, 1, 0];
    assert_eq!(result.as_slice(), expected_result);
    assert_eq!(rest, []);
}

#[test]
fn deserialize_tls_byte_vec_u24() {
    let bytes = [0, 0, 3, 2, 1, 0];
    let (result, rest) = TlsByteVecU24::tls_deserialize_bytes(&bytes).unwrap();
    let expected_result = [2, 1, 0];
    assert_eq!(result.as_slice(), expected_result);
    assert_eq!(rest, []);
}

#[test]
fn deserialize_tls_byte_vec_u32() {
    let bytes = [0, 0, 0, 3, 2, 1, 0];
    let (result, rest) = TlsByteVecU32::tls_deserialize_bytes(&bytes).unwrap();
    let expected_result = [2, 1, 0];
    assert_eq!(result.as_slice(), expected_result);
    assert_eq!(rest, []);
}

/// A zero-serialized-length element that always deserializes successfully
/// without consuming any input. Before the fix this caused an infinite loop.
#[derive(Debug, Clone, PartialEq)]
struct Zero;

impl Size for Zero {
    fn tls_serialized_len(&self) -> usize {
        0
    }
}

impl DeserializeBytes for Zero {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        Ok((Zero, bytes))
    }
}

#[cfg(feature = "std")]
impl tls_codec::Deserialize for Zero {
    fn tls_deserialize<R: std::io::Read>(_: &mut R) -> Result<Self, Error> {
        Ok(Zero)
    }
}

// zero-sized elements must not loop forever
#[test]
fn zero_sized_element_does_not_hang_bytes() {
    // Length prefix says "1 byte of content" but `Zero` consumes nothing.
    let input = [1u8];
    let res = TlsVecU8::<Zero>::tls_deserialize_bytes(&input);
    assert!(
        matches!(res, Err(Error::DecodingError(_))),
        "expected a decoding error, got {res:?}"
    );
}

#[cfg(feature = "std")]
#[test]
fn zero_sized_element_does_not_hang_read() {
    use tls_codec::Deserialize;
    let input = [1u8];
    let res = TlsVecU8::<Zero>::tls_deserialize(&mut input.as_slice());
    assert!(
        matches!(res, Err(Error::DecodingError(_))),
        "expected a decoding error, got {res:?}"
    );
}

#[test]
fn zero_sized_element_does_not_hang_quic_vec() {
    // QUIC-style `Vec<T>` with a varint length prefix of 1.
    let input = [1u8];
    let res = Vec::<Zero>::tls_deserialize_bytes(&input);
    assert!(
        matches!(res, Err(Error::DecodingError(_))),
        "expected a decoding error, got {res:?}"
    );
}

#[cfg(feature = "std")]
#[test]
fn zero_sized_element_does_not_hang_quic_vec_read() {
    // The QUIC-style `Vec<T>` Read path has its own bounded-reader loop that
    // fuzzing can never reach (no real type consumes 0 bytes), so a unit test is
    // its only possible coverage. Varint length prefix of 1, `Zero` consumes
    // nothing.
    use tls_codec::Deserialize;
    let input = [1u8];
    let res = Vec::<Zero>::tls_deserialize(&mut input.as_slice());
    assert!(
        matches!(res, Err(Error::DecodingError(_))),
        "expected a decoding error, got {res:?}"
    );
}

// declared length must be enforced exactly (no overshoot)
#[test]
fn overshooting_declared_length_is_rejected_bytes() {
    // Declared content length is 3 bytes, but two `u16` elements consume 4.
    // The trailing 0xAA proves the decoder must not silently read past 3.
    let input = [3u8, 0x00, 0x01, 0x00, 0x02, 0xAA];
    let res = TlsVecU8::<u16>::tls_deserialize_bytes(&input);
    assert!(
        matches!(res, Err(Error::DecodingError(_))),
        "expected a decoding error, got {res:?}"
    );
}

#[test]
fn overshooting_declared_length_is_rejected_quic_vec() {
    // varint length prefix = 3, followed by two u16 (4 bytes) + trailing byte.
    let input = [3u8, 0x00, 0x01, 0x00, 0x02, 0xAA];
    let res = Vec::<u16>::tls_deserialize_bytes(&input);
    assert!(
        matches!(res, Err(Error::DecodingError(_))),
        "expected a decoding error, got {res:?}"
    );
}

#[cfg(feature = "std")]
#[test]
fn overshooting_declared_length_is_rejected_read() {
    use tls_codec::Deserialize;
    let input = [3u8, 0x00, 0x01, 0x00, 0x02, 0xAA];
    let res = TlsVecU8::<u16>::tls_deserialize(&mut input.as_slice());
    // The Read path bounds the reader to the declared length (3 bytes), so it
    // never reads past the boundary: the first `u16` consumes 2 bytes and the
    // second cannot fit in the remaining byte, yielding `EndOfStream`.
    assert!(
        matches!(res, Err(Error::EndOfStream)),
        "expected end of stream, got {res:?}"
    );
}

#[cfg(feature = "std")]
#[test]
fn overshooting_declared_length_is_rejected_quic_vec_read() {
    // Same as above, but for the QUIC-style `Vec<T>` Read path: varint length
    // prefix = 3, followed by two `u16` (4 bytes). The reader is bounded to the
    // declared 3 bytes, so the second element cannot fit and yields
    // `EndOfStream`.
    use tls_codec::Deserialize;
    let input = [3u8, 0x00, 0x01, 0x00, 0x02, 0xAA];
    let res = Vec::<u16>::tls_deserialize(&mut input.as_slice());
    assert!(
        matches!(res, Err(Error::EndOfStream)),
        "expected end of stream, got {res:?}"
    );
}

// An exactly-fitting vector still round-trips
#[test]
fn exact_length_still_decodes() {
    // Declared length 4 == two u16 elements.
    let input = [4u8, 0x00, 0x01, 0x00, 0x02];
    let (v, rest) = TlsVecU8::<u16>::tls_deserialize_bytes(&input).expect("should decode");
    assert_eq!(v.as_slice(), &[1u16, 2]);
    assert!(rest.is_empty());
}

// Oversized length must not overflow, just report EndOfStream
#[test]
fn truncated_byte_vec_reports_end_of_stream() {
    // A u32 length prefix advertising a large length with no content bytes.
    // The range computation must not overflow `usize`; it must fail cleanly.
    let mut input = u32::MAX.to_be_bytes().to_vec();
    input.push(0xAA); // one stray content byte, far fewer than advertised
    let res = TlsByteVecU32::tls_deserialize_bytes(&input);
    assert!(
        matches!(
            res,
            Err(Error::EndOfStream) | Err(Error::InvalidVectorLength)
        ),
        "expected EndOfStream/InvalidVectorLength, got {res:?}"
    );
}

// The length-summing overflow/saturation branches only exist on non-64-bit
// targets (on 64-bit, lengths are bounded by `isize::MAX` and can't overflow
// `usize`). This test therefore only compiles and runs on 32-bit — e.g. the
// i686 CI target. It uses a mock element whose reported serialized length is
// `usize::MAX` so that summing two of them exercises the saturating/overflow
// path.
#[cfg(target_pointer_width = "32")]
mod overflow_32bit {
    use tls_codec::{SerializeBytes, Size};

    struct HugeLen;

    impl Size for HugeLen {
        fn tls_serialized_len(&self) -> usize {
            usize::MAX
        }
    }

    impl SerializeBytes for HugeLen {
        fn tls_serialize(&self) -> Result<Vec<u8>, tls_codec::Error> {
            // Never actually reached: the length sum overflows before any
            // element is serialized.
            Ok(Vec::new())
        }
    }

    // The checked length-summing path must reject an overflowing sum instead of
    // wrapping `usize` and writing a truncated length prefix.
    #[test]
    fn serializing_overflowing_length_is_rejected() {
        let v = vec![HugeLen, HugeLen];
        let res = v.tls_serialize();
        assert!(
            matches!(res, Err(tls_codec::Error::InvalidVectorLength)),
            "expected InvalidVectorLength, got {res:?}"
        );
    }

    // The infallible `Size` path must saturate (not panic on overflow) so that
    // the oversized length is subsequently rejected rather than wrapping.
    #[test]
    fn size_saturates_instead_of_panicking() {
        let v = vec![HugeLen, HugeLen];
        assert_eq!(v.tls_serialized_len(), usize::MAX);
    }
}
