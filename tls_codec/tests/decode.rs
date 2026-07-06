#![cfg(feature = "std")]
// These tests intentionally exercise the deprecated `VLBytes` for backward
// compatibility coverage.
#![allow(deprecated)]

use tls_codec::{
    Error, Serialize, Size, TlsByteSliceU16, TlsByteVecU8, TlsByteVecU16, TlsByteVecU32,
    TlsSliceU16, TlsVecU8, TlsVecU16, TlsVecU32, U24, VLByteSlice, VLBytes,
};

/// A `VLBytes` element encoded with a *non-minimal* 2-byte varint length prefix
/// (`0x40 0x01`) for a single payload byte (`0xAA`). Actual wire size is 3, but
/// `tls_serialized_len()` reports the canonical size of 2.
const NON_MINIMAL_ELEMENT: &[u8] = &[0x40, 0x01, 0xAA];

#[test]
fn deserialize_primitives() {
    use tls_codec::Deserialize;
    let mut b = &[77u8, 88, 1, 99] as &[u8];

    let a = u8::tls_deserialize(&mut b).expect("Unable to tls_deserialize");
    assert_eq!(1, a.tls_serialized_len());
    assert_eq!(77, a);
    let a = u8::tls_deserialize(&mut b).expect("Unable to tls_deserialize");
    assert_eq!(1, a.tls_serialized_len());
    assert_eq!(88, a);
    let a = u16::tls_deserialize(&mut b).expect("Unable to tls_deserialize");
    assert_eq!(2, a.tls_serialized_len());
    assert_eq!(355, a);

    // It's empty now.
    assert!(u8::tls_deserialize(&mut b).is_err())
}

#[test]
fn deserialize_option_bytes() {
    use tls_codec::DeserializeBytes;
    for b in [Some(0u8), None] {
        let b_encoded = b.tls_serialize_detached().expect("Unable to tls_serialize");
        let (b_decoded, remainder) = Option::<u8>::tls_deserialize_bytes(b_encoded.as_slice())
            .expect("Unable to tls_deserialize");

        assert!(remainder.is_empty());

        assert_eq!(b_decoded, b);
    }
}

#[test]
fn deserialize_bytes_primitives() {
    use tls_codec::DeserializeBytes;
    let b = &[77u8, 88, 1, 99, 1, 0, 73] as &[u8];

    let (a, remainder) = u8::tls_deserialize_bytes(b).expect("Unable to tls_deserialize");
    assert_eq!(1, a.tls_serialized_len());
    assert_eq!(77, a);
    let (a, remainder) = u8::tls_deserialize_bytes(remainder).expect("Unable to tls_deserialize");
    assert_eq!(1, a.tls_serialized_len());
    assert_eq!(88, a);
    let (a, remainder) = u16::tls_deserialize_bytes(remainder).expect("Unable to tls_deserialize");
    assert_eq!(2, a.tls_serialized_len());
    assert_eq!(355, a);
    let (a, remainder) = U24::tls_deserialize_bytes(remainder).expect("Unable to tls_deserialize");
    assert_eq!(3, a.tls_serialized_len());
    assert_eq!(U24::try_from(65609usize).unwrap(), a);

    // It's empty now.
    assert!(remainder.is_empty());
    assert!(u8::tls_deserialize_bytes(remainder).is_err())
}

#[test]
fn deserialize_tls_vec() {
    use tls_codec::Deserialize;
    let mut b = &[1u8, 4, 77, 88, 1, 99] as &[u8];

    let a = u8::tls_deserialize(&mut b).expect("Unable to tls_deserialize");
    assert_eq!(1, a);
    assert_eq!(1, a.tls_serialized_len());
    println!("b: {b:?}");
    let v = TlsVecU8::<u8>::tls_deserialize(&mut b).expect("Unable to tls_deserialize");
    assert_eq!(5, v.tls_serialized_len());
    assert_eq!(&[77, 88, 1, 99], v.as_slice());

    // It's empty now.
    assert!(u8::tls_deserialize(&mut b).is_err());

    let long_vector = vec![77u8; 65535];
    let serialized_long_vec = TlsSliceU16(&long_vector).tls_serialize_detached().unwrap();
    let deserialized_long_vec =
        TlsVecU16::<u8>::tls_deserialize(&mut serialized_long_vec.as_slice()).unwrap();
    assert_eq!(
        deserialized_long_vec.tls_serialized_len(),
        long_vector.len() + 2
    );
    assert_eq!(long_vector.len(), deserialized_long_vec.len());
    assert_eq!(long_vector.as_slice(), deserialized_long_vec.as_slice());
}

#[test]
fn deserialize_bytes_tls_vec() {
    use tls_codec::DeserializeBytes;
    let b = &[1u8, 4, 77, 88, 1, 99] as &[u8];

    let (a, remainder) = u8::tls_deserialize_bytes(b).expect("Unable to tls_deserialize");
    assert_eq!(1, a);
    assert_eq!(1, a.tls_serialized_len());
    println!("b: {b:?}");
    let (v, remainder) =
        TlsVecU8::<u8>::tls_deserialize_bytes(remainder).expect("Unable to tls_deserialize");
    assert_eq!(5, v.tls_serialized_len());
    assert_eq!(&[77, 88, 1, 99], v.as_slice());

    // It's empty now.
    assert!(u8::tls_deserialize_bytes(remainder).is_err());

    let long_vector = vec![77u8; 65535];
    let serialized_long_vec = TlsSliceU16(&long_vector).tls_serialize_detached().unwrap();
    let (deserialized_long_vec, _remainder) =
        TlsVecU16::<u8>::tls_deserialize_bytes(serialized_long_vec.as_slice()).unwrap();
    assert_eq!(
        deserialized_long_vec.tls_serialized_len(),
        long_vector.len() + 2
    );
    assert_eq!(long_vector.len(), deserialized_long_vec.len());
    assert_eq!(long_vector.as_slice(), deserialized_long_vec.as_slice());
}

#[test]
fn deserialize_tls_byte_vec() {
    use tls_codec::Deserialize;
    let mut b = &[1u8, 4, 77, 88, 1, 99] as &[u8];

    let a = u8::tls_deserialize(&mut b).expect("Unable to tls_deserialize");
    assert_eq!(1, a);
    assert_eq!(1, a.tls_serialized_len());
    println!("b: {b:?}");
    let v = TlsByteVecU8::tls_deserialize(&mut b).expect("Unable to tls_deserialize");
    assert_eq!(5, v.tls_serialized_len());
    assert_eq!(&[77, 88, 1, 99], v.as_slice());

    // It's empty now.
    assert!(u8::tls_deserialize(&mut b).is_err());

    let long_vector = vec![77u8; 65535];
    let serialized_long_vec = TlsByteSliceU16(&long_vector)
        .tls_serialize_detached()
        .unwrap();
    let deserialized_long_vec =
        TlsByteVecU16::tls_deserialize(&mut serialized_long_vec.as_slice()).unwrap();
    assert_eq!(
        deserialized_long_vec.tls_serialized_len(),
        long_vector.len() + 2
    );
    assert_eq!(long_vector.len(), deserialized_long_vec.len());
    assert_eq!(long_vector.as_slice(), deserialized_long_vec.as_slice());
}

#[test]
fn deserialize_tuples() {
    use tls_codec::Deserialize;
    let t = (
        TlsVecU16::from(vec![1u8, 2, 3]),
        TlsVecU32::from(vec![1u16, 2, 3]),
    );
    let t1 = TlsVecU16::from(vec![1u8, 2, 3]);
    let t2 = TlsVecU32::from(vec![1u16, 2, 3]);
    let t_borrowed = (&t1, &t2);

    let mut bytes = Vec::new();
    let serialized_len = t
        .tls_serialize(&mut bytes)
        .expect("Error serializing tuple");
    assert_eq!(serialized_len, 2 + 3 + 4 + 6);

    let mut bytes2 = Vec::new();
    let serialized_len = t_borrowed
        .tls_serialize(&mut bytes2)
        .expect("Error serializing borrow tuple");
    assert_eq!(serialized_len, 2 + 3 + 4 + 6);

    {
        use tls_codec::DeserializeBytes;
        let (deserialized_bytes, _remainder) =
            <(TlsVecU16<u8>, TlsVecU32<u16>)>::tls_deserialize_bytes(bytes.as_slice())
                .expect("Error deserializing tuple.");
        assert_eq!(deserialized_bytes, t);
    }

    let deserialized = <(TlsVecU16<u8>, TlsVecU32<u16>)>::tls_deserialize(&mut bytes.as_slice())
        .expect("Error deserializing tuple.");
    assert_eq!(deserialized, t);
}

#[test]
fn deserialize_var_len_vec() {
    use tls_codec::Deserialize;
    fn test_it<
        T: Serialize + Deserialize + tls_codec::DeserializeBytes + std::fmt::Debug + PartialEq,
    >(
        v: Vec<T>,
    ) {
        let serialized = v.tls_serialize_detached().expect("Error encoding vector");
        let deserialized: Vec<T> =
            Vec::tls_deserialize(&mut serialized.as_slice()).expect("Error deserializing vector");
        assert_eq!(deserialized, v);
        {
            use tls_codec::DeserializeBytes;
            let serialized = v.tls_serialize_detached().expect("Error encoding vector");
            let (deserialized, _remainder): (Vec<T>, &[u8]) =
                Vec::<T>::tls_deserialize_bytes(serialized.as_slice())
                    .expect("Error deserializing vector");
            assert_eq!(deserialized, v);
        }
    }

    let v = vec![9u8, 2, 98, 34, 55, 90, 54];
    let serialized = v.tls_serialize_detached().expect("Error encoding vector");
    assert_eq!(serialized, vec![7, 9, 2, 98, 34, 55, 90, 54]);
    test_it(v);

    let v  = b"Geilo is a centre in the municipality of Hol in Viken county, Norway. Geilo is primarily a ski resort town, with around 2,500 inhabitants. It is situated in the valley of Hallingdal, 250 km from Oslo and 260 km from Bergen. The Bergen Line facilitated Geilo's development as the first skiing resort in the country, and it is still one of the largest. It is also known for having some of the most luxurious and expensive holiday cabins in Norway. The center of the town lies at 800 meters above sea level, and its highest point is 1178 meters above sea level.".to_vec();
    test_it(v);

    let first = b"".to_vec();
    let second = b"".to_vec();
    let third = b"".to_vec();
    let v = vec![first, second, third];
    test_it(v);

    let first =
        b"The Three Pigs is a children's picture book written and illustrated by David Wiesner"
            .to_vec();
    let second = b"Published in 2001, the book is based on the traditional tale of the Three Little Pigs, though in this story they step out of their own tale and wander into others, depicted in different illustration styles.".to_vec();
    let third = b"Wiesner won the 2002 Caldecott Medal for his illustrations, Wiesner's second of three such medals.".to_vec();
    let v = vec![first, second, third];
    test_it(v);
}

#[test]
fn deserialize_tls_vl_bytes() {
    use tls_codec::Deserialize;
    let mut b = &[4u8, 77, 88, 1, 99] as &[u8];

    let v = VLBytes::tls_deserialize(&mut b).expect("Unable to tls_deserialize");
    assert_eq!(5, v.tls_serialized_len());
    assert_eq!(&[77, 88, 1, 99], v.as_slice());

    // It's empty now.
    assert!(u8::tls_deserialize(&mut b).is_err());

    let long_vector = vec![77u8; 65535];
    let serialized_long_vec = VLByteSlice(&long_vector).tls_serialize_detached().unwrap();
    assert_eq!(serialized_long_vec[0], 0x80);
    let deserialized_long_vec =
        VLBytes::tls_deserialize(&mut serialized_long_vec.as_slice()).unwrap();
    assert_eq!(
        deserialized_long_vec.tls_serialized_len(),
        long_vector.len() + 4
    );
    assert_eq!(long_vector.len(), deserialized_long_vec.as_slice().len());
    assert_eq!(long_vector.as_slice(), deserialized_long_vec.as_slice());
}

#[test]
fn deserialize_bytes_tls_vl_bytes() {
    use tls_codec::DeserializeBytes;
    let b = &[4u8, 77, 88, 1, 99];

    let (v, remainder) = VLBytes::tls_deserialize_bytes(b).expect("Unable to tls_deserialize");
    assert_eq!(5, v.tls_serialized_len());
    assert_eq!(&[77, 88, 1, 99], v.as_slice());

    // There is no remainder
    assert!(remainder.is_empty());

    let long_vector = vec![77u8; 65535];
    let serialized_long_vec = VLByteSlice(&long_vector).tls_serialize_detached().unwrap();
    std::println!("bytes: {:x?}", &serialized_long_vec[0..5]);
    let (deserialized_long_vec, remainder) =
        VLBytes::tls_deserialize_bytes(serialized_long_vec.as_slice()).unwrap();
    assert_eq!(
        deserialized_long_vec.tls_serialized_len(),
        long_vector.len() + 4
    );
    assert!(remainder.is_empty());
    assert_eq!(long_vector.len(), deserialized_long_vec.as_slice().len());
    assert_eq!(long_vector.as_slice(), deserialized_long_vec.as_slice());
}

#[test]
fn deserialize_tls_vl_invalid_length() {
    use tls_codec::Deserialize;
    let mut b = &[0x40u8, 3, 10, 20, 30] as &[u8];
    let result = VLBytes::tls_deserialize(&mut b);
    if cfg!(feature = "mls") {
        assert_eq!(result, Err(Error::InvalidVectorLength));
    } else {
        let deserialized = result.expect("Unable to tls_deserialize");
        assert_eq!(deserialized.as_slice(), [10, 20, 30]);
    }
}

#[test]
fn deserialize_bytes_tls_vl_invalid_length() {
    use tls_codec::DeserializeBytes;
    let b = &[0x40u8, 3, 10, 20, 30] as &[u8];
    let result = VLBytes::tls_deserialize_bytes(b);
    if cfg!(feature = "mls") {
        assert_eq!(result, Err(Error::InvalidVectorLength));
    } else {
        let (deserialized, _remainder) = result.expect("Unable to tls_deserialize");
        assert_eq!(deserialized.as_slice(), [10, 20, 30]);
    }
}

#[test]
fn deserialize_empty_vl_bytes() {
    use tls_codec::Deserialize;
    let mut b: &[u8] = &[0x00];
    VLBytes::tls_deserialize(&mut b).expect("Error parsing empty bytes");

    let mut b: &[u8] = &[];
    VLBytes::tls_deserialize(&mut b).expect_err("Empty bytes were parsed successfully");
}

#[test]
fn deserialize_bytes_empty_vl_bytes() {
    use tls_codec::DeserializeBytes;
    let b: &[u8] = &[0x00];
    VLBytes::tls_deserialize_bytes(b).expect("Error parsing empty bytes");

    let b: &[u8] = &[];
    VLBytes::tls_deserialize_bytes(b).expect_err("Empty bytes were parsed successfully");
}

// The `Deserialize` (Read) and `DeserializeBytes` paths for element vectors must
// agree, even for non-canonical inner encodings. The Read path bounds the reader
// to the declared length and measures actual consumption instead of trusting
// `tls_serialized_len()`.
#[test]
fn read_and_bytes_paths_agree_on_non_minimal_inner_length() {
    use tls_codec::{Deserialize, DeserializeBytes};
    // `Vec<VLBytes>` uses a varint outer length. Declared content length = 3,
    // followed by the single (non-minimally encoded) 3-byte element.
    let mut input = vec![0x03];
    input.extend_from_slice(NON_MINIMAL_ELEMENT);

    let bytes_res = Vec::<VLBytes>::tls_deserialize_exact_bytes(&input);

    let mut read_input = input.as_slice();
    let read_res = Vec::<VLBytes>::tls_deserialize(&mut read_input);

    if cfg!(feature = "mls") {
        // MLS requires minimum-size length encoding, so both paths reject it.
        assert!(bytes_res.is_err());
        assert!(read_res.is_err());
    } else {
        // Both paths must accept it and produce the identical result.
        let expected = vec![VLBytes::new(vec![0xAA])];
        assert_eq!(bytes_res.as_ref().unwrap(), &expected);
        assert_eq!(read_res.as_ref().unwrap(), &expected);
        // And the Read path must have consumed the whole input.
        assert!(read_input.is_empty());
    }
}

#[test]
fn read_and_bytes_paths_agree_on_non_minimal_inner_length_fixed_len_vec() {
    use tls_codec::{Deserialize, DeserializeBytes};
    // Same as above but with a fixed-size (u8) outer length field.
    let mut input = vec![0x03];
    input.extend_from_slice(NON_MINIMAL_ELEMENT);

    let bytes_res = TlsVecU8::<VLBytes>::tls_deserialize_exact_bytes(&input);

    let mut read_input = input.as_slice();
    let read_res = TlsVecU8::<VLBytes>::tls_deserialize(&mut read_input);

    if cfg!(feature = "mls") {
        assert!(bytes_res.is_err());
        assert!(read_res.is_err());
    } else {
        let expected = TlsVecU8::from(vec![VLBytes::new(vec![0xAA])]);
        assert_eq!(bytes_res.as_ref().unwrap(), &expected);
        assert_eq!(read_res.as_ref().unwrap(), &expected);
        assert!(read_input.is_empty());
    }
}

#[test]
fn canonical_element_vec_still_round_trips() {
    use tls_codec::{Deserialize, DeserializeBytes};
    // Guard against a regression in the bounded-reader loop for canonical input.
    let original: Vec<VLBytes> = vec![
        VLBytes::new(vec![1, 2, 3]),
        VLBytes::new(vec![]),
        VLBytes::new(vec![4]),
    ];
    let serialized = original.tls_serialize_detached().unwrap();

    let mut read_input = serialized.as_slice();
    let read = Vec::<VLBytes>::tls_deserialize(&mut read_input).unwrap();
    assert_eq!(read, original);
    assert!(read_input.is_empty());

    let (bytes, remainder) = Vec::<VLBytes>::tls_deserialize_bytes(&serialized).unwrap();
    assert_eq!(bytes, original);
    assert!(remainder.is_empty());
}

// Read-based byte-vector deserialization must not eagerly allocate based on an
// untrusted length field.
#[test]
fn oversized_length_field_does_not_over_allocate() {
    use tls_codec::Deserialize;
    // TlsByteVecU32 declares ~4 GiB of content but only 3 bytes are present.
    // The bounded reader must return an error promptly instead of allocating
    // 4 GiB up front.
    let input = &[0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3];
    let mut read_input = input.as_slice();
    let res = TlsByteVecU32::tls_deserialize(&mut read_input);
    assert!(res.is_err());

    // Same for the varint-length VLBytes: an 8-byte varint declaring a huge
    // length with only one trailing byte.
    let input = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
    let mut read_input = input.as_slice();
    let res = VLBytes::tls_deserialize(&mut read_input);
    assert!(res.is_err());
}

#[test]
fn byte_vec_round_trips_beyond_prealloc_cap() {
    use tls_codec::Deserialize;
    // Larger than the internal MAX_PREALLOC (4096) so the bounded reader has to
    // loop across multiple chunks and grow the vector.
    let payload = vec![0x5Au8; 10_000];
    let original = TlsByteVecU32::from(payload.clone());
    let serialized = original.tls_serialize_detached().unwrap();

    let mut read_input = serialized.as_slice();
    let read = TlsByteVecU32::tls_deserialize(&mut read_input).unwrap();
    assert_eq!(read.as_slice(), payload.as_slice());
    assert!(read_input.is_empty());
}
