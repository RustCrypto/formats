#![cfg(feature = "std")]

use tls_codec::{
    Deserialize, Serialize, Size, TlsByteSliceU16, TlsByteVecU16, TlsByteVecU8, TlsSliceU16,
    TlsVecU16, TlsVecU32, TlsVecU8, VLByteSlice, VLBytes,
};

#[test]
fn deserialize_primitives() {
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
fn deserialize_tls_vec() {
    let mut b = &[1u8, 4, 77, 88, 1, 99] as &[u8];

    let a = u8::tls_deserialize(&mut b).expect("Unable to tls_deserialize");
    assert_eq!(1, a);
    assert_eq!(1, a.tls_serialized_len());
    println!("b: {:?}", b);
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
fn deserialize_tls_byte_vec() {
    let mut b = &[1u8, 4, 77, 88, 1, 99] as &[u8];

    let a = u8::tls_deserialize(&mut b).expect("Unable to tls_deserialize");
    assert_eq!(1, a);
    assert_eq!(1, a.tls_serialized_len());
    println!("b: {:?}", b);
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

    let deserialized = <(TlsVecU16<u8>, TlsVecU32<u16>)>::tls_deserialize(&mut bytes.as_slice())
        .expect("Error deserializing tuple.");
    assert_eq!(deserialized, t);
}

#[test]
fn deserialize_var_len_vec() {
    fn test_it<T: Serialize + Deserialize + std::fmt::Debug + PartialEq>(v: Vec<T>) {
        let serialized = v.tls_serialize_detached().expect("Error encoding vector");
        let deserialized: Vec<T> =
            Vec::tls_deserialize(&mut serialized.as_slice()).expect("Error deserializing vector");
        assert_eq!(deserialized, v);
    }

    let v = vec![9u8, 2, 98, 34, 55, 90, 54];
    let serialized = v.tls_serialize_detached().expect("Error encoding vector");
    assert_eq!(serialized, vec![0b00 << 6 | 7, 9, 2, 98, 34, 55, 90, 54]);
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
    let mut b = &[4u8, 77, 88, 1, 99] as &[u8];

    let v = VLBytes::tls_deserialize(&mut b).expect("Unable to tls_deserialize");
    assert_eq!(5, v.tls_serialized_len());
    assert_eq!(&[77, 88, 1, 99], v.as_slice());

    // It's empty now.
    assert!(u8::tls_deserialize(&mut b).is_err());

    let long_vector = vec![77u8; 65535];
    let serialized_long_vec = VLByteSlice(&long_vector).tls_serialize_detached().unwrap();
    std::println!("bytes: {:x?}", &serialized_long_vec[0..5]);
    let deserialized_long_vec =
        VLBytes::tls_deserialize(&mut serialized_long_vec.as_slice()).unwrap();
    assert_eq!(
        deserialized_long_vec.tls_serialized_len(),
        long_vector.len() + 4
    );
    assert_eq!(long_vector.len(), deserialized_long_vec.as_slice().len());
    assert_eq!(long_vector.as_slice(), deserialized_long_vec.as_slice());
}
