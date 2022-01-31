#![cfg(feature = "std")]

use tls_codec::{
    Deserialize, Serialize, Size, TlsByteSliceU16, TlsByteVecU16, TlsByteVecU8, TlsSliceU16,
    TlsVecU16, TlsVecU32, TlsVecU8,
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
