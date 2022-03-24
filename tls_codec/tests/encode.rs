#![cfg(feature = "std")]

use tls_codec::{Serialize, TlsVecU16, VLByteSlice, VLBytes};

#[test]
fn serialize_primitives() {
    let mut v = Vec::new();
    77u8.tls_serialize(&mut v).expect("Error encoding u8");
    88u8.tls_serialize(&mut v).expect("Error encoding u8");
    355u16.tls_serialize(&mut v).expect("Error encoding u16");
    let b = [77u8, 88, 1, 99];
    assert_eq!(&b[..], &v[..]);
}

#[test]
fn serialize_tls_vec() {
    let mut v = Vec::new();
    1u8.tls_serialize(&mut v).expect("Error encoding u8");
    TlsVecU16::<u8>::from_slice(&[77, 88, 1, 99])
        .tls_serialize(&mut v)
        .expect("Error encoding u8");

    let b = [1u8, 0, 4, 77, 88, 1, 99];
    assert_eq!(&b[..], &v[..]);
}

#[test]
fn serialize_var_len_vec() {
    let v = vec![9u8, 2, 98, 34, 55, 90, 54];
    let serialized = v.tls_serialize_detached().expect("Error encoding vector");
    assert_eq!(serialized, vec![0b00 << 6 | 7, 9, 2, 98, 34, 55, 90, 54]);

    let serialized = Vec::<u8>::new()
        .tls_serialize_detached()
        .expect("Error encoding vector");
    assert_eq!(serialized, vec![0x00]);
}

#[test]
fn serialize_var_len_bytes() {
    let v = VLBytes::new(vec![9u8, 2, 98, 34, 55, 90, 54]);
    let serialized = v.tls_serialize_detached().expect("Error encoding vector");
    assert_eq!(serialized, vec![0b00 << 6 | 7, 9, 2, 98, 34, 55, 90, 54]);

    let serialized = VLBytes::new(vec![])
        .tls_serialize_detached()
        .expect("Error encoding vector");
    assert_eq!(serialized, vec![0x00]);

    let v = vec![9u8, 2, 98, 34, 55, 90, 54];
    let serialized = VLByteSlice(&v)
        .tls_serialize_detached()
        .expect("Error encoding vector");
    assert_eq!(serialized, vec![0b00 << 6 | 7, 9, 2, 98, 34, 55, 90, 54]);

    let serialized = VLByteSlice(&[])
        .tls_serialize_detached()
        .expect("Error encoding vector");
    assert_eq!(serialized, vec![0x00]);
}
