#![cfg(feature = "serde")]

use tls_codec::{Bytes, VLBytes};

// Old VLBytes without serde bytes serialization
#[derive(serde::Serialize, serde::Deserialize)]
struct OldVLBytes {
    vec: Vec<u8>,
}

impl From<VLBytes> for OldVLBytes {
    fn from(v: VLBytes) -> Self {
        OldVLBytes { vec: v.into() }
    }
}

#[test]
fn serde_impls() {
    let value = VLBytes::from(vec![32; 128]);
    let old_value: OldVLBytes = value.clone().into();
    let mut new_serialized = Vec::new();
    ciborium::into_writer(&value, &mut new_serialized).unwrap();
    let mut old_serialized = Vec::new();
    ciborium::into_writer(&old_value, &mut old_serialized).unwrap();

    // Serialization format has changed
    assert_ne!(new_serialized, old_serialized);
    assert!(new_serialized.len() < old_serialized.len());

    // We should be able to deserialize both into the new format
    let deserialized: VLBytes = ciborium::from_reader(new_serialized.as_slice()).unwrap();
    let old_deserialized: VLBytes = ciborium::from_reader(old_serialized.as_slice()).unwrap();

    assert_eq!(deserialized, old_deserialized);
}

#[test]
fn bytes_is_transparent() {
    let data = vec![32; 128];
    let bytes_value = Bytes::new(data.clone());
    let vlbytes_value = VLBytes::new(data);

    let mut bytes_serialized = Vec::new();
    ciborium::into_writer(&bytes_value, &mut bytes_serialized).unwrap();
    let mut vlbytes_serialized = Vec::new();
    ciborium::into_writer(&vlbytes_value, &mut vlbytes_serialized).unwrap();

    // Bytes (transparent) should produce smaller output than VLBytes (has field name)
    assert!(bytes_serialized.len() < vlbytes_serialized.len());

    // Bytes should roundtrip
    let deserialized: Bytes = ciborium::from_reader(bytes_serialized.as_slice()).unwrap();
    assert_eq!(deserialized, bytes_value);
}

#[test]
fn bytes_vlbytes_cross_deserialization() {
    let data = vec![42; 64];
    let bytes_value = Bytes::new(data.clone());
    let vlbytes_value = VLBytes::new(data);

    let mut bytes_serialized = Vec::new();
    ciborium::into_writer(&bytes_value, &mut bytes_serialized).unwrap();
    let mut vlbytes_serialized = Vec::new();
    ciborium::into_writer(&vlbytes_value, &mut vlbytes_serialized).unwrap();

    // Bytes can deserialize VLBytes-serialized data
    let from_vlbytes: Bytes = ciborium::from_reader(vlbytes_serialized.as_slice()).unwrap();
    assert_eq!(from_vlbytes, bytes_value);
}
