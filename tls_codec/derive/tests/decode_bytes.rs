use tls_codec::{TlsVecU16, TlsVecU32, TlsVecU8};
use tls_codec_derive::{TlsDeserializeBytes, TlsSize};

#[derive(TlsDeserializeBytes, Debug, PartialEq, Clone, Copy, TlsSize)]
#[repr(u16)]
pub enum ExtensionType {
    Reserved = 0,
    Capabilities = 1,
    Lifetime = 2,
    KeyId = 3,
    ParentHash = 4,
    RatchetTree = 5,
    SomethingElse = 500,
}

impl Default for ExtensionType {
    fn default() -> Self {
        Self::Reserved
    }
}

#[derive(TlsDeserializeBytes, Debug, PartialEq, TlsSize, Clone, Default)]
pub struct ExtensionStruct {
    extension_type: ExtensionType,
    extension_data: TlsVecU32<u8>,
}

#[derive(TlsDeserializeBytes, Debug, PartialEq, TlsSize)]
pub struct ExtensionTypeVec {
    data: TlsVecU8<ExtensionType>,
}

#[derive(TlsDeserializeBytes, Debug, PartialEq, TlsSize)]
pub struct ArrayWrap {
    data: [u8; 8],
}

#[derive(TlsDeserializeBytes, TlsSize, Debug, PartialEq)]
pub struct TupleStruct1(ExtensionStruct);

#[derive(TlsDeserializeBytes, TlsSize, Debug, PartialEq)]
pub struct TupleStruct(ExtensionStruct, u8);

#[test]
fn tuple_struct() {
    let ext = ExtensionStruct {
        extension_type: ExtensionType::KeyId,
        extension_data: TlsVecU32::from_slice(&[1, 2, 3, 4, 5]),
    };
    let t1 = TupleStruct1(ext.clone());
    let serialized_t1 = vec![0, 3, 0, 0, 0, 5, 1, 2, 3, 4, 5];
    println!("{:?}", serialized_t1);
    let (deserialized_bytes_t1, _remainder) =
        <TupleStruct1 as tls_codec::DeserializeBytes>::tls_deserialize(serialized_t1.as_slice())
            .unwrap();
    assert_eq!(t1, deserialized_bytes_t1);

    let t2 = TupleStruct(ext, 5);
    let serialized_t2 = vec![0, 3, 0, 0, 0, 5, 1, 2, 3, 4, 5, 5];
    let (deserialized_bytes_t2, _remainder) =
        <TupleStruct as tls_codec::DeserializeBytes>::tls_deserialize(serialized_t2.as_slice())
            .unwrap();
    assert_eq!(t2, deserialized_bytes_t2);
}

#[test]
fn simple_enum() {
    let b = &[0u8, 5] as &[u8];
    let (deserialized_bytes, _remainder) =
        <ExtensionType as tls_codec::DeserializeBytes>::tls_deserialize(b).unwrap();
    assert_eq!(ExtensionType::RatchetTree, deserialized_bytes);

    let mut b = &[0u8, 5, 1, 244, 0, 1] as &[u8];
    let variants = [
        ExtensionType::RatchetTree,
        ExtensionType::SomethingElse,
        ExtensionType::Capabilities,
    ];
    for variant in variants.iter() {
        let (deserialized_bytes, remainder) =
            <ExtensionType as tls_codec::DeserializeBytes>::tls_deserialize(b).unwrap();
        b = remainder;
        assert_eq!(variant, &deserialized_bytes);
    }
}

#[test]
fn deserialize_tls_vec() {
    let long_vector = vec![ExtensionStruct::default(); 4];
    let serialized_long_vec = [
        0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let (deserialized_long_vec_bytes, _remainder): (Vec<ExtensionStruct>, &[u8]) =
        <TlsVecU16<ExtensionStruct> as tls_codec::DeserializeBytes>::tls_deserialize(
            serialized_long_vec.as_slice(),
        )
        .map(|(v, r)| (v.into(), r))
        .unwrap();
    assert_eq!(long_vector.len(), deserialized_long_vec_bytes.len());
    assert_eq!(long_vector, deserialized_long_vec_bytes);
}
