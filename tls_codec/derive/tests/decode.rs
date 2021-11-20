use tls_codec::{Deserialize, Serialize, Size, TlsSliceU16, TlsVecU16, TlsVecU32, TlsVecU8};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(TlsDeserialize, Debug, PartialEq, Clone, Copy, TlsSize, TlsSerialize)]
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

#[derive(TlsDeserialize, Debug, PartialEq, TlsSerialize, TlsSize, Clone, Default)]
pub struct ExtensionStruct {
    extension_type: ExtensionType,
    extension_data: TlsVecU32<u8>,
}

#[derive(TlsDeserialize, Debug, PartialEq, TlsSize, TlsSerialize)]
pub struct ExtensionTypeVec {
    data: TlsVecU8<ExtensionType>,
}

#[derive(TlsDeserialize, Debug, PartialEq, TlsSize, TlsSerialize)]
pub struct ArrayWrap {
    data: [u8; 8],
}

#[derive(TlsSerialize, TlsDeserialize, TlsSize, Debug, PartialEq)]
pub struct TupleStruct1(ExtensionStruct);

#[derive(TlsSerialize, TlsDeserialize, TlsSize, Debug, PartialEq)]
pub struct TupleStruct(ExtensionStruct, u8);

#[test]
fn tuple_struct() {
    let ext = ExtensionStruct {
        extension_type: ExtensionType::KeyId,
        extension_data: TlsVecU32::from_slice(&[1, 2, 3, 4, 5]),
    };
    let t1 = TupleStruct1(ext.clone());
    let serialized_t1 = t1.tls_serialize_detached().unwrap();
    let deserialized_t1 = TupleStruct1::tls_deserialize(&mut serialized_t1.as_slice()).unwrap();
    assert_eq!(t1, deserialized_t1);
    assert_eq!(
        serialized_t1,
        deserialized_t1.tls_serialize_detached().unwrap()
    );

    let t2 = TupleStruct(ext, 5);
    let serialized_t2 = t2.tls_serialize_detached().unwrap();
    let deserialized_t2 = TupleStruct::tls_deserialize(&mut serialized_t2.as_slice()).unwrap();
    assert_eq!(t2, deserialized_t2);
    assert_eq!(
        serialized_t2,
        deserialized_t2.tls_serialize_detached().unwrap()
    );
}

#[test]
fn simple_enum() {
    let mut b = &[0u8, 5] as &[u8];
    let deserialized = ExtensionType::tls_deserialize(&mut b).unwrap();
    assert_eq!(ExtensionType::RatchetTree, deserialized);

    let mut b = &[0u8, 5, 1, 244, 0, 1] as &[u8];
    let variants = [
        ExtensionType::RatchetTree,
        ExtensionType::SomethingElse,
        ExtensionType::Capabilities,
    ];
    for variant in variants.iter() {
        let deserialized = ExtensionType::tls_deserialize(&mut b).unwrap();
        assert_eq!(variant, &deserialized);
    }
}

#[test]
fn deserialize_tls_vec() {
    let long_vector = vec![ExtensionStruct::default(); 3000];
    let serialized_long_vec = TlsSliceU16(&long_vector).tls_serialize_detached().unwrap();
    println!("ser len: {:?}", serialized_long_vec.len());
    println!("ser len: {:?}", &serialized_long_vec[0..2]);
    let deserialized_long_vec: Vec<ExtensionStruct> =
        TlsVecU16::tls_deserialize(&mut serialized_long_vec.as_slice())
            .unwrap()
            .into();
    assert_eq!(long_vector.len(), deserialized_long_vec.len());
    assert_eq!(long_vector, deserialized_long_vec);
}

#[test]
fn byte_arrays() {
    let x = [0u8, 1, 2, 3];
    let serialized = x.tls_serialize_detached().unwrap();
    assert_eq!(x.to_vec(), serialized);

    let y = <[u8; 4]>::tls_deserialize(&mut serialized.as_slice()).unwrap();
    assert_eq!(y, x);

    let x = [0u8, 1, 2, 3, 7, 6, 5, 4];
    let w = ArrayWrap { data: x };
    let serialized = x.tls_serialize_detached().unwrap();
    assert_eq!(x.to_vec(), serialized);

    let y = ArrayWrap::tls_deserialize(&mut serialized.as_slice()).unwrap();
    assert_eq!(y, w);
}

#[test]
fn simple_struct() {
    let mut b = &[0u8, 3, 0, 0, 0, 5, 1, 2, 3, 4, 5] as &[u8];
    let extension = ExtensionStruct {
        extension_type: ExtensionType::KeyId,
        extension_data: TlsVecU32::from_slice(&[1, 2, 3, 4, 5]),
    };
    let deserialized = ExtensionStruct::tls_deserialize(&mut b).unwrap();
    assert_eq!(extension, deserialized);

    let mut b = &[8u8, 0, 1, 0, 2, 0, 3, 1, 244] as &[u8];
    let extension = ExtensionTypeVec {
        data: TlsVecU8::from_slice(&[
            ExtensionType::Capabilities,
            ExtensionType::Lifetime,
            ExtensionType::KeyId,
            ExtensionType::SomethingElse,
        ]),
    };
    let deserialized = ExtensionTypeVec::tls_deserialize(&mut b).unwrap();
    assert_eq!(extension, deserialized);
}

#[derive(TlsDeserialize, Clone, TlsSize, PartialEq)]
struct DeserializeOnlyStruct(u16);

// KAT from MLS

#[derive(TlsSerialize, TlsDeserialize, TlsSize, Clone, PartialEq)]
#[repr(u8)]
enum ProtocolVersion {
    Reserved = 0,
    Mls10 = 1,
}

#[derive(TlsSerialize, TlsDeserialize, TlsSize, Clone, PartialEq)]
struct CipherSuite(u16);

#[derive(TlsSerialize, TlsDeserialize, TlsSize, Clone, PartialEq)]
struct HPKEPublicKey(TlsVecU16<u8>);

#[derive(TlsSerialize, TlsDeserialize, TlsSize, Clone, PartialEq)]
struct CredentialType(u16);

#[derive(TlsSerialize, TlsDeserialize, TlsSize, Clone, PartialEq)]
struct SignatureScheme(u16);

#[derive(TlsSerialize, TlsDeserialize, TlsSize, Clone, PartialEq)]
struct BasicCredential {
    identity: TlsVecU16<u8>,
    signature_scheme: SignatureScheme,
    signature_key: TlsVecU16<u8>,
}

#[derive(TlsSerialize, TlsDeserialize, TlsSize, Clone, PartialEq)]
struct Credential {
    credential_type: CredentialType,
    credential: BasicCredential,
}

#[derive(TlsSerialize, TlsDeserialize, TlsSize, Clone, PartialEq)]
struct Extension {
    extension_type: ExtensionType,
    extension_data: TlsVecU32<u8>,
}

#[derive(TlsSerialize, TlsDeserialize, TlsSize, Clone, PartialEq)]
struct KeyPackage {
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
    hpke_init_key: HPKEPublicKey,
    credential: Credential,
    extensions: TlsVecU32<Extension>,
    signature: TlsVecU16<u8>,
}

#[test]
fn kat_mls_key_package() {
    let key_package_bytes = &[
        0x01u8, 0x00, 0x01, 0x00, 0x20, 0xF2, 0xBC, 0xD8, 0x95, 0x19, 0xDD, 0x1D, 0x06, 0x9F, 0x8B,
        0x9E, 0xB2, 0xEC, 0xBA, 0xA9, 0xF1, 0x67, 0xAA, 0xCC, 0x52, 0xE7, 0x4D, 0x8D, 0xFE, 0xCC,
        0xAA, 0xA3, 0xF9, 0xCF, 0x92, 0xAA, 0x35, 0x00, 0x01, 0x00, 0x0D, 0x4F, 0x70, 0x65, 0x6E,
        0x4D, 0x4C, 0x53, 0x20, 0x72, 0x6F, 0x63, 0x6B, 0x73, 0x08, 0x07, 0x00, 0x20, 0xD8, 0x0F,
        0x6A, 0x71, 0xFD, 0x5F, 0xB5, 0xEF, 0x27, 0x13, 0xE0, 0xA1, 0xD4, 0xC9, 0x28, 0x5D, 0xD2,
        0x4A, 0x5A, 0x5B, 0x21, 0xCC, 0xF5, 0x13, 0x4F, 0xDF, 0xE8, 0x25, 0xB2, 0xA6, 0x17, 0x18,
        0x00, 0x00, 0x00, 0x29, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0D, 0x02, 0x01, 0xC8, 0x02, 0x00,
        0x01, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x60, 0xA5, 0xEF, 0xCE, 0x00, 0x00, 0x00, 0x00, 0x61, 0x14, 0xBB, 0xDE,
        0x00, 0x40, 0x73, 0xE2, 0xC6, 0x9A, 0x23, 0x49, 0x24, 0x04, 0x8A, 0xC3, 0x19, 0x20, 0x72,
        0x1A, 0x14, 0xBB, 0x92, 0x52, 0x33, 0x29, 0xB0, 0xDD, 0x36, 0x08, 0x35, 0xA1, 0x6F, 0xCA,
        0xA7, 0x64, 0xB2, 0x2A, 0xC3, 0x5C, 0x47, 0x6D, 0x0C, 0x6A, 0x8E, 0x28, 0x86, 0x96, 0x94,
        0xB6, 0xC4, 0xE0, 0x2C, 0xBE, 0x00, 0xB6, 0x2D, 0x50, 0xA7, 0x39, 0xF9, 0x30, 0xA7, 0x3F,
        0x09, 0xFC, 0xA1, 0xF4, 0x53, 0x03,
    ];
    let key_package = KeyPackage::tls_deserialize(&mut (key_package_bytes as &[u8]))
        .expect("Error deserializing key package.");
    let serialized_key_package = key_package
        .tls_serialize_detached()
        .expect("Error serializing key package.");
    assert_eq!(
        key_package_bytes as &[u8],
        serialized_key_package.as_slice()
    );
}

#[derive(Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
struct Custom {
    #[tls_codec(with = "custom")]
    values: Vec<u8>,
    a: u8,
}

mod custom {
    use std::io::{Read, Write};
    use tls_codec::{Deserialize, Serialize, Size, TlsByteSliceU32, TlsByteVecU32};

    pub fn tls_serialized_len(v: &[u8]) -> usize {
        TlsByteSliceU32(v).tls_serialized_len()
    }

    pub fn tls_serialize<W: Write>(v: &[u8], writer: &mut W) -> Result<usize, tls_codec::Error> {
        TlsByteSliceU32(v).tls_serialize(writer)
    }

    pub fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Vec<u8>, tls_codec::Error> {
        Ok(TlsByteVecU32::tls_deserialize(bytes)?.into_vec())
    }
}

#[test]
fn custom() {
    let x = Custom {
        values: vec![0, 1, 2],
        a: 3,
    };
    let serialized = x.tls_serialize_detached().unwrap();
    let deserialized = Custom::tls_deserialize(&mut &*serialized).unwrap();
    assert_eq!(x, deserialized);
}
