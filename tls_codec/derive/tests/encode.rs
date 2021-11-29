use tls_codec::{SecretTlsVecU16, Serialize, TlsSliceU16, TlsVecU16, TlsVecU32};
use tls_codec_derive::{TlsSerialize, TlsSize};

#[derive(TlsSerialize, TlsSize, Debug)]
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

#[derive(TlsSerialize, TlsSize, Debug)]
pub struct ExtensionStruct {
    extension_type: ExtensionType,
    extension_data: TlsVecU32<u8>,
    additional_data: Option<SecretTlsVecU16<u8>>,
}

#[derive(TlsSerialize, TlsSize, Debug)]
pub struct TupleStruct(ExtensionStruct, u8);

#[derive(TlsSerialize, TlsSize, Debug)]
pub struct StructWithLifetime<'a> {
    value: &'a TlsVecU16<u8>,
}

#[derive(TlsSerialize, TlsSize, Debug, Clone)]
struct SomeValue {
    val: TlsVecU16<u8>,
}

#[derive(TlsSerialize, TlsSize)]
pub struct StructWithDoubleLifetime<'a, 'b> {
    value: &'a TlsSliceU16<'a, &'b SomeValue>,
}

#[test]
fn lifetime_struct() {
    let value: TlsVecU16<u8> = vec![7u8; 33].into();
    let s = StructWithLifetime { value: &value };
    let serialized_s = s.tls_serialize_detached().unwrap();
    assert_eq!(serialized_s, value.tls_serialize_detached().unwrap());

    let some_default_value = SomeValue { val: value };
    let values = vec![some_default_value; 33];
    let ref_values: Vec<&SomeValue> = values.iter().map(|v| v).collect();
    let ref_values_slice = TlsSliceU16(&ref_values);
    let s = StructWithDoubleLifetime {
        value: &ref_values_slice,
    };
    let serialized_s = s.tls_serialize_detached().unwrap();
    assert_eq!(
        serialized_s,
        ref_values_slice.tls_serialize_detached().unwrap()
    );
}

#[test]
fn simple_enum() {
    let serialized = ExtensionType::KeyId.tls_serialize_detached().unwrap();
    assert_eq!(vec![0, 3], serialized);
    let serialized = ExtensionType::SomethingElse
        .tls_serialize_detached()
        .unwrap();
    assert_eq!(vec![1, 244], serialized);
}

#[test]
fn simple_struct() {
    let extension = ExtensionStruct {
        extension_type: ExtensionType::KeyId,
        extension_data: TlsVecU32::from_slice(&[1, 2, 3, 4, 5]),
        additional_data: None,
    };
    let serialized = extension.tls_serialize_detached().unwrap();
    assert_eq!(vec![0, 3, 0, 0, 0, 5, 1, 2, 3, 4, 5, 0], serialized);
}

#[test]
fn tuple_struct() {
    let ext = ExtensionStruct {
        extension_type: ExtensionType::KeyId,
        extension_data: TlsVecU32::from_slice(&[1, 2, 3, 4, 5]),
        additional_data: None,
    };
    let x = TupleStruct(ext, 6);
    let serialized = x.tls_serialize_detached().unwrap();
    assert_eq!(vec![0, 3, 0, 0, 0, 5, 1, 2, 3, 4, 5, 0, 6], serialized);
}

#[test]
fn byte_arrays() {
    let x = [0u8, 1, 2, 3];
    let serialized = x.tls_serialize_detached().unwrap();
    assert_eq!(vec![0, 1, 2, 3], serialized);
}

#[test]
fn lifetimes() {
    let x = vec![1, 2, 3, 4].into();
    let s = StructWithLifetime { value: &x };
    let serialized = s.tls_serialize_detached().unwrap();
    assert_eq!(vec![0, 4, 1, 2, 3, 4], serialized);

    pub fn do_some_serializing(val: &StructWithLifetime) -> Vec<u8> {
        val.tls_serialize_detached().unwrap()
    }
    let serialized = do_some_serializing(&s);
    assert_eq!(vec![0, 4, 1, 2, 3, 4], serialized);
}

#[derive(TlsSerialize, TlsSize)]
struct Custom {
    #[tls_codec(with = "custom")]
    values: Vec<u8>,
    a: u8,
}

mod custom {
    use std::io::Write;
    use tls_codec::{Serialize, Size, TlsByteSliceU32};

    pub fn tls_serialized_len(v: &[u8]) -> usize {
        TlsByteSliceU32(v).tls_serialized_len()
    }

    pub fn tls_serialize<W: Write>(v: &[u8], writer: &mut W) -> Result<usize, tls_codec::Error> {
        TlsByteSliceU32(v).tls_serialize(writer)
    }
}

#[test]
fn custom() {
    let x = Custom {
        values: vec![0, 1, 2],
        a: 3,
    };
    let serialized = x.tls_serialize_detached().unwrap();
    assert_eq!(vec![0, 0, 0, 3, 0, 1, 2, 3], serialized);
}

#[derive(TlsSerialize, TlsSize)]
struct OptionalMemberRef<'a> {
    optional_member: Option<&'a u32>,
    ref_optional_member: &'a Option<&'a u32>,
    ref_vector: &'a TlsVecU16<u16>,
}

#[test]
fn optional_member() {
    let m = 6;
    let v = vec![1, 2, 3];
    let x = OptionalMemberRef {
        optional_member: Some(&m),
        ref_optional_member: &None,
        ref_vector: &v.into(),
    };
    let serialized = x.tls_serialize_detached().unwrap();
    assert_eq!(vec![1, 0, 0, 0, 6, 0, 0, 6, 0, 1, 0, 2, 0, 3], serialized);
}

#[derive(TlsSerialize, TlsSize)]
#[repr(u8)]
enum EnumWithTupleVariant {
    A(u8, u32),
}

#[test]
fn enum_with_tuple_variant() {
    let x = EnumWithTupleVariant::A(3, 4);
    let serialized = x.tls_serialize_detached().unwrap();
    assert_eq!(vec![0, 3, 0, 0, 0, 4], serialized);
}

#[derive(TlsSerialize, TlsSize)]
#[repr(u8)]
enum EnumWithStructVariant {
    A { foo: u8, bar: u32 },
}

#[test]
fn enum_with_struct_variant() {
    let x = EnumWithStructVariant::A { foo: 3, bar: 4 };
    let serialized = x.tls_serialize_detached().unwrap();
    assert_eq!(vec![0, 3, 0, 0, 0, 4], serialized);
}

#[derive(TlsSerialize, TlsSize)]
#[repr(u16)]
enum EnumWithDataAndDiscriminant {
    #[tls_codec(discriminant = 3)]
    A(u8),
    B,
}

#[test]
fn enum_with_data_and_discriminant() {
    let x = EnumWithDataAndDiscriminant::A(4);
    let serialized = x.tls_serialize_detached().unwrap();
    assert_eq!(vec![0, 3, 4], serialized);
}

#[test]
fn discriminant_is_incremented_implicitly() {
    let x = EnumWithDataAndDiscriminant::B;
    let serialized = x.tls_serialize_detached().unwrap();
    assert_eq!(vec![0, 4], serialized);
}

#[derive(TlsSerialize, TlsSize)]
#[repr(u8)]
enum EnumWithCustomSerializedField {
    A(#[tls_codec(with = "custom")] Vec<u8>),
}

#[test]
fn enum_with_custom_serialized_field() {
    let x = EnumWithCustomSerializedField::A(vec![1, 2, 3]);
    let serialized = x.tls_serialize_detached().unwrap();
    assert_eq!(vec![0, 0, 0, 0, 3, 1, 2, 3], serialized);
}
