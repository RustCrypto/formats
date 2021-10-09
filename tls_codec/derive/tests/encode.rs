use tls_codec::{SecretTlsVecU16, Serialize, Size, TlsSliceU16, TlsVecU16, TlsVecU32};
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
pub struct TupleStruct1(ExtensionStruct);

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
