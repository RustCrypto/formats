use std::println;

use crate::alloc::vec::Vec;

use crate::{Serialize as _, VLByteSlice};
use serde::{ser, Serialize};

use super::error::{Error, Result};

pub struct Serializer {
    // This vector starts empty and JSON is appended as values are serialized.
    output: Vec<u8>,
}

// By convention, the public API of a Serde serializer is one or more `to_abc`
// functions such as `to_string`, `to_bytes`, or `to_writer` depending on what
// Rust types the serializer is able to produce as output.
//
// This basic serializer supports only `to_bytes`.
pub fn to_bytes<T>(value: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let mut serializer = Serializer { output: Vec::new() };
    value.serialize(&mut serializer)?;
    Ok(serializer.output)
}

impl Serializer {
    fn serialize<V: crate::Serialize>(&mut self, v: V) -> Result<()> {
        self.output
            .extend_from_slice(&v.tls_serialize_detached().map_err(|_| Error::CodecError)?);
        Ok(())
    }
}

impl<'a> ser::Serializer for &'a mut Serializer {
    // The output type produced by this `Serializer` during successful
    // serialization. Most serializers that produce text or binary output should
    // set `Ok = ()` and serialize into an `io::Write` or buffer contained
    // within the `Serializer` instance, as happens here. Serializers that build
    // in-memory data structures may be simplified by using `Ok` to propagate
    // the data structure around.
    type Ok = ();

    // The error type when some error occurs during serialization.
    type Error = Error;

    // Associated types for keeping track of additional state while serializing
    // compound data structures like sequences and maps. In this case no
    // additional state is required beyond what is already stored in the
    // Serializer struct.
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, _: bool) -> Result<()> {
        Result::Err(Error::Unsupported)
    }

    fn serialize_i8(self, v: i8) -> Result<()> {
        unimplemented!()
    }

    fn serialize_i16(self, v: i16) -> Result<()> {
        unimplemented!()
    }

    fn serialize_i32(self, v: i32) -> Result<()> {
        unimplemented!()
    }

    fn serialize_i64(self, v: i64) -> Result<()> {
        unimplemented!()
    }

    fn serialize_u8(self, v: u8) -> Result<()> {
        self.serialize(v)
    }

    fn serialize_u16(self, v: u16) -> Result<()> {
        self.serialize(v)
    }

    fn serialize_u32(self, v: u32) -> Result<()> {
        self.serialize(v)
    }

    fn serialize_u64(self, v: u64) -> Result<()> {
        self.serialize(v)
    }

    fn serialize_f32(self, v: f32) -> Result<()> {
        unimplemented!()
    }

    fn serialize_f64(self, v: f64) -> Result<()> {
        unimplemented!()
    }

    fn serialize_char(self, v: char) -> Result<()> {
        unimplemented!()
    }

    fn serialize_str(self, v: &str) -> Result<()> {
        v.as_bytes().serialize(&mut *self)
    }

    // XXX: Note that this is not correct in general, but for MLS.
    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        self.output.extend_from_slice(
            &VLByteSlice(v)
                .tls_serialize_detached()
                .map_err(|_| Error::CodecError)?,
        );
        Ok(())
    }

    fn serialize_none(self) -> Result<()> {
        // The type here is irrelevant.
        self.serialize::<Option<u8>>(Option::None)
    }

    fn serialize_some<T>(self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        self.serialize(1u8)?;
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<()> {
        unimplemented!()
    }

    // Unit struct means a named value containing no data. Again, since there is
    // no data, map this to JSON as `null`. There is no need to serialize the
    // name in most formats.
    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        self.serialize_unit()
    }

    // When serializing a unit variant (or any other kind of variant), formats
    // can choose whether to keep track of it by index or by name. Binary
    // formats typically use the index of the variant and human-readable formats
    // typically use the name.
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
    ) -> Result<()> {
        // For TLS, we use the index.
        // TODO: In TLS codec we allow variants, but only with a representation.
        //       TLS syntax itself does not support enums like this. Check how
        //       this is used.
        self.serialize_u32(variant_index)
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain.
    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    // Note that newtype variant (and all of the other variant serialization
    // methods) refer exclusively to the "externally tagged" enum
    // representation.
    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        self.serialize_u32(variant_index)?;
        value.serialize(&mut *self)?;
        Ok(())
    }

    // Now we get to the serialization of compound types.
    //
    // The start of the sequence, each value, and the end are three separate
    // method calls. This one is responsible only for serializing the start.
    // In TLS this is the length
    //
    // The length of the sequence may or may not be known ahead of time.
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        // Serialize the length as variable encoding. This only works for MLS/QUIC.
        if let Some(len) = len {
            self.output.extend_from_slice(
                &crate::quic_vec::write_variable_length(len)
                    .map_err(|_| Error::VariableLengthError)?,
            );
        } else {
            return Err(Error::SequenceWithoutLength);
        }
        Ok(self)
    }

    // Tuples look just like sequences in JSON. Some formats may be able to
    // represent tuples more efficiently by omitting the length, since tuple
    // means that the corresponding `Deserialize implementation will know the
    // length without needing to look at the serialized data.
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        self.serialize_seq(Some(len))
    }

    // Tuple structs look just like sequences in JSON.
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        self.serialize_seq(Some(len))
    }

    // Tuple variants are represented in JSON as `{ NAME: [DATA...] }`. Again
    // this method is only responsible for the externally tagged representation.
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        variant_index.serialize(&mut *self)?;
        Ok(self)
    }

    // Maps are represented in JSON as `{ K: V, K: V, ... }`.
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        todo!();
        // self.output += "{";
        Ok(self)
    }

    // Just serialize one element after the other.
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        Ok(self)
    }

    // Struct variants are represented in TLS syntax as the plain values
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        variant_index.serialize(&mut *self)?;
        Ok(self)
    }
}

// The following 7 impls deal with the serialization of compound types like
// sequences and maps. Serialization of such types is begun by a Serializer
// method and followed by zero or more calls to serialize individual elements of
// the compound type and one call to end the compound type.
//
// This impl is SerializeSeq so these methods are called after `serialize_seq`
// is called on the Serializer.
impl<'a> ser::SerializeSeq for &'a mut Serializer {
    // Must match the `Ok` type of the serializer.
    type Ok = ();
    // Must match the `Error` type of the serializer.
    type Error = Error;

    // Serialize a single element of the sequence.
    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    // Close the sequence.
    fn end(self) -> Result<()> {
        Ok(())
    }
}

// Same thing but for tuples.
impl<'a> ser::SerializeTuple for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        todo!();
        // if !self.output.ends_with('[') {
        //     self.output += ",";
        // }
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        todo!();
        // self.output += "]";
        Ok(())
    }
}

// Same thing but for tuple structs.
impl<'a> ser::SerializeTupleStruct for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        todo!();
        // if !self.output.ends_with('[') {
        //     self.output += ",";
        // }
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        todo!();
        // self.output += "]";
        Ok(())
    }
}

// Tuple variants are a little different. Refer back to the
// `serialize_tuple_variant` method above. But we don't do any endings here.
impl<'a> ser::SerializeTupleVariant for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

// Some `Serialize` types are not able to hold a key and value in memory at the
// same time so `SerializeMap` implementations are required to support
// `serialize_key` and `serialize_value` individually.
//
// There is a third optional method on the `SerializeMap` trait. The
// `serialize_entry` method allows serializers to optimize for the case where
// key and value are both available simultaneously. In JSON it doesn't make a
// difference so the default behavior for `serialize_entry` is fine.
impl<'a> ser::SerializeMap for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    // The Serde data model allows map keys to be any serializable type. JSON
    // only allows string keys so the implementation below will produce invalid
    // JSON if the key serializes as something other than a string.
    //
    // A real JSON serializer would need to validate that map keys are strings.
    // This can be done by using a different Serializer to serialize the key
    // (instead of `&mut **self`) and having that other serializer only
    // implement `serialize_str` and return an error on any other data type.
    fn serialize_key<T>(&mut self, key: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        todo!();
        // if !self.output.ends_with('{') {
        //     self.output += ",";
        // }
        key.serialize(&mut **self)
    }

    // It doesn't make a difference whether the colon is printed at the end of
    // `serialize_key` or at the beginning of `serialize_value`. In this case
    // the code is a bit simpler having it here.
    fn serialize_value<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        todo!();
        // self.output += ":";
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        todo!();
        // self.output += "}";
        Ok(())
    }
}

// Structs are like maps in which the keys are constrained to be compile-time
// constant strings.
impl<'a> ser::SerializeStruct for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // We don't care about the key. We just serialize the value.
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

// Serialize struct values as the value itself.
impl<'a> ser::SerializeStructVariant for &'a mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

#[test]
fn test_struct() {
    #[derive(Serialize)]
    struct Test {
        int: u32,
        seq: Vec<&'static str>,
    }

    let test = Test {
        int: 1,
        seq: vec!["a", "b"],
    };
    let expected = &[
        0, 0, 0, 1, // 1u32
        2, // vec with len 2
        1, 0x61, // vec with len 1 and utf8 value
        1, 0x62, // vec with len 1 and utf8 value
    ];
    assert_eq!(to_bytes(&test).unwrap(), expected);
}

#[test]
fn test_enum() {
    #[derive(Serialize)]
    enum E {
        Unit,
        Newtype(u32),
        Tuple(u32, u32),
        Struct { a: u32 },
    }

    let u = E::Unit;
    let expected = &[0, 0, 0, 0]; // 0u32
    assert_eq!(to_bytes(&u).unwrap(), expected);

    let n = E::Newtype(1);
    let expected = [
        0, 0, 0, 1, // 1u32
        0, 0, 0, 1, // 1u32
    ];
    assert_eq!(to_bytes(&n).unwrap(), expected);

    let t = E::Tuple(1, 2);
    let expected = [
        0, 0, 0, 2, // 2u32
        0, 0, 0, 1, // 1u32
        0, 0, 0, 2, // u32
    ];
    assert_eq!(to_bytes(&t).unwrap(), expected);

    let s = E::Struct { a: 1 };
    let expected = [
        0, 0, 0, 3, // 3u32
        0, 0, 0, 1, // 1u32
    ];
    assert_eq!(to_bytes(&s).unwrap(), expected);
}
