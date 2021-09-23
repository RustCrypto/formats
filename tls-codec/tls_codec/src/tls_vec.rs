//! A vector with a length field for TLS serialisation.
//! Use this for any vector that is serialised.

// TODO: #2 share code between the different implementations. There's too much
//       duplicate code in here.

use std::{
    io::{Read, Write},
    ops::Drop,
};

#[cfg(feature = "serde_serialize")]
use serde::ser::SerializeStruct;
use zeroize::Zeroize;

use crate::{Deserialize, Error, Serialize, Size};

macro_rules! impl_size {
    ($self:ident, $size:ty, $name:ident, $len_len:literal) => {
        /// The serialized len
        #[inline(always)]
        fn tls_serialized_length(&$self) -> usize {
            $self.as_slice()
                .iter()
                .fold($len_len, |acc, e| acc + e.tls_serialized_len())
        }
    }
}

macro_rules! impl_byte_size {
    ($self:ident, $size:ty, $name:ident, $len_len:literal) => {
        /// The serialized len
        #[inline(always)]
        fn tls_serialized_byte_length(&$self) -> usize {
            $self.as_slice().len() + $len_len
        }
    }
}

macro_rules! impl_byte_deserialize {
    ($self:ident, $size:ty, $name:ident, $len_len:literal) => {
        #[inline(always)]
        fn deserialize_bytes<R: Read>(bytes: &mut R) -> Result<Self, Error> {
            let len = <$size>::tls_deserialize(bytes)? as usize;
            // When fuzzing we limit the maximum size to allocate.
            // XXX: We should think about a configurable limit for the allocation
            //      here.
            if cfg!(fuzzing) && len > u16::MAX as usize {
                return Err(Error::DecodingError(format!(
                    "Trying to allocate {} bytes. Only {} allowed.",
                    len,
                    u16::MAX
                )));
            }
            let mut result = Self {
                vec: vec![0u8; len],
            };
            let read = bytes.read(result.vec.as_mut_slice())?;
            if read != len {
                if !cfg!(fuzzing) {
                    // When fuzzing we don't want to assert here because it would
                    // crash all the time. Throwing an error is sufficient.
                    debug_assert_eq!(
                        read, len,
                        "Expected to read {} bytes but {} were read.",
                        len, read
                    );
                }
                Err(Error::DecodingError(format!(
                    "{} bytes were read but {} were expected",
                    read, len
                )))
            } else {
                Ok(result)
            }
        }
    };
}

macro_rules! impl_deserialize {
    ($self:ident, $size:ty, $name:ident, $len_len:literal) => {
        #[inline(always)]
        fn deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
            let mut result = Self { vec: Vec::new() };
            let len = <$size>::tls_deserialize(bytes)?;
            let mut read = len.tls_serialized_len();
            let len_len = read;
            while (read - len_len) < len as usize {
                let element = T::tls_deserialize(bytes)?;
                read += element.tls_serialized_len();
                result.push(element);
            }
            Ok(result)
        }
    };
}

macro_rules! impl_serialize {
    ($self:ident, $size:ty, $name:ident, $len_len:literal) => {
        #[inline(always)]
        fn serialize<W: Write>(&$self, writer: &mut W) -> Result<usize, Error> {
            // Get the byte length of the content, make sure it's not too
            // large and write it out.
            let tls_serialized_len = $self.tls_serialized_len();
            let byte_length = tls_serialized_len - $len_len;

            let max_len = <$size>::MAX as usize;
            debug_assert!(
                byte_length <= max_len,
                "Vector length can't be encoded in the vector length a {} >= {}",
                byte_length,
                max_len
            );
            if byte_length > max_len {
                return Err(Error::InvalidVectorLength);
            }

            let mut written = (byte_length as $size).tls_serialize(writer)?;

            // Now serialize the elements
            for e in $self.as_slice().iter() {
                written += e.tls_serialize(writer)?;
            }

            debug_assert_eq!(
                written, tls_serialized_len,
                "{} bytes should have been serialized but {} were written",
                tls_serialized_len, written
            );
            if written != tls_serialized_len {
                return Err(Error::EncodingError(format!(
                    "{} bytes should have been serialized but {} were written",
                    tls_serialized_len, written
                )));
            }
            Ok(written)
        }
    };
}

macro_rules! impl_byte_serialize {
    ($self:ident, $size:ty, $name:ident, $len_len:literal) => {
        #[inline(always)]
        fn serialize_bytes<W: Write>(&$self, writer: &mut W) -> Result<usize, Error> {
            // Get the byte length of the content, make sure it's not too
            // large and write it out.
            let tls_serialized_len = $self.tls_serialized_len();
            let byte_length = tls_serialized_len - $len_len;

            let max_len = <$size>::MAX as usize;
            debug_assert!(
                byte_length <= max_len,
                "Vector length can't be encoded in the vector length a {} >= {}",
                byte_length,
                max_len
            );
            if byte_length > max_len {
                return Err(Error::InvalidVectorLength);
            }

            let mut written = (byte_length as $size).tls_serialize(writer)?;

            // Now serialize the elements
            written += writer.write($self.as_slice())?;

            debug_assert_eq!(
                written, tls_serialized_len,
                "{} bytes should have been serialized but {} were written",
                tls_serialized_len, written
            );
            if written != tls_serialized_len {
                return Err(Error::EncodingError(format!(
                    "{} bytes should have been serialized but {} were written",
                    tls_serialized_len, written
                )));
            }
            Ok(written)
        }
    };
}

macro_rules! impl_tls_vec_codec_generic {
    ($size:ty, $name:ident, $len_len: literal, $($bounds:ident),*) => {
        impl<T: $($bounds + )*> Serialize
            for $name<T>
        {
            fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
                self.serialize(writer)
            }
        }

        impl<T: $($bounds + )*> Size
            for $name<T>
        {
            #[inline]
            fn tls_serialized_len(&self) -> usize {
                self.tls_serialized_length()
            }
        }

        impl<T: $($bounds + )*> Serialize
            for &$name<T>
        {
            fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
                self.serialize(writer)
            }
        }

        impl<T: $($bounds + )*> Size
            for &$name<T>
        {
            #[inline]
            fn tls_serialized_len(&self) -> usize {
                self.tls_serialized_length()
            }
        }

        impl<T: $($bounds + )*> Deserialize
            for $name<T>
        {
            fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
                Self::deserialize(bytes)
            }
        }
    }
}

macro_rules! impl_tls_vec_codec_bytes {
    ($size:ty, $name:ident, $len_len: literal) => {
        impl Serialize for $name {
            fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
                self.serialize_bytes(writer)
            }
        }

        impl Size for $name {
            #[inline]
            fn tls_serialized_len(&self) -> usize {
                self.tls_serialized_byte_length()
            }
        }

        impl Serialize for &$name {
            fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
                self.serialize_bytes(writer)
            }
        }

        impl Size for &$name {
            #[inline]
            fn tls_serialized_len(&self) -> usize {
                self.tls_serialized_byte_length()
            }
        }

        impl Deserialize for $name {
            fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
                Self::deserialize_bytes(bytes)
            }
        }
    };
}

macro_rules! impl_vec_members {
    ($element_type:ident, $len_len:literal) => {
        /// Create a new `TlsVec` from a Rust Vec.
        #[inline]
        pub fn new(vec: Vec<$element_type>) -> Self {
            Self { vec }
        }

        /// Create a new `TlsVec` from a slice.
        #[inline]
        pub fn from_slice(slice: &[$element_type]) -> Self
        where
            $element_type: Clone,
        {
            Self {
                vec: slice.to_vec(),
            }
        }

        /// Get the length of the vector.
        #[inline]
        pub fn len(&self) -> usize {
            self.vec.len()
        }

        /// Get a slice to the raw vector.
        #[inline]
        pub fn as_slice(&self) -> &[$element_type] {
            &self.vec
        }

        /// Check if the vector is empty.
        #[inline]
        pub fn is_empty(&self) -> bool {
            self.vec.is_empty()
        }

        /// Get the underlying vector and consume this.
        #[inline]
        pub fn into_vec(mut self) -> Vec<$element_type> {
            std::mem::take(&mut self.vec)
        }

        /// Add an element to this.
        #[inline]
        pub fn push(&mut self, value: $element_type) {
            self.vec.push(value);
        }

        /// Remove the last element.
        #[inline]
        pub fn pop(&mut self) -> Option<$element_type> {
            self.vec.pop()
        }

        /// Remove the element at `index`.
        #[inline]
        pub fn remove(&mut self, index: usize) -> $element_type {
            self.vec.remove(index)
        }

        /// Returns a reference to an element or subslice depending on the type of index.
        /// XXX: implement SliceIndex instead
        #[inline]
        pub fn get(&self, index: usize) -> Option<&$element_type> {
            self.vec.get(index)
        }

        /// Returns an iterator over the slice.
        #[inline]
        pub fn iter(&self) -> std::slice::Iter<'_, $element_type> {
            self.vec.iter()
        }

        /// Retains only the elements specified by the predicate.
        #[inline]
        pub fn retain<F>(&mut self, f: F)
        where
            F: FnMut(&$element_type) -> bool,
        {
            self.vec.retain(f)
        }

        /// Get the number of bytes used for the length encoding.
        #[inline(always)]
        pub fn len_len() -> usize {
            $len_len
        }
    };
}

macro_rules! impl_tls_vec_generic {
    ($size:ty, $name:ident, $len_len: literal, $($bounds:ident),*) => {
        #[derive(Eq, Debug)]
        pub struct $name<T: $($bounds + )*> {
            vec: Vec<T>,
        }

        impl<T: Clone + $($bounds + )*> Clone for $name<T> {
            fn clone(&self) -> Self {
                Self::new(self.vec.clone())
            }
        }

        impl<T: $($bounds + )*> $name<T> {
            impl_vec_members!(T, $len_len);
        }

        impl<T: std::hash::Hash + $($bounds + )*> std::hash::Hash for $name<T> {
            #[inline]
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.vec.hash(state)
            }
        }

        impl<T: $($bounds + )*> std::ops::Index<usize> for $name<T> {
            type Output = T;

            #[inline]
            fn index(&self, i: usize) -> &T {
                self.vec.index(i)
            }
        }

        impl<T: std::cmp::PartialEq + $($bounds + )*> std::cmp::PartialEq for $name<T> {
            fn eq(&self, other: &Self) -> bool {
                self.vec.eq(&other.vec)
            }
        }

        impl<T: $($bounds + )*> std::ops::IndexMut<usize> for $name<T> {
            #[inline]
            fn index_mut(&mut self, i: usize) -> &mut Self::Output {
                self.vec.index_mut(i)
            }
        }

        impl<T: $($bounds + )*> std::borrow::Borrow<[T]> for $name<T> {
            #[inline]
            fn borrow(&self) -> &[T] {
                &self.vec
            }
        }

        impl<T: $($bounds + )*> std::iter::FromIterator<T> for  $name<T>  {
            #[inline]
            fn from_iter<I>(iter: I) -> Self
            where
                I: IntoIterator<Item = T>, {
                let vec = Vec::<T>::from_iter(iter);
                Self{vec}
            }
        }

        impl<T: $($bounds + )*> From<Vec<T>>
            for $name<T>
        {
            #[inline]
            fn from(v: Vec<T>) -> Self {
                Self::new(v)
            }
        }

        impl<T: Clone + $($bounds + )*> From<&[T]>
            for $name<T>
        {
            #[inline]
            fn from(v: &[T]) -> Self {
                Self::from_slice(v)
            }
        }

        impl<T: $($bounds + )*> From<$name<T>>
            for Vec<T>
        {
            #[inline]
            fn from(mut v: $name<T>) -> Self {
                std::mem::take(&mut v.vec)
            }
        }

        impl<T: $($bounds + )*> Default
            for $name<T>
        {
            #[inline]
            fn default() -> Self {
                Self { vec: Vec::new() }
            }
        }

        #[cfg(feature = "serde_serialize")]
        impl<T> serde::Serialize for $name<T>
        where
            T: $($bounds + )* serde::Serialize,
        {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let mut state = serializer.serialize_struct(stringify!($name), 1)?;
                state.serialize_field("vec", &self.vec)?;
                state.end()
            }
        }

        #[cfg(feature = "serde_serialize")]
        impl<'de, T> serde::de::Deserialize<'de> for $name<T>
        where
            T: Serialize
                + Deserialize
                + Size
                + $($bounds + )*
                serde::de::Deserialize<'de>,
        {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                enum Field {
                    Vec,
                }

                impl<'de> serde::de::Deserialize<'de> for Field {
                    fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
                    where
                        D: serde::de::Deserializer<'de>,
                    {
                        struct FieldVisitor;

                        impl<'de> serde::de::Visitor<'de> for FieldVisitor {
                            type Value = Field;

                            fn expecting(
                                &self,
                                formatter: &mut std::fmt::Formatter,
                            ) -> std::fmt::Result {
                                formatter.write_str("`vec`")
                            }

                            fn visit_str<E>(self, value: &str) -> Result<Field, E>
                            where
                                E: serde::de::Error,
                            {
                                match value {
                                    "vec" => Ok(Field::Vec),
                                    _ => Err(serde::de::Error::unknown_field(value, &["vec"])),
                                }
                            }
                        }

                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }

                struct TlsVecVisitor<T> {
                    data: std::marker::PhantomData<T>,
                }

                impl<'de, T> serde::de::Visitor<'de> for TlsVecVisitor<T>
                where
                    T: Serialize
                        + Deserialize
                        + Size
                        + $($bounds + )*
                        serde::de::Deserialize<'de>,
                {
                    type Value = $name<T>;
                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_fmt(format_args!("struct {}<T>", stringify!($name)))
                    }
                    fn visit_seq<V>(self, mut seq: V) -> Result<$name<T>, V::Error>
                    where
                        V: serde::de::SeqAccess<'de>,
                    {
                        let vec = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                        Ok($name::<T>::new(vec))
                    }
                    fn visit_map<V>(self, mut map: V) -> Result<$name<T>, V::Error>
                    where
                        V: serde::de::MapAccess<'de>,
                    {
                        let mut vec = None;
                        while let Some(key) = map.next_key()? {
                            match key {
                                Field::Vec => {
                                    if vec.is_some() {
                                        return Err(serde::de::Error::duplicate_field("vec"));
                                    }
                                    vec = Some(map.next_value()?);
                                }
                            }
                        }
                        let vec = vec.ok_or_else(|| serde::de::Error::missing_field("vec"))?;
                        Ok($name::<T>::new(vec))
                    }
                }
                deserializer.deserialize_struct(
                    stringify!($name),
                    &["vec"],
                    TlsVecVisitor {
                        data: std::marker::PhantomData,
                    },
                )
            }
        }
    };
}

macro_rules! impl_tls_vec {
    ($name:ident, $len_len:literal) => {
        #[derive(Eq, Clone, Debug)]
        pub struct $name {
            vec: Vec<u8>,
        }

        impl $name {
            impl_vec_members!(u8, 1);
        }

        impl std::hash::Hash for $name {
            #[inline]
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.vec.hash(state)
            }
        }

        impl std::ops::Index<usize> for $name {
            type Output = u8;

            #[inline]
            fn index(&self, i: usize) -> &u8 {
                self.vec.index(i)
            }
        }

        impl std::cmp::PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.vec.eq(&other.vec)
            }
        }

        impl std::ops::IndexMut<usize> for $name {
            #[inline]
            fn index_mut(&mut self, i: usize) -> &mut Self::Output {
                self.vec.index_mut(i)
            }
        }

        impl std::borrow::Borrow<[u8]> for $name {
            #[inline]
            fn borrow(&self) -> &[u8] {
                &self.vec
            }
        }

        impl std::iter::FromIterator<u8> for $name {
            #[inline]
            fn from_iter<I>(iter: I) -> Self
            where
                I: IntoIterator<Item = u8>,
            {
                let vec = Vec::<u8>::from_iter(iter);
                Self { vec }
            }
        }

        impl From<Vec<u8>> for $name {
            #[inline]
            fn from(v: Vec<u8>) -> Self {
                Self::new(v)
            }
        }

        impl From<&[u8]> for $name {
            #[inline]
            fn from(v: &[u8]) -> Self {
                Self::from_slice(v)
            }
        }

        impl From<$name> for Vec<u8> {
            #[inline]
            fn from(mut v: $name) -> Self {
                std::mem::take(&mut v.vec)
            }
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self { vec: Vec::new() }
            }
        }

        #[cfg(feature = "serde_serialize")]
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let mut state = serializer.serialize_struct(stringify!($name), 1)?;
                state.serialize_field("vec", &self.vec)?;
                state.end()
            }
        }

        #[cfg(feature = "serde_serialize")]
        impl<'de> serde::de::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                enum Field {
                    Vec,
                }

                impl<'de> serde::de::Deserialize<'de> for Field {
                    fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
                    where
                        D: serde::de::Deserializer<'de>,
                    {
                        struct FieldVisitor;

                        impl<'de> serde::de::Visitor<'de> for FieldVisitor {
                            type Value = Field;

                            fn expecting(
                                &self,
                                formatter: &mut std::fmt::Formatter,
                            ) -> std::fmt::Result {
                                formatter.write_str("`vec`")
                            }

                            fn visit_str<E>(self, value: &str) -> Result<Field, E>
                            where
                                E: serde::de::Error,
                            {
                                match value {
                                    "vec" => Ok(Field::Vec),
                                    _ => Err(serde::de::Error::unknown_field(value, &["vec"])),
                                }
                            }
                        }

                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }

                struct TlsVecVisitor {
                    data: std::marker::PhantomData<u8>,
                }

                impl<'de> serde::de::Visitor<'de> for TlsVecVisitor {
                    type Value = $name;
                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_fmt(format_args!("struct {}", stringify!($name)))
                    }
                    fn visit_seq<V>(self, mut seq: V) -> Result<$name, V::Error>
                    where
                        V: serde::de::SeqAccess<'de>,
                    {
                        let vec = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                        Ok($name::new(vec))
                    }
                    fn visit_map<V>(self, mut map: V) -> Result<$name, V::Error>
                    where
                        V: serde::de::MapAccess<'de>,
                    {
                        let mut vec = None;
                        while let Some(key) = map.next_key()? {
                            match key {
                                Field::Vec => {
                                    if vec.is_some() {
                                        return Err(serde::de::Error::duplicate_field("vec"));
                                    }
                                    vec = Some(map.next_value()?);
                                }
                            }
                        }
                        let vec = vec.ok_or_else(|| serde::de::Error::missing_field("vec"))?;
                        Ok($name::new(vec))
                    }
                }
                deserializer.deserialize_struct(
                    stringify!($name),
                    &["vec"],
                    TlsVecVisitor {
                        data: std::marker::PhantomData,
                    },
                )
            }
        }
    };
}

macro_rules! impl_secret_tls_vec {
    ($size:ty, $name:ident, $len_len: literal) => {
        impl_tls_vec_generic!(
            $size,
            $name,
            $len_len,
            Serialize,
            Deserialize,
            Size,
            Zeroize
        );
        impl_tls_vec_codec_generic!(
            $size,
            $name,
            $len_len,
            Serialize,
            Deserialize,
            Size,
            Zeroize
        );

        impl<T: Serialize + Deserialize + Size + Zeroize> $name<T> {
            // This implements serialize and size for all versions
            impl_serialize!(self, $size, $name, $len_len);
            impl_size!(self, $size, $name, $len_len);
            impl_deserialize!(self, $size, $name, $len_len);
        }

        impl<T: Serialize + Deserialize + Size + Zeroize> Zeroize for $name<T> {
            fn zeroize(&mut self) {
                self.vec.zeroize()
            }
        }

        impl<T: Serialize + Deserialize + Size + Zeroize> Drop for $name<T> {
            fn drop(&mut self) {
                self.zeroize()
            }
        }
    };
}

macro_rules! impl_public_tls_vec {
    ($size:ty, $name:ident, $len_len: literal) => {
        impl_tls_vec_generic!($size, $name, $len_len, Serialize, Deserialize, Size);

        impl_tls_vec_codec_generic!($size, $name, $len_len, Serialize, Deserialize, Size);

        impl<T: Serialize + Deserialize + Size> $name<T> {
            // This implements serialize and size for all versions
            impl_serialize!(self, $size, $name, $len_len);
            impl_size!(self, $size, $name, $len_len);
            impl_deserialize!(self, $size, $name, $len_len);
        }
    };
}

macro_rules! impl_tls_byte_vec {
    ($size:ty, $name:ident, $len_len: literal) => {
        impl_tls_vec!($name, $len_len);

        impl $name {
            // This implements serialize and size for all versions
            impl_byte_serialize!(self, $size, $name, $len_len);
            impl_byte_size!(self, $size, $name, $len_len);
            impl_byte_deserialize!(self, $size, $name, $len_len);
        }

        impl_tls_vec_codec_bytes!($size, $name, $len_len);
    };
}

// TODO: #1 provide specialized TlsByteVec* versions holding u8 that are more efficient.

impl_public_tls_vec!(u8, TlsVecU8, 1);
impl_public_tls_vec!(u16, TlsVecU16, 2);
impl_public_tls_vec!(u32, TlsVecU32, 4);

impl_tls_byte_vec!(u8, TlsByteVecU8, 1);
impl_tls_byte_vec!(u16, TlsByteVecU16, 2);
impl_tls_byte_vec!(u32, TlsByteVecU32, 4);

// Secrets should be put into these Secret tls vectors as they implement zeroize.
impl_secret_tls_vec!(u8, SecretTlsVecU8, 1);
impl_secret_tls_vec!(u16, SecretTlsVecU16, 2);
impl_secret_tls_vec!(u32, SecretTlsVecU32, 4);

// We also implement shallow serialization for slices

macro_rules! impl_tls_byte_slice {
    ($size:ty, $name:ident, $len_len:literal) => {
        pub struct $name<'a>(pub &'a [u8]);

        impl<'a> $name<'a> {
            #[inline(always)]
            fn as_slice(&self) -> &[u8] {
                &self.0
            }
        }

        impl<'a> $name<'a> {
            impl_byte_serialize!(self, $size, $name, $len_len);
            impl_byte_size!(self, $size, $name, $len_len);
        }

        impl<'a> Serialize for &$name<'a> {
            fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
                self.serialize_bytes(writer)
            }
        }

        impl<'a> Serialize for $name<'a> {
            fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
                self.serialize_bytes(writer)
            }
        }

        impl<'a> Size for &$name<'a> {
            #[inline]
            fn tls_serialized_len(&self) -> usize {
                self.tls_serialized_byte_length()
            }
        }

        impl<'a> Size for $name<'a> {
            #[inline]
            fn tls_serialized_len(&self) -> usize {
                self.tls_serialized_byte_length()
            }
        }
    };
}

impl_tls_byte_slice!(u8, TlsByteSliceU8, 1);
impl_tls_byte_slice!(u16, TlsByteSliceU16, 2);
impl_tls_byte_slice!(u32, TlsByteSliceU32, 4);

macro_rules! impl_tls_slice {
    ($size:ty, $name:ident, $len_len: literal) => {
        pub struct $name<'a, T: Size + Serialize>(pub &'a [T]);

        impl<'a, T: Size + Serialize> $name<'a, T> {
            #[inline(always)]
            fn as_slice(&self) -> &[T] {
                &self.0
            }
        }

        impl<'a, T: Size + Serialize> $name<'a, T> {
            impl_serialize!(self, $size, $name, $len_len);
            impl_size!(self, $size, $name, $len_len);
        }

        impl<'a, T: Size + Serialize> Serialize for &$name<'a, T> {
            fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
                self.serialize(writer)
            }
        }

        impl<'a, T: Size + Serialize> Serialize for $name<'a, T> {
            fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
                self.serialize(writer)
            }
        }

        impl<'a, T: Size + Serialize> Size for &$name<'a, T> {
            #[inline]
            fn tls_serialized_len(&self) -> usize {
                self.tls_serialized_length()
            }
        }

        impl<'a, T: Size + Serialize> Size for $name<'a, T> {
            #[inline]
            fn tls_serialized_len(&self) -> usize {
                self.tls_serialized_length()
            }
        }
    };
}

impl_tls_slice!(u8, TlsSliceU8, 1);
impl_tls_slice!(u16, TlsSliceU16, 2);
impl_tls_slice!(u32, TlsSliceU32, 4);

impl From<std::num::TryFromIntError> for Error {
    fn from(_e: std::num::TryFromIntError) -> Self {
        Self::InvalidVectorLength
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(_e: std::convert::Infallible) -> Self {
        Self::InvalidVectorLength
    }
}
