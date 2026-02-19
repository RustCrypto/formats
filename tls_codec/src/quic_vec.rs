//! # Variable length vectors
//!
//! While the TLS RFC 8446 only specifies vectors with fixed length length fields
//! the QUIC RFC 9000 defines a variable length integer encoding.
//!
//! Note that we require, as the MLS specification does, that vectors have to
//! use the minimum number of bytes necessary for the encoding.
//! This ensures that encodings are unique.
//!
//! With the `mls` feature the length of variable length vectors can be limited
//! to 30-bit values.
//! This is in contrast to the default behaviour defined by RFC 9000 that allows
//! up to 62-bit length values.
use super::alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "std")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "serde")]
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

use crate::{DeserializeBytes, Error, SerializeBytes, Size};

#[cfg(feature = "mls")]
const MAX_MLS_LEN: u64 = (1 << 30) - 1;

/// Thin wrapper around [`TlsVarInt`] representing the length of encoded vector
/// content in bytes.
///
/// When `mls` feature is enabled, the maximum length is limited to 30-bit.
/// Otherwise, this type is no-op.
struct ContentLength(super::TlsVarInt);

impl ContentLength {
    #[cfg(all(not(feature = "mls"), feature = "arbitrary"))]
    const MAX: u64 = crate::TlsVarInt::MAX;

    #[cfg(feature = "mls")]
    const MAX: u64 = MAX_MLS_LEN;

    fn new(value: super::TlsVarInt) -> Result<Self, Error> {
        #[cfg(feature = "mls")]
        if Self::MAX < value.value() {
            return Err(Error::InvalidVectorLength);
        }
        Ok(Self(value))
    }

    fn from_usize(value: usize) -> Result<Self, Error> {
        Self::new(super::TlsVarInt::try_new(value.try_into()?)?)
    }
}

impl Size for ContentLength {
    fn tls_serialized_len(&self) -> usize {
        self.0.tls_serialized_len()
    }
}

impl DeserializeBytes for ContentLength {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (value, remainder) = super::TlsVarInt::tls_deserialize_bytes(bytes)?;
        Ok((Self(value), remainder))
    }
}

impl<T: Size> Size for Vec<T> {
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        self.as_slice().tls_serialized_len()
    }
}

impl<T: Size> Size for &Vec<T> {
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        (*self).tls_serialized_len()
    }
}

impl<T: DeserializeBytes> DeserializeBytes for Vec<T> {
    #[inline(always)]
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (length, mut remainder) = ContentLength::tls_deserialize_bytes(bytes)?;
        let len_len = length.0.bytes_len();
        let length: usize = length.0.value().try_into()?;

        if length == 0 {
            // An empty vector.
            return Ok((Vec::new(), remainder));
        }

        let mut result = Vec::new();
        let mut read = len_len;
        while (read - len_len) < length {
            let (element, next_remainder) = T::tls_deserialize_bytes(remainder)?;
            remainder = next_remainder;
            read += element.tls_serialized_len();
            result.push(element);
        }
        Ok((result, remainder))
    }
}

impl<T: SerializeBytes> SerializeBytes for &[T] {
    #[inline(always)]
    fn tls_serialize(&self) -> Result<Vec<u8>, Error> {
        // We need to pre-compute the length of the content.
        // This requires more computations but the other option would be to buffer
        // the entire content, which can end up requiring a lot of memory.
        let content_length = self.iter().fold(0, |acc, e| acc + e.tls_serialized_len());
        let length = ContentLength::from_usize(content_length)?;
        let len_len = length.0.bytes_len();

        let mut out = Vec::with_capacity(content_length + len_len);
        out.resize(len_len, 0);
        length.0.write_bytes(&mut out)?;

        // Serialize the elements
        for e in self.iter() {
            out.append(&mut e.tls_serialize()?);
        }
        #[cfg(debug_assertions)]
        if out.len() - len_len != content_length {
            return Err(Error::LibraryError);
        }

        Ok(out)
    }
}

impl<T: SerializeBytes> SerializeBytes for &Vec<T> {
    #[inline(always)]
    fn tls_serialize(&self) -> Result<Vec<u8>, Error> {
        self.as_slice().tls_serialize()
    }
}

impl<T: SerializeBytes> SerializeBytes for Vec<T> {
    fn tls_serialize(&self) -> Result<Vec<u8>, Error> {
        self.as_slice().tls_serialize()
    }
}

impl<T: Size> Size for &[T] {
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        let content_length = self.iter().fold(0, |acc, e| acc + e.tls_serialized_len());
        let len_len = ContentLength::from_usize(content_length)
            .map(|content_length| content_length.0.bytes_len())
            .unwrap_or({
                // We can't do anything about the error unless we change the
                // trait. Let's say there's no content for now.
                0
            });
        content_length + len_len
    }
}

fn write_hex(f: &mut fmt::Formatter<'_>, data: &[u8]) -> fmt::Result {
    if !data.is_empty() {
        write!(f, "0x")?;
        for byte in data {
            write!(f, "{byte:02x}")?;
        }
    } else {
        write!(f, "b\"\"")?;
    }

    Ok(())
}

macro_rules! impl_vl_bytes_generic {
    ($name:ident) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{} {{ ", stringify!($name))?;
                write_hex(f, &self.vec())?;
                write!(f, " }}")
            }
        }

        impl $name {
            /// Get a reference to the vlbytes's vec.
            pub fn as_slice(&self) -> &[u8] {
                self.vec().as_ref()
            }

            /// Add an element to this.
            #[inline]
            pub fn push(&mut self, value: u8) {
                self.vec_mut().push(value);
            }

            /// Remove the last element.
            #[inline]
            pub fn pop(&mut self) -> Option<u8> {
                self.vec_mut().pop()
            }
        }

        impl From<Vec<u8>> for $name {
            fn from(vec: Vec<u8>) -> Self {
                Self::new(vec)
            }
        }

        impl From<&[u8]> for $name {
            fn from(slice: &[u8]) -> Self {
                Self::new(slice.to_vec())
            }
        }

        impl<const N: usize> From<&[u8; N]> for $name {
            fn from(slice: &[u8; N]) -> Self {
                Self::new(slice.to_vec())
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.vec()
            }
        }
    };
}

/// Variable-length encoded byte vectors.
/// Use this struct if bytes are encoded.
/// This is faster than the generic version.
#[cfg_attr(feature = "serde", derive(SerdeSerialize, SerdeDeserialize))]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[derive(Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct VLBytes {
    #[cfg_attr(feature = "serde", serde(serialize_with = "serde_bytes::serialize"))]
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "serde_impl::de_vec_bytes_compat")
    )]
    vec: Vec<u8>,
}

impl VLBytes {
    /// Generate a new variable-length byte vector.
    pub fn new(vec: Vec<u8>) -> Self {
        Self { vec }
    }

    fn vec(&self) -> &[u8] {
        &self.vec
    }

    fn vec_mut(&mut self) -> &mut Vec<u8> {
        &mut self.vec
    }
}

impl_vl_bytes_generic!(VLBytes);

impl From<VLBytes> for Vec<u8> {
    fn from(b: VLBytes) -> Self {
        b.vec
    }
}

#[inline(always)]
fn tls_serialize_bytes_len(bytes: &[u8]) -> usize {
    let content_length = bytes.len();
    let len_len = ContentLength::from_usize(content_length)
        .map(|content_length| content_length.0.bytes_len())
        .unwrap_or({
            // We can't do anything about the error. Let's say there's no
            // content.
            0
        });
    content_length + len_len
}

impl Size for VLBytes {
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        tls_serialize_bytes_len(self.as_slice())
    }
}

impl DeserializeBytes for VLBytes {
    #[inline(always)]
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (length, remainder) = ContentLength::tls_deserialize_bytes(bytes)?;
        let length: usize = length.0.value().try_into()?;

        if length == 0 {
            return Ok((Self::new(vec![]), remainder));
        }

        match remainder.get(..length).ok_or(Error::EndOfStream) {
            Ok(vec) => Ok((Self { vec: vec.to_vec() }, &remainder[length..])),
            Err(_e) => {
                let remaining_len = remainder.len();
                if !cfg!(fuzzing) {
                    debug_assert_eq!(
                        remaining_len, length,
                        "Expected to read {length} bytes but {remaining_len} were read.",
                    );
                }
                Err(Error::DecodingError(format!(
                    "{remaining_len} bytes were read but {length} were expected",
                )))
            }
        }
    }
}

impl Size for &VLBytes {
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        (*self).tls_serialized_len()
    }
}

#[cfg(feature = "serde")]
mod serde_impl {
    use std::{fmt, vec::Vec};

    use serde::{Deserializer, de};

    pub(super) fn de_vec_bytes_compat<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesOrSeq;

        impl<'de> de::Visitor<'de> for BytesOrSeq {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("either a byte blob or a sequence of u8")
            }

            // New format (native bytes; e.g., CBOR/Bincode/Msgpack)
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(v.to_vec())
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(v)
            }

            // Old format (seq of u8)
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut out = Vec::new();
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }

        deserializer.deserialize_any(BytesOrSeq)
    }
}
pub struct VLByteSlice<'a>(pub &'a [u8]);

impl fmt::Debug for VLByteSlice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VLByteSlice {{ ")?;
        write_hex(f, self.0)?;
        write!(f, " }}")
    }
}

impl VLByteSlice<'_> {
    /// Get the raw slice.
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        self.0
    }
}

impl Size for &VLByteSlice<'_> {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        tls_serialize_bytes_len(self.0)
    }
}

impl Size for VLByteSlice<'_> {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        tls_serialize_bytes_len(self.0)
    }
}

#[cfg(feature = "std")]
pub mod rw {
    use super::*;
    use crate::{Deserialize, Serialize};

    impl Deserialize for ContentLength {
        #[inline(always)]
        fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, Error> {
            ContentLength::new(crate::TlsVarInt::tls_deserialize(bytes)?)
        }
    }

    impl Serialize for ContentLength {
        #[inline(always)]
        fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
            self.0.tls_serialize(writer)
        }
    }

    /// Read the length of a variable-length vector.
    ///
    /// This function assumes that the reader is at the start of a variable length
    /// vector and returns an error if there's not a single byte to read.
    ///
    /// The length and number of bytes read are returned.
    #[inline]
    pub fn read_length<R: std::io::Read>(bytes: &mut R) -> Result<(usize, usize), Error> {
        let length = ContentLength::tls_deserialize(bytes)?;
        let len_len = length.0.bytes_len();
        let length: usize = length.0.value().try_into()?;
        Ok((length, len_len))
    }

    impl<T: Deserialize> Deserialize for Vec<T> {
        #[inline(always)]
        fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, Error> {
            let (length, len_len) = read_length(bytes)?;

            if length == 0 {
                // An empty vector.
                return Ok(Vec::new());
            }

            let mut result = Vec::new();
            let mut read = len_len;
            while (read - len_len) < length {
                let element = T::tls_deserialize(bytes)?;
                read += element.tls_serialized_len();
                result.push(element);
            }
            Ok(result)
        }
    }

    #[inline(always)]
    pub fn write_length<W: std::io::Write>(
        writer: &mut W,
        content_length: usize,
    ) -> Result<usize, Error> {
        ContentLength::from_usize(content_length)?.tls_serialize(writer)
    }

    impl<T: Serialize + std::fmt::Debug> Serialize for Vec<T> {
        #[inline(always)]
        fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
            self.as_slice().tls_serialize(writer)
        }
    }

    impl<T: Serialize + std::fmt::Debug> Serialize for &[T] {
        #[inline(always)]
        fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
            // We need to pre-compute the length of the content.
            // This requires more computations but the other option would be to buffer
            // the entire content, which can end up requiring a lot of memory.
            let content_length = self.iter().fold(0, |acc, e| acc + e.tls_serialized_len());
            let len_len = write_length(writer, content_length)?;

            // Serialize the elements
            #[cfg(debug_assertions)]
            let mut written = 0;
            for e in self.iter() {
                #[cfg(debug_assertions)]
                {
                    written += e.tls_serialize(writer)?;
                }
                // We don't care about the length here. We pre-computed it.
                #[cfg(not(debug_assertions))]
                e.tls_serialize(writer)?;
            }
            #[cfg(debug_assertions)]
            if written != content_length {
                return Err(Error::LibraryError);
            }

            Ok(content_length + len_len)
        }
    }
}

/// Read/Write (std) based (de)serialization for [`VLBytes`].
#[cfg(feature = "std")]
mod rw_bytes {
    use super::*;
    use crate::{Deserialize, Serialize};

    #[inline(always)]
    fn tls_serialize_bytes<W: std::io::Write>(
        writer: &mut W,
        bytes: &[u8],
    ) -> Result<usize, Error> {
        // Get the byte length of the content, make sure it's not too
        // large and write it out.
        let content_length = bytes.len();

        let len_len = ContentLength::from_usize(content_length)?.tls_serialize(writer)?;

        // Now serialize the elements
        writer.write_all(bytes)?;

        Ok(content_length + len_len)
    }

    impl Serialize for VLBytes {
        #[inline(always)]
        fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
            tls_serialize_bytes(writer, self.as_slice())
        }
    }

    impl Serialize for &VLBytes {
        #[inline(always)]
        fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
            (*self).tls_serialize(writer)
        }
    }

    impl Deserialize for VLBytes {
        fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, Error> {
            let length = ContentLength::tls_deserialize(bytes)?;

            if length.0.value() == 0 {
                return Ok(Self::new(vec![]));
            }

            let mut result = Self {
                vec: vec![0u8; length.0.value().try_into()?],
            };
            bytes.read_exact(result.vec.as_mut_slice())?;
            Ok(result)
        }
    }

    impl Serialize for &VLByteSlice<'_> {
        fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
            tls_serialize_bytes(writer, self.0)
        }
    }

    impl Serialize for VLByteSlice<'_> {
        fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
            tls_serialize_bytes(writer, self.0)
        }
    }
}

#[cfg(feature = "std")]
mod secret_bytes {
    use super::*;
    use crate::{Deserialize, Serialize};

    /// A wrapper struct around [`VLBytes`] that implements [`ZeroizeOnDrop`]. It
    /// behaves just like [`VLBytes`], except that it doesn't allow conversion into
    /// a [`Vec<u8>`].
    #[cfg_attr(feature = "serde", derive(SerdeSerialize, SerdeDeserialize))]
    #[derive(Clone, PartialEq, Eq, Hash, Ord, PartialOrd, Zeroize, ZeroizeOnDrop)]
    pub struct SecretVLBytes(VLBytes);

    impl SecretVLBytes {
        /// Generate a new variable-length byte vector that implements
        /// [`ZeroizeOnDrop`].
        pub fn new(vec: Vec<u8>) -> Self {
            Self(VLBytes { vec })
        }

        fn vec(&self) -> &[u8] {
            &self.0.vec
        }

        fn vec_mut(&mut self) -> &mut Vec<u8> {
            &mut self.0.vec
        }
    }

    impl_vl_bytes_generic!(SecretVLBytes);

    impl Size for SecretVLBytes {
        fn tls_serialized_len(&self) -> usize {
            self.0.tls_serialized_len()
        }
    }

    impl DeserializeBytes for SecretVLBytes {
        fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
        where
            Self: Sized,
        {
            let (bytes, remainder) = VLBytes::tls_deserialize_bytes(bytes)?;
            Ok((Self(bytes), remainder))
        }
    }

    impl Serialize for SecretVLBytes {
        fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
            self.0.tls_serialize(writer)
        }
    }

    impl Deserialize for SecretVLBytes {
        fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, Error>
        where
            Self: Sized,
        {
            Ok(Self(VLBytes::tls_deserialize(bytes)?))
        }
    }
}

#[cfg(feature = "std")]
pub use secret_bytes::SecretVLBytes;

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for VLBytes {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // We generate an arbitrary `Vec<u8>` ...
        let mut vec = Vec::arbitrary(u)?;
        // ... and truncate it to `MAX_LEN`.
        vec.truncate(ContentLength::MAX as usize);
        // We probably won't exceed `MAX_LEN` in practice, e.g., during fuzzing,
        // but better make sure that we generate valid instances.

        Ok(Self { vec })
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use crate::{SecretVLBytes, VLByteSlice, VLBytes};
    use std::println;

    #[test]
    fn test_debug() {
        let tests = [
            (vec![], "b\"\""),
            (vec![0x00], "0x00"),
            (vec![0xAA], "0xaa"),
            (vec![0xFF], "0xff"),
            (vec![0x00, 0x00], "0x0000"),
            (vec![0x00, 0xAA], "0x00aa"),
            (vec![0x00, 0xFF], "0x00ff"),
            (vec![0xff, 0xff], "0xffff"),
        ];

        for (test, expected) in tests.into_iter() {
            println!("\n# {test:?}");

            let expected_vl_byte_slice = format!("VLByteSlice {{ {expected} }}");
            let got = format!("{:?}", VLByteSlice(&test));
            println!("{got}");
            assert_eq!(expected_vl_byte_slice, got);

            let expected_vl_bytes = format!("VLBytes {{ {expected} }}");
            let got = format!("{:?}", VLBytes::new(test.clone()));
            println!("{got}");
            assert_eq!(expected_vl_bytes, got);

            let expected_secret_vl_bytes = format!("SecretVLBytes {{ {expected} }}");
            let got = format!("{:?}", SecretVLBytes::new(test.clone()));
            println!("{got}");
            assert_eq!(expected_secret_vl_bytes, got);
        }
    }
}
