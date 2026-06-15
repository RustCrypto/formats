//! This module implements de/serialization for String by storing the UTF-8 representation in a
//! VLByteVec, i.e. a byte vec with a varint Length.

use alloc::string::String;

use crate::{DeserializeBytes, SerializeBytes, Size, VLByteSlice, VLByteVec};

impl Size for String {
    fn tls_serialized_len(&self) -> usize {
        self.as_bytes().tls_serialized_len()
    }
}

impl Size for str {
    fn tls_serialized_len(&self) -> usize {
        self.as_bytes().tls_serialized_len()
    }
}

impl Size for &str {
    fn tls_serialized_len(&self) -> usize {
        self.as_bytes().tls_serialized_len()
    }
}

impl SerializeBytes for String {
    fn tls_serialize(&self) -> Result<alloc::vec::Vec<u8>, crate::Error> {
        SerializeBytes::tls_serialize(&VLByteSlice(self.as_bytes()))
    }
}

impl SerializeBytes for str {
    fn tls_serialize(&self) -> Result<alloc::vec::Vec<u8>, crate::Error> {
        SerializeBytes::tls_serialize(&self.as_bytes())
    }
}

impl SerializeBytes for &str {
    fn tls_serialize(&self) -> Result<alloc::vec::Vec<u8>, crate::Error> {
        SerializeBytes::tls_serialize(&self.as_bytes())
    }
}

impl DeserializeBytes for String {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), crate::Error>
    where
        Self: Sized,
    {
        let (bytes, rest) = VLByteVec::tls_deserialize_bytes(bytes)?;
        let text = String::from_utf8(bytes.into())
            .map_err(|err| crate::Error::DecodingError(format!("invalid utf8: {err}")))?;

        Ok((text, rest))
    }
}

#[cfg(feature = "std")]
mod std_only {
    use super::*;
    use crate::{Deserialize, Serialize};

    impl Serialize for String {
        fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, crate::Error> {
            Serialize::tls_serialize(&VLByteSlice(self.as_bytes()), writer)
        }
    }

    impl Serialize for str {
        fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, crate::Error> {
            Serialize::tls_serialize(&self.as_bytes(), writer)
        }
    }

    impl Serialize for &str {
        fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, crate::Error> {
            Serialize::tls_serialize(&self.as_bytes(), writer)
        }
    }

    impl Deserialize for String {
        fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, crate::Error>
        where
            Self: Sized,
        {
            let bytes = VLByteVec::tls_deserialize(bytes)?;
            String::from_utf8(bytes.into())
                .map_err(|err| crate::Error::DecodingError(format!("invalid utf8: {err}")))
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests_with_std {
    use crate::{Deserialize, Serialize, Size};
    use alloc::string::String;

    #[test]
    fn serialize_multibyte_utf8_string() {
        // U+00FC = "ü", encoded as 2 bytes in UTF-8: [0xC3, 0xBC]
        let s = String::from("ü");
        let buf = s.tls_serialize_detached().unwrap();
        assert_eq!(buf, [2, 0xC3, 0xBC]);
        assert_eq!(s.tls_serialized_len(), 3);
    }

    #[test]
    fn serialize_empty_string() {
        let s = String::new();
        let buf = s.tls_serialize_detached().unwrap();
        assert_eq!(buf, [0]);
        assert_eq!(s.tls_serialized_len(), 1);
    }

    #[test]
    fn serialize_hello_string() {
        let s = String::from("hello");
        let buf = s.tls_serialize_detached().unwrap();
        // length prefix (5) + b"hello"
        assert_eq!(buf, [5, b'h', b'e', b'l', b'l', b'o']);
        assert_eq!(s.tls_serialized_len(), 6);
    }

    #[test]
    fn roundtrip_deserialize() {
        let original = String::from("roundtrip test");
        let buf = original.tls_serialize_detached().unwrap();
        let deserialized = String::tls_deserialize_exact(&buf).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn roundtrip_deserialize_longstring() {
        let original = String::from_utf8(vec![0x30u8; 300]).unwrap();
        let buf = original.tls_serialize_detached().unwrap();
        let deserialized = String::tls_deserialize_exact(&buf).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn roundtrip_deserialize_empty() {
        let original = String::new();
        let buf = original.tls_serialize_detached().unwrap();
        let deserialized = String::tls_deserialize_exact(&buf).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn deserialize_invalid_utf8() {
        // length prefix 2 + two bytes that are not valid UTF-8
        let buf: &[u8] = &[2, 0xFF, 0xFE];
        let err = String::tls_deserialize_exact(buf).unwrap_err();
        assert!(matches!(err, crate::Error::DecodingError(msg) if msg.contains("invalid utf8")));
    }
}
#[cfg(test)]
mod tests {
    use alloc::string::String;

    #[cfg(feature = "std")]
    use crate::Serialize;

    use crate::{DeserializeBytes, SerializeBytes, Size};

    #[test]
    fn serialize_empty_str() {
        let s = "";

        #[cfg(feature = "std")]
        {
            let mut buf = [0u8; 1];
            Serialize::tls_serialize(&s, &mut buf.as_mut_slice()).unwrap();
            assert_eq!(buf, [0]);
            assert_eq!(s.tls_serialized_len(), 1);
        }

        let buf = SerializeBytes::tls_serialize(&s).unwrap();
        assert_eq!(buf, [0]);
        assert_eq!(s.tls_serialized_len(), 1);
    }

    #[test]
    fn serialize_hello_str() {
        let s = "hello";
        #[cfg(feature = "std")]
        {
            let mut buf = [0u8; 6];
            Serialize::tls_serialize(&s, &mut buf.as_mut_slice()).unwrap();
            // length prefix (5) + b"hello"
            assert_eq!(buf, [5, b'h', b'e', b'l', b'l', b'o']);
            assert_eq!(s.tls_serialized_len(), 6);
        }

        let buf = SerializeBytes::tls_serialize(&s).unwrap();
        // length prefix (5) + b"hello"
        assert_eq!(buf, [5, b'h', b'e', b'l', b'l', b'o']);
        assert_eq!(s.tls_serialized_len(), 6);
    }

    #[test]
    fn serialize_multibyte_utf8_str() {
        // U+00FC = "ü", encoded as 2 bytes in UTF-8: [0xC3, 0xBC]
        let s = "ü";
        #[cfg(feature = "std")]
        {
            let mut buf = [0u8; 3];
            Serialize::tls_serialize(&s, &mut buf.as_mut_slice()).unwrap();
            assert_eq!(buf, [2, 0xC3, 0xBC]);
            assert_eq!(s.tls_serialized_len(), 3);
        }

        let buf = SerializeBytes::tls_serialize(&s).unwrap();
        assert_eq!(buf, [2, 0xC3, 0xBC]);
        assert_eq!(s.tls_serialized_len(), 3);
    }

    #[test]
    fn deserialize_bytes_hello() {
        let input = [5, b'h', b'e', b'l', b'l', b'o'];
        let (s, rest) = String::tls_deserialize_bytes(&input).unwrap();
        assert_eq!(s, "hello");
        assert!(rest.is_empty());
        assert_eq!(s.tls_serialized_len(), 6);
    }

    #[test]
    fn deserialize_bytes_with_trailing_data() {
        // "hi" (length 2) followed by extra byte 0x99
        let input = [2, b'h', b'i', 0x99];
        let (s, rest) = String::tls_deserialize_bytes(&input).unwrap();
        assert_eq!(s, "hi");
        assert_eq!(rest, [0x99]);
    }

    #[test]
    fn deserialize_bytes_invalid_utf8() {
        // length prefix 3 + 3 bytes that form an invalid UTF-8 sequence
        let input = [3, 0xED, 0xA0, 0x80]; // surrogates are invalid in UTF-8
        let err = String::tls_deserialize_exact_bytes(&input).unwrap_err();
        assert!(matches!(err, crate::Error::DecodingError(msg) if msg.contains("invalid utf8")));
    }

    #[test]
    fn deserialize_bytes_empty_string() {
        let input = [0];
        let (s, rest) = String::tls_deserialize_bytes(&input).unwrap();
        assert_eq!(s, "");
        assert!(rest.is_empty());
    }
}
