//! Context-specific field.

use crate::tag::CLASS_CONTEXT_SPECIFIC;

use super::custom_class::{
    CustomClassExplicit, CustomClassExplicitRef, CustomClassImplicit, CustomClassImplicitRef,
};

/// Context-specific class, EXPLICIT
pub type ContextSpecificExplicit<const TAG: u16, T> =
    CustomClassExplicit<TAG, T, CLASS_CONTEXT_SPECIFIC>;

/// Context-specific class, IMPLICIT
pub type ContextSpecificImplicit<const TAG: u16, T> =
    CustomClassImplicit<TAG, T, CLASS_CONTEXT_SPECIFIC>;

/// Context-specific class, reference, EXPLICIT
pub type ContextSpecificExplicitRef<'a, const TAG: u16, T> =
    CustomClassExplicitRef<'a, TAG, T, CLASS_CONTEXT_SPECIFIC>;

/// Context-specific class, reference, IMPLICIT
pub type ContextSpecificImplicitRef<'a, const TAG: u16, T> =
    CustomClassImplicitRef<'a, TAG, T, CLASS_CONTEXT_SPECIFIC>;

// pub fn decode_implicit<'a, R: Reader<'a>, T: Tagged + DecodeValue<'a>>(
//     number: TagNumber,
//     reader: &mut R,
// ) -> Result<Option<T>, T::Error> {
//     match AnyCustomClassImplicit::decode_skipping(Class::ContextSpecific, number, reader) {
//         Ok(Some(custom)) => Ok(Some(custom.value)),
//         Ok(None) => Ok(None),
//         Err(err) => Err(err),
//     }
// }

// pub fn decode_explicit<'a, R: Reader<'a>, T: Decode<'a>>(
//     number: TagNumber,
//     reader: &mut R,
// ) -> Result<Option<T>, T::Error> {
//     match AnyCustomClassExplicit::decode_skipping(Class::ContextSpecific, number, reader) {
//         Ok(Some(custom)) => Ok(Some(custom.value)),
//         Ok(None) => Ok(None),
//         Err(err) => Err(err),
//     }
// }

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::{
        asn1::{
            context_specific::{ContextSpecificExplicit, ContextSpecificImplicit},
            BitStringRef, ContextSpecificExplicitRef, ContextSpecificImplicitRef, SetOf,
            Utf8StringRef,
        },
        Decode, Encode, SliceReader,
    };
    use hex_literal::hex;

    // Public key data from `pkcs8` crate's `ed25519-pkcs8-v2.der`
    const EXAMPLE_BYTES: &[u8] =
        &hex!("A123032100A3A7EAE3A8373830BC47E1167BC50E1DB551999651E0E2DC587623438EAC3F31");

    #[test]
    fn round_trip() {
        let field =
            ContextSpecificExplicit::<1, BitStringRef<'_>>::from_der(EXAMPLE_BYTES).unwrap();
        assert_eq!(
            field.value,
            BitStringRef::from_bytes(&EXAMPLE_BYTES[5..]).unwrap()
        );

        let mut buf = [0u8; 128];
        let encoded = field.encode_to_slice(&mut buf).unwrap();
        assert_eq!(encoded, EXAMPLE_BYTES);
    }

    #[test]
    fn decode_context_specific_with_explicit_field() {
        // Empty message
        let mut reader = SliceReader::new(&[]).unwrap();
        assert_eq!(
            ContextSpecificExplicit::<0, u8>::decode_skipping(&mut reader).unwrap(),
            None
        );

        // Message containing a non-context-specific type
        let mut reader = SliceReader::new(&hex!("020100")).unwrap();
        assert_eq!(
            ContextSpecificExplicit::<0, u8>::decode_skipping(&mut reader).unwrap(),
            None
        );

        // Message containing an EXPLICIT context-specific field
        let mut reader = SliceReader::new(&hex!("A003020100")).unwrap();
        let field = ContextSpecificExplicit::<0, u8>::decode_skipping(&mut reader)
            .unwrap()
            .unwrap();

        assert_eq!(field.value, 0);
    }

    #[test]
    fn decode_context_specific_with_implicit_field() {
        // From RFC8410 Section 10.3:
        // <https://datatracker.ietf.org/doc/html/rfc8410#section-10.3>
        //
        //    81  33:   [1] 00 19 BF 44 09 69 84 CD FE 85 41 BA C1 67 DC 3B
        //                  96 C8 50 86 AA 30 B6 B6 CB 0C 5C 38 AD 70 31 66
        //                  E1
        let context_specific_implicit_bytes =
            hex!("81210019BF44096984CDFE8541BAC167DC3B96C85086AA30B6B6CB0C5C38AD703166E1");

        let mut reader = SliceReader::new(&context_specific_implicit_bytes).unwrap();
        let field = ContextSpecificImplicit::<1, BitStringRef<'_>>::decode_skipping(&mut reader)
            .unwrap()
            .unwrap();

        assert_eq!(
            field.value.as_bytes().unwrap(),
            &context_specific_implicit_bytes[3..]
        );
    }

    #[test]
    fn decode_context_specific_skipping_unknown_field() {
        let mut reader = SliceReader::new(&hex!("A003020100A103020101")).unwrap();
        let field = ContextSpecificExplicit::<1, u8>::decode_skipping(&mut reader)
            .unwrap()
            .unwrap();
        assert_eq!(field.value, 1);
    }

    #[test]
    fn decode_context_specific_returns_none_on_greater_tag_number() {
        let mut reader = SliceReader::new(&hex!("A103020101")).unwrap();
        assert_eq!(
            ContextSpecificExplicit::<0, u8>::decode_skipping(&mut reader).unwrap(),
            None
        );
    }

    #[test]
    fn encode_context_specific_explicit_ref() {
        let mut set = SetOf::new();
        set.insert(8u16).unwrap();
        set.insert(7u16).unwrap();

        let field = ContextSpecificExplicitRef::<2, SetOf<u16, 2>> { value: &set };

        let mut buf = [0u8; 16];
        let encoded = field.encode_to_slice(&mut buf).unwrap();
        assert_eq!(
            encoded,
            &[
                /* CONTEXT-SPECIFIC [2] */ 0xA2, 0x08, /* SET 0x11 | 0x20 */ 0x31, 0x06,
                /* INTEGER */ 0x02, 0x01, 0x07, /* INTEGER */ 0x02, 0x01, 0x08
            ]
        );

        let mut reader = SliceReader::new(encoded).unwrap();
        let field = ContextSpecificExplicit::<2, SetOf<u16, 2>>::decode_skipping(&mut reader)
            .unwrap()
            .unwrap();

        assert_eq!(field.value.len(), 2);
        assert_eq!(field.value.get(0).cloned(), Some(7));
        assert_eq!(field.value.get(1).cloned(), Some(8));
    }

    #[test]
    fn encode_context_specific_implicit_ref() {
        let hello = Utf8StringRef::new("Hello").unwrap();
        let world = Utf8StringRef::new("world").unwrap();

        let mut set = SetOf::new();
        set.insert(hello).unwrap();
        set.insert(world).unwrap();

        let field = ContextSpecificImplicitRef::<2, SetOf<Utf8StringRef<'_>, 2>> { value: &set };

        let mut buf = [0u8; 16];
        let encoded = field.encode_to_slice(&mut buf).unwrap();
        assert_eq!(
            encoded,
            &[
                0xA2, 0x0E, // CONTEXT-SPECIFIC [2]
                0x0C, 0x05, b'H', b'e', b'l', b'l', b'o', // UTF8String "Hello"
                0x0C, 0x05, b'w', b'o', b'r', b'l', b'd', // UTF8String "world"
            ]
        );

        let mut reader = SliceReader::new(encoded).unwrap();
        let field =
            ContextSpecificImplicit::<2, SetOf<Utf8StringRef<'_>, 2>>::decode_skipping(&mut reader)
                .unwrap()
                .unwrap();

        assert_eq!(field.value.len(), 2);
        assert_eq!(field.value.get(0).cloned(), Some(hello));
        assert_eq!(field.value.get(1).cloned(), Some(world));
    }
}
