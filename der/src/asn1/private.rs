//! Private field.

use crate::tag::CLASS_PRIVATE;

use super::custom_class::{
    CustomClassExplicit, CustomClassExplicitRef, CustomClassImplicit, CustomClassImplicitRef,
};

/// Private class, EXPLICIT
pub type PrivateExplicit<const TAG: u16, T> = CustomClassExplicit<TAG, T, CLASS_PRIVATE>;

/// Private class, IMPLICIT
pub type PrivateImplicit<const TAG: u16, T> = CustomClassImplicit<TAG, T, CLASS_PRIVATE>;

/// Private class, reference, EXPLICIT
pub type PrivateExplicitRef<'a, const TAG: u16, T> =
    CustomClassExplicitRef<'a, TAG, T, CLASS_PRIVATE>;

/// Private class, reference, IMPLICIT
pub type PrivateImplicitRef<'a, const TAG: u16, T> =
    CustomClassImplicitRef<'a, TAG, T, CLASS_PRIVATE>;

// /// Private field reference.
// ///
// /// This type encodes a field which is whose meaning is specific to a given
// /// enterprise and is identified by a [`TagNumber`].
// #[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
// pub struct PrivateRef<'a, T> {
//     /// Private tag number sans the leading `0b11000000` class
//     /// identifier bit and `0b100000` constructed flag.
//     pub tag_number: TagNumber,

//     /// Tag mode: `EXPLICIT` VS `IMPLICIT`.
//     pub tag_mode: TagMode,

//     /// Value of the field.
//     pub value: &'a T,
// }

// impl<'a, T> PrivateRef<'a, T> {
//     /// Convert to a [`Private`].
//     fn encoder(&self) -> Private<EncodeValueRef<'a, T>> {
//         Private {
//             tag_number: self.tag_number,
//             tag_mode: self.tag_mode,
//             value: EncodeValueRef(self.value),
//         }
//     }
// }

// impl<'a, T> EncodeValue for PrivateRef<'a, T>
// where
//     T: EncodeValue + Tagged,
// {
//     fn value_len(&self) -> Result<Length, Error> {
//         self.encoder().value_len()
//     }

//     fn encode_value(&self, writer: &mut impl Writer) -> Result<(), Error> {
//         self.encoder().encode_value(writer)
//     }
// }

// impl<'a, T> Tagged for PrivateRef<'a, T>
// where
//     T: Tagged,
// {
//     fn tag(&self) -> Tag {
//         self.encoder().tag()
//     }
// }

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::PrivateExplicit;
    use super::PrivateImplicit;
    use crate::asn1::PrivateExplicitRef;
    use crate::asn1::PrivateImplicitRef;
    use crate::{asn1::BitStringRef, Decode, Encode, SliceReader};
    use hex_literal::hex;

    const EXAMPLE_BYTES: &[u8] =
        &hex!("E123032100A3A7EAE3A8373830BC47E1167BC50E1DB551999651E0E2DC587623438EAC3F31");

    #[test]
    fn round_trip() {
        let field = PrivateExplicit::<1, BitStringRef<'_>>::from_der(EXAMPLE_BYTES).unwrap();
        assert_eq!(
            field.value,
            BitStringRef::from_bytes(&EXAMPLE_BYTES[5..]).unwrap()
        );

        let mut buf = [0u8; 128];
        let encoded = field.encode_to_slice(&mut buf).unwrap();
        assert_eq!(encoded, EXAMPLE_BYTES);
    }

    #[test]
    fn encode_round_trip() {
        let field = PrivateExplicit::<1, u16> { value: 257u16 };
        let mut buf = [0u8; 128];
        let encoded = field.encode_to_slice(&mut buf).unwrap();

        let mut reader = SliceReader::new(encoded).unwrap();
        let field = PrivateExplicit::<1, u16>::decode_skipping(&mut reader)
            .unwrap()
            .unwrap();

        assert_eq!(field.value, 257u16);
    }

    #[test]
    fn encode_round_trip_ref_explicit() {
        let value: u16 = 257u16;

        let field = PrivateExplicitRef::<1, u16> { value: &value };
        let mut buf = [0u8; 128];
        let encoded = field.encode_to_slice(&mut buf).unwrap();

        let mut reader = SliceReader::new(encoded).unwrap();
        let field = PrivateExplicit::<1, u16>::decode_skipping(&mut reader)
            .unwrap()
            .unwrap();

        assert_eq!(field.value, 257u16);
    }

    #[test]
    fn encode_round_trip_ref_implicit() {
        let value: u16 = 257u16;

        let field = PrivateImplicitRef::<1, u16> { value: &value };
        let mut buf = [0u8; 128];
        let encoded = field.encode_to_slice(&mut buf).unwrap();

        let mut reader = SliceReader::new(encoded).unwrap();
        let field = PrivateImplicit::<1, u16>::decode_skipping(&mut reader)
            .unwrap()
            .unwrap();

        assert_eq!(field.value, 257u16);
    }

    #[test]
    fn private_with_explicit_field() {
        // Empty message
        let mut reader = SliceReader::new(&[]).unwrap();
        assert_eq!(
            PrivateImplicit::<0, u8>::decode_skipping(&mut reader).unwrap(),
            None
        );

        // Message containing a non-private type
        let mut reader = SliceReader::new(&hex!("020100")).unwrap();
        assert_eq!(
            PrivateImplicit::<0, u8>::decode_skipping(&mut reader).unwrap(),
            None
        );

        // Message containing an EXPLICIT private field
        let mut reader = SliceReader::new(&hex!("E003020100")).unwrap();
        let field = PrivateExplicit::<0, _>::decode_skipping(&mut reader)
            .unwrap()
            .unwrap();

        let value: u8 = field.value;

        assert_eq!(value, 0);

        // Message containing an EXPLICIT private field, primitive (not constructed)
        let mut reader = SliceReader::new(&hex!("C003020100")).unwrap();
        let result = PrivateExplicit::<0, u8>::decode_skipping(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn private_with_implicit_field() {
        let private_implicit_bytes =
            hex!("C1210019BF44096984CDFE8541BAC167DC3B96C85086AA30B6B6CB0C5C38AD703166E1");

        let mut reader = SliceReader::new(&private_implicit_bytes).unwrap();
        let field = PrivateImplicit::<1, BitStringRef<'_>>::decode(&mut reader).unwrap();

        assert_eq!(
            field.value.as_bytes().unwrap(),
            &private_implicit_bytes[3..]
        );
    }

    #[test]
    fn private_not_skipping_unknown_field() {
        let mut reader = SliceReader::new(&hex!("E003020100E103020101")).unwrap();
        let field = PrivateExplicit::<1, u8>::decode_skipping(&mut reader).unwrap();
        assert_eq!(field, None);
    }

    #[test]
    fn private_returns_none_on_unequal_tag_number() {
        let mut reader = SliceReader::new(&hex!("C103020101")).unwrap();
        assert_eq!(
            PrivateExplicit::<0, u8>::decode_skipping(&mut reader).unwrap(),
            None
        );
    }
}
