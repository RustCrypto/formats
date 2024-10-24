//! Application field.

use crate::tag::CLASS_APPLICATION;

use super::custom_class::{
    CustomClassExplicit, CustomClassExplicitRef, CustomClassImplicit, CustomClassImplicitRef,
};

/// Application class, EXPLICIT
pub type ApplicationExplicit<const TAG: u16, T> = CustomClassExplicit<TAG, T, CLASS_APPLICATION>;

/// Application class, IMPLICIT
pub type ApplicationImplicit<const TAG: u16, T> = CustomClassImplicit<TAG, T, CLASS_APPLICATION>;

/// Application class, reference, EXPLICIT
pub type ApplicationExplicitRef<'a, const TAG: u16, T> =
    CustomClassExplicitRef<'a, TAG, T, CLASS_APPLICATION>;

/// Application class, reference, IMPLICIT
pub type ApplicationImplicitRef<'a, const TAG: u16, T> =
    CustomClassImplicitRef<'a, TAG, T, CLASS_APPLICATION>;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::{
        asn1::{context_specific::ContextSpecificExplicit, OctetStringRef},
        Decode, Encode,
    };
    use hex_literal::hex;

    #[test]
    fn round_trip() {
        const EXAMPLE_BYTES: &[u8] = &hex!(
            "A2 06"
            "04 04"
            "01020304"
        );

        let field =
            ContextSpecificExplicit::<2, OctetStringRef<'_>>::from_der(EXAMPLE_BYTES).unwrap();
        assert_eq!(field.value, OctetStringRef::new(&[1, 2, 3, 4]).unwrap());

        let mut buf = [0u8; 128];
        let encoded = field.encode_to_slice(&mut buf).unwrap();
        assert_eq!(encoded, EXAMPLE_BYTES);
    }
}
