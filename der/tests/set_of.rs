//! `SetOf` tests.

#[cfg(feature = "alloc")]
use {
    der::{asn1::SetOfVec, DerOrd},
    proptest::{prelude::*, string::*},
};

#[cfg(feature = "alloc")]
proptest! {
    #[test]
    fn sort_equiv(bytes in bytes_regex(".{0,64}").unwrap()) {
        let mut expected = bytes.clone();
        expected.sort_by(|a, b| a.der_cmp(b).unwrap());

        let set = SetOfVec::try_from(bytes).unwrap();
        prop_assert_eq!(expected.as_slice(), set.as_slice());
    }
}

#[cfg(all(feature = "derive", feature = "oid"))]
mod attr_regression {
    #![cfg(all(feature = "derive", feature = "oid"))]

    use core::cmp::Ordering;
    use der::{
        asn1::{Any, ObjectIdentifier, SetOf},
        Decode, Result, Sequence, ValueOrd,
    };
    use hex_literal::hex;

    /// Attribute type/value pairs as defined in [RFC 5280 Section 4.1.2.4].
    ///
    /// [RFC 5280 Section 4.1.2.4]: https://tools.ietf.org/html/rfc5280#section-4.1.2.4
    #[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence)]
    pub struct AttributeTypeAndValue<'a> {
        /// OID describing the type of the attribute
        pub oid: ObjectIdentifier,

        /// Value of the attribute
        pub value: Any<'a>,
    }

    impl ValueOrd for AttributeTypeAndValue<'_> {
        fn value_cmp(&self, other: &Self) -> Result<Ordering> {
            match self.oid.value_cmp(&other.oid)? {
                Ordering::Equal => self.value.value_cmp(&other.value),
                other => Ok(other),
            }
        }
    }

    /// Test to ensure ordering is handled correctly.
    #[test]
    fn ordering_regression() {
        let der_bytes = hex!("3139301906035504030C12546573742055736572393031353734333830301C060A0992268993F22C640101130E3437303031303030303134373333");
        let set = SetOf::<AttributeTypeAndValue<'_>, 3>::from_der(&der_bytes).unwrap();
        let attr1 = set.get(0).unwrap();
        assert_eq!(ObjectIdentifier::new("2.5.4.3").unwrap(), attr1.oid);
    }
}
