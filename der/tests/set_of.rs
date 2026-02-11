//! `SetOf` tests.

#![cfg(feature = "alloc")]

use der::{DerOrd, asn1::SetOfVec};
use proptest::{prelude::*, string::*};
use std::collections::BTreeSet;

proptest! {
    #[test]
    fn sort_equiv(bytes in bytes_regex(".{0,64}").unwrap()) {
        let mut uniq = BTreeSet::new();

        // Ensure there are no duplicates
        if bytes.iter().copied().all(move |x| uniq.insert(x)) {
            let mut expected = bytes.clone();
            expected.sort_by(|a, b| a.der_cmp(b).unwrap());

            let set = SetOfVec::try_from(bytes).unwrap();
            prop_assert_eq!(expected.as_slice(), set.as_slice());
        }
    }
}

/// Set ordering tests.
#[cfg(all(feature = "derive", feature = "oid"))]
mod ordering {
    use der::{
        Decode, Sequence, ValueOrd,
        asn1::{AnyRef, ObjectIdentifier, SetOfVec},
    };
    use hex_literal::hex;

    /// X.501 `AttributeTypeAndValue`
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
    pub struct AttributeTypeAndValue<'a> {
        pub oid: ObjectIdentifier,
        pub value: AnyRef<'a>,
    }

    const OUT_OF_ORDER_RDN_EXAMPLE: &[u8] =
        &hex!("311F301106035504030C0A4A4F484E20534D495448300A060355040A0C03313233");

    /// Same as above, with `SetOfVec` instead of `SetOf`.
    #[test]
    fn allow_out_of_order_setofvec() {
        assert!(SetOfVec::<AttributeTypeAndValue<'_>>::from_der(OUT_OF_ORDER_RDN_EXAMPLE).is_ok());
    }
}
