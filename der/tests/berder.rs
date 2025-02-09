//! BER to DER tests.
#![cfg(feature = "alloc")]

use der::{ber_to_der, Encode, Length, Result, SliceWriter, Tag, Writer};
use proptest::prelude::*;

const ROOT_CA: &[u8] = include_bytes!("examples/root_cert.der");
const ENCLAVE_CMS: &[u8] = include_bytes!("examples/cms_enveloped_data.ber");
const ENCLAVE_CMS_AS_DER: &[u8] = include_bytes!("examples/cms_enveloped_data.der");

#[test]
fn der_test_vectors() -> Result<()> {
    assert_eq!(ROOT_CA, &ber_to_der(ROOT_CA)?);
    assert_eq!(ENCLAVE_CMS_AS_DER, &ber_to_der(ENCLAVE_CMS_AS_DER)?);
    Ok(())
}

#[test]
fn ber_to_der_test_vectors() -> Result<()> {
    assert_eq!(ENCLAVE_CMS_AS_DER, &ber_to_der(ENCLAVE_CMS)?);
    Ok(())
}

#[derive(Clone, Debug)]
enum Doc {
    Null,
    Bool(bool),
    Int(i32),
    Seq(Vec<Doc>),
}

impl Doc {
    fn arb() -> impl Strategy<Value = Doc> {
        let leaf = prop_oneof![
            Just(Doc::Null),
            any::<bool>().prop_map(Doc::Bool),
            any::<i32>().prop_map(Doc::Int),
        ];
        leaf.prop_recursive(5, 64, 3, |inner| {
            prop_oneof![prop::collection::vec(inner.clone(), 0..3).prop_map(Doc::Seq)]
        })
    }

    fn encoded_len_der(&self) -> der::Result<Length> {
        match self {
            Doc::Null => der::asn1::Null.encoded_len(),
            Doc::Bool(b) => b.encoded_len(),
            Doc::Int(i) => i.encoded_len(),
            Doc::Seq(docs) => {
                let mut len = Length::ZERO;
                for d in docs {
                    len = (len + d.encoded_len_der()?)?
                }
                len.for_tlv()
            }
        }
    }

    fn encoded_len_ber(&self) -> der::Result<Length> {
        match self {
            Doc::Null => der::asn1::Null.encoded_len(),
            Doc::Bool(b) => b.encoded_len(),
            Doc::Int(i) => i.encoded_len(),
            Doc::Seq(docs) => {
                let mut len = Length::ZERO;
                for d in docs {
                    len = (len + d.encoded_len_ber()?)?
                }
                len + Length::from(4u8) // 1 tag, 1 0x80, 2 0x0000
            }
        }
    }

    fn to_der1(&self, w: &mut SliceWriter) -> der::Result<()> {
        match self {
            Doc::Null => der::asn1::Null.encode(w),
            Doc::Bool(b) => b.encode(w),
            Doc::Int(i) => i.encode(w),
            Doc::Seq(docs) => {
                let len = {
                    let mut len = Length::ZERO;
                    for d in docs {
                        len = (len + d.encoded_len_der()?)?
                    }
                    len
                };
                w.sequence(len, |w| {
                    for d in docs {
                        d.to_der1(w)?
                    }
                    Ok(())
                })
            }
        }
    }

    fn to_ber1(&self, w: &mut SliceWriter) -> der::Result<()> {
        match self {
            Doc::Null => der::asn1::Null.encode(w),
            Doc::Bool(b) => b.encode(w),
            Doc::Int(i) => i.encode(w),
            Doc::Seq(docs) => {
                Tag::Sequence.encode(w)?;
                w.write_byte(0x80)?;
                for d in docs {
                    d.to_ber1(w)?
                }
                w.write(&[0x00, 0x00])
            }
        }
    }

    fn to_der(&self) -> der::Result<Vec<u8>> {
        let len = usize::try_from(self.encoded_len_der()?)?;
        let mut buf = vec![0u8; len];
        let mut w = SliceWriter::new(&mut buf);
        self.to_der1(&mut w)?;
        Ok(w.finish()?.to_vec())
    }

    fn to_ber(&self) -> der::Result<Vec<u8>> {
        let len = usize::try_from(self.encoded_len_ber()?)?;
        let mut buf = vec![0u8; len];
        let mut w = SliceWriter::new(&mut buf);
        self.to_ber1(&mut w)?;
        Ok(w.finish()?.to_vec())
    }
}

fn ber_to_der_round_trip(doc: Doc) -> der::Result<(Vec<u8>, Vec<u8>)> {
    let der = doc.to_der()?;

    let der1 = ber_to_der(&der)?;

    Ok((der, der1))
}

fn ber_to_der_compare(doc: Doc) -> der::Result<(Vec<u8>, Vec<u8>)> {
    let ber = doc.to_ber()?;
    let der = doc.to_der()?;

    let der1 = ber_to_der(&ber)?;

    Ok((der, der1))
}

proptest! {
    #[test]
    fn prop_ber_to_der_round_trip(doc in Doc::arb()) {
        match ber_to_der_round_trip(doc) {
            Ok((expected, actual)) => prop_assert_eq!(expected, actual),
            Err(err) => panic!("Unexpected error: {}", err),
        }
    }

    #[test]
    fn prop_ber_to_der_compare(doc in Doc::arb()) {
        match ber_to_der_compare(doc) {
            Ok((expected, actual)) => prop_assert_eq!(expected, actual),
            Err(err) => panic!("Unexpected error: {}", err),
        }
    }
}
