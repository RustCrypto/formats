//! PKCS#7 example tests

use der::{
    asn1::{ObjectIdentifier, OctetStringRef, SequenceRef},
    Decode, Encode, Length, SliceWriter,
};
use hex_literal::hex;
use pkcs7::{
    cms_version::CmsVersion, encapsulated_content_info::EncapsulatedContentInfo,
    encrypted_data_content::EncryptedDataContent, enveloped_data_content::EncryptedContentInfo,
    signed_data_content::SignedDataContent, ContentInfo, ContentType,
};
use spki::AlgorithmIdentifierRef;
use std::fs;

fn encode_content_info<'a>(content_info: &ContentInfo<'a>, buf: &'a mut [u8]) -> &'a [u8] {
    let mut encoder = SliceWriter::new(buf);
    encoder.encode(content_info).expect("encoded content info");
    encoder.finish().expect("encoding success")
}

#[test]
fn decode_cert_example() {
    let path = "./tests/examples/certData.bin";
    let bytes = fs::read(&path).expect(&format!("Failed to read from {}", &path));

    let content = ContentInfo::from_der(&bytes).expect("expected valid data");

    match content {
        ContentInfo::Data(Some(data)) => assert_eq!(data.content.len(), 781),
        _ => panic!("expected ContentInfo::Data(Some(_))"),
    }

    let mut buf = vec![0u8; bytes.len()];
    let encoded_content = encode_content_info(&content, &mut buf);

    assert_eq!(encoded_content, bytes);
}

#[test]
fn decode_encrypted_key_example() {
    let path = "./tests/examples/keyEncryptedData.bin";
    let bytes = fs::read(&path).expect(&format!("Failed to read from {}", &path));

    let content = ContentInfo::from_der(&bytes).expect("expected valid data");

    let expected_oid = ObjectIdentifier::new("1.2.840.113549.1.12.1.6").unwrap();
    let expected_salt = &hex!("ad2d4b4e87b34d67");
    match content {
        ContentInfo::EncryptedData(Some(EncryptedDataContent {
            version: _,
            encrypted_content_info:
                EncryptedContentInfo {
                    content_type: ContentType::Data,
                    content_encryption_algorithm:
                        AlgorithmIdentifierRef {
                            oid,
                            parameters: Some(any),
                        },
                    encrypted_content: Some(bytes),
                },
        })) => {
            assert_eq!(oid, expected_oid);

            let (salt, iter) = any
                .sequence(|decoder| {
                    let salt = OctetStringRef::decode(decoder)?;
                    let iter = u16::decode(decoder)?;
                    Ok((salt, iter))
                })
                .expect("salt and iters parameters");
            assert_eq!(salt.as_bytes(), expected_salt);
            assert_eq!(iter, 2048);

            assert_eq!(bytes.len(), 552)
        }
        _ => panic!("expected ContentInfo::Data(Some(_))"),
    }

    let mut buf = vec![0u8; bytes.len()];
    let encoded_content = encode_content_info(&content, &mut buf);

    assert_eq!(encoded_content, bytes)
}

#[test]
fn decode_signed_mdm_example() {
    let path = "./tests/examples/apple_mdm_signature_der.bin";
    let bytes = fs::read(&path).expect(&format!("Failed to read from {}", &path));

    let content = ContentInfo::from_der(&bytes).expect("expected valid data");

    match content {
        ContentInfo::SignedData(Some(SignedDataContent {
            version: _,
            digest_algorithms: _,
            encap_content_info:
                EncapsulatedContentInfo {
                    e_content_type: _,
                    e_content: Some(content),
                },
            certificates: _,
            crls: _,
            signer_infos: _,
        })) => {
            let _content = content
                .decode_into::<SequenceRef>()
                .expect("Content should be in the correct format: SequenceRef");
        }
        _ => panic!("expected ContentInfo::SignedData(Some(_))"),
    }
}

#[test]
fn decode_signed_scep_example() {
    let path = "./tests/examples/scep_der.bin";
    let bytes = fs::read(&path).expect(&format!("Failed to read from {}", &path));

    let content = ContentInfo::from_der(&bytes).expect("expected valid data");

    match content {
        ContentInfo::SignedData(Some(SignedDataContent {
            version: ver,
            digest_algorithms: _,
            encap_content_info:
                EncapsulatedContentInfo {
                    e_content_type: _,
                    e_content: Some(content),
                },
            certificates: _,
            crls: _,
            signer_infos: _,
        })) => {
            let _content = content
                .decode_into::<OctetStringRef>()
                .expect("Content should be in the correct format: OctetStringRef");

            assert_eq!(ver, CmsVersion::V1)
        }
        _ => panic!("expected ContentInfo::SignedData(Some(_))"),
    }
}

#[test]
fn decode_signed_ber() {
    let path = "./tests/examples/cms_der.bin";
    let bytes = fs::read(&path).expect(&format!("Failed to read from {}", &path));

    let content = ContentInfo::from_der(&bytes).expect("expected valid data");

    match content {
        ContentInfo::SignedData(Some(data)) => {
            assert_eq!(
                data.encap_content_info
                    .e_content
                    .unwrap()
                    .decode_into::<OctetStringRef>()
                    .unwrap()
                    .as_bytes()
                    .len(),
                10034
            )
        }
        _ => panic!("expected ContentInfo::SignedData(Some(_))"),
    }
}
