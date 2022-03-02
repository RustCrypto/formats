//! PKCS#7 example tests

use der::{asn1::ObjectIdentifier, Decodable, Encoder};
use hex_literal::hex;
use pkcs7::{
    encrypted_data_content::EncryptedDataContent, enveloped_data_content::EncryptedContentInfo,
    ContentInfo, ContentType,
};
use spki::AlgorithmIdentifier;
use std::fs;

fn encode_content_info<'a>(content_info: &ContentInfo<'a>, buf: &'a mut [u8]) -> &'a [u8] {
    let mut encoder = Encoder::new(buf);
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
                        AlgorithmIdentifier {
                            oid,
                            parameters: Some(any),
                        },
                    encrypted_content: Some(bytes),
                },
        })) => {
            assert_eq!(oid, expected_oid);

            let (salt, iter) = any
                .sequence(|decoder| {
                    let salt = decoder.octet_string()?;
                    let iter = decoder.uint16()?;
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
