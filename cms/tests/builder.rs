// TODO NM #![cfg(feature = "builder")]

use cms::builder::{create_signing_time_attribute, SignedDataBuilder};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::CmsVersion;
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier, SignerInfo};
use der::asn1::{OctetString, SetOfVec, Utf8StringRef};
use der::{Any, DecodePem, Encode, Tag, Tagged};
use pem_rfc7468::LineEnding;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use sha2::Sha256;
use spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned};
use x509_cert::attr::{Attribute, AttributeTypeAndValue};
use x509_cert::name::{RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;

const RSA_2048_PRIV_DER_EXAMPLE: &[u8] = include_bytes!("examples/rsa2048-priv.der");

fn rsa_signer() -> SigningKey<Sha256> {
    let private_key = rsa::RsaPrivateKey::from_pkcs1_der(RSA_2048_PRIV_DER_EXAMPLE).unwrap();
    let signing_key = SigningKey::<Sha256>::new(private_key);
    signing_key
}

fn signer_identifier(id: i32) -> SignerIdentifier {
    let mut rdn_sequence = RdnSequence::default();
    let rdn = &[AttributeTypeAndValue {
        oid: const_oid::db::rfc4519::CN,
        value: Any::from(Utf8StringRef::new(&format!("test client {id}")).unwrap()),
    }];
    let set_of_vector = SetOfVec::try_from(rdn.to_vec()).unwrap();
    rdn_sequence
        .0
        .push(RelativeDistinguishedName::from(set_of_vector));
    SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: rdn_sequence,
        serial_number: SerialNumber::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
            .expect("failed to create a serial number"),
    })
}

#[test]
fn build_signed_data() {
    let mut builder = SignedDataBuilder::new();
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };
    let content = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: Some(
            Any::new(
                Tag::OctetString,
                OctetString::new(vec![48]).unwrap().to_der().unwrap(),
            )
            .unwrap(),
        ),
    };
    let certificate_buf = include_bytes!("examples/ValidCertificatePathTest1EE.pem");
    let certificate = x509_cert::Certificate::from_pem(certificate_buf).unwrap();
    let mut signer = rsa_signer();
    let signer_info = SignerInfo {
        version: CmsVersion::V1, // sid: IssuerAndSerialNumber -> V1, subjectKeyIdentifier -> V3
        sid: signer_identifier(1),
        digest_alg: digest_algorithm.clone(),
        signed_attrs: None,
        signature_algorithm: AlgorithmIdentifier {
            oid: const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        },
        signature: OctetString::new(Vec::new()).unwrap(), // will be set during signing
        unsigned_attrs: None,
    };
    let external_message_digest = None;
    let signed_data_pkcs7 = builder
        .add_digest_algorithm(digest_algorithm)
        .expect("could not add a digest algorithm")
        .set_content_info(content)
        .expect("adding content failed")
        .add_certificate(CertificateChoices::Certificate(certificate))
        .expect("error adding certificate")
        .sign(&mut signer, signer_info, external_message_digest)
        .expect("signing signed data failed")
        .build()
        .expect("building signed data failed");
    let signed_data_pkcs7_der = signed_data_pkcs7
        .to_der()
        .expect("conversion of signed data to DER failed.");
    println!(
        "{}",
        pem_rfc7468::encode_string("PKCS7", LineEnding::LF, &signed_data_pkcs7_der)
            .expect("PEM encoding of signed data DER failed")
    );
}

#[test]
fn test_create_signing_attribute() {
    let attribute: Attribute =
        create_signing_time_attribute().expect("Creation of signing time attribute failed.");
    let mut arcs = attribute.oid.arcs();
    assert_eq!(
        arcs.next(),
        Some(1),
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        arcs.next(),
        Some(2),
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        arcs.next(),
        Some(840),
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        arcs.next(),
        Some(113549),
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        arcs.next(),
        Some(1),
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        arcs.next(),
        Some(9),
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        arcs.next(),
        Some(5),
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        arcs.next(),
        None,
        "Invalid arc value in signing time attribute value"
    );
    assert_eq!(
        attribute.values.len(),
        1,
        "Too many attribute values in signing time attribute"
    );
    let signing_time = attribute
        .values
        .iter()
        .next()
        .expect("No time in signing time attribute");
    let tag = signing_time.tag();
    assert!(
        tag == Tag::GeneralizedTime || tag == Tag::UtcTime,
        "Invalid tag number in signing time attribute value"
    );
}
