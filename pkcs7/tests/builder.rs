// TODO NM #![cfg(feature = "builder")]

use const_oid::db::DB;
use der::asn1::{OctetStringRef, SetOfVec, Utf8StringRef};
use der::Any;
use p256::{pkcs8::DecodePrivateKey, NistP256};
use pkcs7::algorithm_identifier_types::DigestAlgorithmIdentifier;
use pkcs7::builder::*;
use pkcs7::cms_version::CmsVersion;
use pkcs7::signer_info::{IssuerAndSerialNumber, SignerIdentifier, SignerInfo};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use sha2::Sha256;
use spki::AlgorithmIdentifier;
use x509_cert::attr::{Attribute, AttributeTypeAndValue};
use x509_cert::name::{RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;

// {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) rsaEncryption(1)}
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
// {iso(1) identified-organization(3) thawte(101) id-Ed25519(112)}
const OID_ED25519: &str = "1.3.101.112";
// {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7) signedData(2)}
const OID_PKCS7_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

const RSA_2048_PRIV_DER_EXAMPLE: &[u8] = include_bytes!("examples/rsa2048-priv.der");
const PKCS8_PRIVATE_KEY_DER: &[u8] = include_bytes!("examples/p256-priv.der");

fn rsa_signer() -> SigningKey<Sha256> {
    let private_key = rsa::RsaPrivateKey::from_pkcs1_der(RSA_2048_PRIV_DER_EXAMPLE).unwrap();
    let signing_key = SigningKey::<Sha256>::new_with_prefix(private_key);
    signing_key
}

fn ecdsa_signer() -> ecdsa::SigningKey<NistP256> {
    let secret_key = p256::SecretKey::from_pkcs8_der(PKCS8_PRIVATE_KEY_DER).unwrap();
    ecdsa::SigningKey::from(secret_key)
}

fn signer_identifier() -> SignerIdentifier {
    let mut rdn_sequence = RdnSequence::default();
    let rdn = &[AttributeTypeAndValue {
        oid: const_oid::db::rfc4519::CN,
        value: Any::from(Utf8StringRef::new("test client").unwrap()),
    }];
    let set_of_vector = SetOfVec::try_from(rdn.to_vec()).unwrap();
    rdn_sequence
        .0
        .push(RelativeDistinguishedName::from(set_of_vector));
    SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        name: rdn_sequence,
        serial_number: SerialNumber::from(123456u32),
    })
}

#[test]
fn build_signed_data() {
    let mut builder = SignedDataBuilder::new();
    let digest_algorithm = DigestAlgorithmIdentifier {
        oid: der::asn1::ObjectIdentifier::new(OID_RSA_ENCRYPTION).unwrap(),
        parameters: None,
    };
    let mut signer = rsa_signer();
    let signer_info = SignerInfo {
        version: CmsVersion::V0,
        sid: signer_identifier(),
        digest_algorithm,
        signed_attributes: None,
        signature_algorithm: AlgorithmIdentifier {
            oid: DB.by_name("id-sha256").unwrap().to_owned(),
            parameters: None,
        },
        signature: OctetStringRef::new(&[]).unwrap(), // will be set during signing
        unsigned_attributes: None,
    };
    let external_message_digest = None;
    builder.add_digest_algorithm(digest_algorithm).expect("could not add a digest algorithm");
    builder
        .sign(&mut signer, signer_info, external_message_digest)
        .expect("signing signed data failed");
    let _signed_data_pkcs7 = builder.build().expect("building signed data failed");
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
    let tag = signing_time
        .value()
        .get(0)
        .expect("Could not read tag number from signed time attribute value");
    assert!(
        *tag == 23 || *tag == 24,
        "Invalid tag number in signing time attribute value"
    );
}
