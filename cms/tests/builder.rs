#![cfg(feature = "builder")]

use cms::builder::{
    create_signing_time_attribute, ContentEncryptionAlgorithm, EnvelopedDataBuilder,
    KeyEncryptionInfo, KeyTransRecipientInfoBuilder, SignedDataBuilder, SignerInfoBuilder,
};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::ContentInfo;
use cms::enveloped_data::RecipientIdentifier;
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use const_oid::ObjectIdentifier;
use der::asn1::{Int, OctetString, PrintableString, SetOfVec, Utf8StringRef};
use der::{Any, AnyRef, DecodePem, Encode, Tag, Tagged};
use p256::{pkcs8::DecodePrivateKey, NistP256};
use pem_rfc7468::LineEnding;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::{rand_core, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::{Attribute, AttributeTypeAndValue, AttributeValue};
use x509_cert::name::{RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;

// TODO bk replace this by const_oid definitions as soon as merged
const RFC8894_ID_MESSAGE_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.2");
const RFC8894_ID_SENDER_NONCE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.5");
const RFC8894_ID_TRANSACTION_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.7");

const RSA_2048_PRIV_DER_EXAMPLE: &[u8] = include_bytes!("examples/rsa2048-priv.der");
const PKCS8_PRIVATE_KEY_DER: &[u8] = include_bytes!("examples/p256-priv.der");

fn rsa_signer() -> SigningKey<Sha256> {
    let private_key = rsa::RsaPrivateKey::from_pkcs1_der(RSA_2048_PRIV_DER_EXAMPLE).unwrap();
    let signing_key = SigningKey::<Sha256>::new(private_key);
    signing_key
}

fn ecdsa_signer() -> ecdsa::SigningKey<NistP256> {
    let secret_key = p256::SecretKey::from_pkcs8_der(PKCS8_PRIVATE_KEY_DER).unwrap();
    ecdsa::SigningKey::from(secret_key)
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

fn recipient_identifier(id: i32) -> RecipientIdentifier {
    let mut rdn_sequence = RdnSequence::default();
    let rdn = &[AttributeTypeAndValue {
        oid: const_oid::db::rfc4519::CN,
        value: Any::from(Utf8StringRef::new(&format!("test client {id}")).unwrap()),
    }];
    let set_of_vector = SetOfVec::try_from(rdn.to_vec()).unwrap();
    rdn_sequence
        .0
        .push(RelativeDistinguishedName::from(set_of_vector));
    RecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: rdn_sequence,
        serial_number: SerialNumber::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
            .expect("failed to create a serial number"),
    })
}

#[test]
fn test_build_signed_data() {
    // Make some content
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
    // Create multiple signer infos
    let signer = rsa_signer();
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };
    let external_message_digest = None;
    let signer_info_builder_1 = SignerInfoBuilder::new(
        &signer,
        signer_identifier(1),
        digest_algorithm.clone(),
        &content,
        external_message_digest,
    )
    .expect("Could not create RSA SignerInfoBuilder");

    let signer_2 = ecdsa_signer();
    let digest_algorithm_2 = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_512,
        parameters: None,
    };
    let external_message_digest_2 = None;
    let signer_info_builder_2 = SignerInfoBuilder::new(
        &signer_2,
        signer_identifier(1),
        digest_algorithm_2.clone(),
        &content,
        external_message_digest_2,
    )
    .expect("Could not create ECDSA SignerInfoBuilder");

    let certificate_buf = include_bytes!("examples/ValidCertificatePathTest1EE.pem");
    let certificate = x509_cert::Certificate::from_pem(certificate_buf).unwrap();

    let mut builder = SignedDataBuilder::new(&content);

    let signed_data_pkcs7 = builder
        .add_digest_algorithm(digest_algorithm)
        .expect("could not add a digest algorithm")
        .add_certificate(CertificateChoices::Certificate(certificate))
        .expect("error adding certificate")
        .add_signer_info::<SigningKey<Sha256>, rsa::pkcs1v15::Signature>(signer_info_builder_1)
        .expect("error adding RSA signer info")
        .add_signer_info::<ecdsa::SigningKey<NistP256>, p256::ecdsa::DerSignature>(
            signer_info_builder_2,
        )
        .expect("error adding P256 signer info")
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

// TODO more tests:
// - external message
// - PKCS #7 message:
//   - different encapsulated content ASN.1 encoding
//   - additional signed attributes

#[test]
fn test_build_enveloped_data() {
    let recipient_identifier = recipient_identifier(1);
    let mut rng = rand_core::OsRng;
    let bits = 2048;
    let recipient_private_key =
        RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let recipient_public_key = RsaPublicKey::from(&recipient_private_key);
    let recipient_info_builder = KeyTransRecipientInfoBuilder::new(
        recipient_identifier,
        KeyEncryptionInfo::Rsa(recipient_public_key),
    )
    .expect("Could not create a KeyTransRecipientInfoBuilder");

    let mut builder = EnvelopedDataBuilder::new(
        None,
        "Arbitrary unencrypted content".as_bytes(),
        ContentEncryptionAlgorithm::Aes128Cbc,
        None,
    )
    .expect("Could not create an EnvelopedData builder.");
    let enveloped_data = builder
        .add_recipient_info(recipient_info_builder)
        .expect("Could not add a recipient info")
        .build()
        .expect("Building EnvelopedData failed");
    let enveloped_data_der = enveloped_data
        .to_der()
        .expect("conversion of enveloped data to DER failed.");
    println!(
        "{}",
        pem_rfc7468::encode_string("ENVELOPEDDATA", LineEnding::LF, &enveloped_data_der)
            .expect("PEM encoding of enveloped data DER failed")
    );
}

#[test]
fn build_pkcs7_scep_pkcsreq() {
    // This test demonstrates how to build a PKCS7 message for the SCEP PKCSReq pkiMessage
    // according to RFC 8894.
    // We use the key transport mechanism in this example, which means, we have the recipient
    // public (RSA) key.
    // Prerequisites are
    // - the recipients public RSA key,
    // - an RSA key pair of the sender and
    // - a CSR (PKCS #10) signed with the sender's key
    // A CMS `SignedData` message is roughly structured as follows:
    // ContentInfo
    //     SignedData
    //         version
    //         digestAlgorithms*
    //         encapContentInfo
    //             ContentInfo
    //                 EnvelopedData
    //                     version
    //                     [originatorInfo]
    //                     recipientInfos*
    //                         e.g. KeyTransRecipientInfo
    //                             version
    //                             rid
    //                             keyEncryptionAlgorithm
    //                             encryptedKey
    //                     encryptedContentInfo
    //                         contentType
    //                         contentEncryptionAlgorithm
    //                         [encryptedContent]
    //                     [unprotectedAttrs*]
    //         [certificates*]
    //         [crls*]
    //         signerInfos
    //             version
    //             sid
    //             digestAlgorithm
    //             [signedAttrs*]
    //             signatureAlgorithm
    //             signature
    //             [unsignedAttrs*]
    // Reduced to the nested structures:
    // ContentInfo
    //     SignedData
    //         encapContentInfo
    //             ContentInfo
    //                 EnvelopedData
    //                     encryptedContentInfo
    // 4 builders are involved in the procedure:
    // - `SignedDataBuilder`
    // - `SignerInfoBuilder`
    // - `EnvelopedDataBuilder`
    // - `RecipientInfoBuilder` (trait)
    //     - `KeyTransRecipientInfoBuilder` (implementation used here)
    // The procedure can be broken down to 4 steps:
    // - Wrap CSR in `EnvelopedData`.
    // - Add recipient information to `Enveloped data`.
    // - Wrap enveloped data in `SignedData`
    // - Sign with sender's RSA key.

    // Create recipient info
    let recipient_identifier = recipient_identifier(1);
    let recipient_private_key =
        rsa::RsaPrivateKey::from_pkcs1_der(RSA_2048_PRIV_DER_EXAMPLE).unwrap();
    let recipient_public_key = RsaPublicKey::from(&recipient_private_key);

    let recipient_info_builder = KeyTransRecipientInfoBuilder::new(
        recipient_identifier,
        KeyEncryptionInfo::Rsa(recipient_public_key),
    )
    .unwrap();

    // Build `EnvelopedData`
    let csr_der = include_bytes!("examples/sceptest_csr.der"); // The CSR to be signed
    let mut enveloped_data_builder = EnvelopedDataBuilder::new(
        None,
        csr_der,                               // data to be encrypted...
        ContentEncryptionAlgorithm::Aes128Cbc, // ... with this algorithm
        None,
    )
    .unwrap();

    // Add recipient info. Multiple recipients are possible, but not used here.
    let enveloped_data = enveloped_data_builder
        .add_recipient_info(recipient_info_builder)
        .unwrap()
        .build()
        .unwrap();

    let enveloped_data_der = enveloped_data.to_der().unwrap();
    let content = AnyRef::try_from(enveloped_data_der.as_slice()).unwrap();
    let content_info = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_ENVELOPED_DATA,
        content: Any::from(content),
    };

    // Encapsulate the `EnvelopedData`
    let content_info_der = content_info.to_der().unwrap();
    let content = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: Some(Any::new(Tag::OctetString, content_info_der).unwrap()),
    };

    // Create a signer info. Multiple signers are possible, but not used here.
    let signer = {
        let sender_rsa_key_pem = include_str!("examples/sceptest_key.pem");
        let sender_rsa_key = RsaPrivateKey::from_pkcs8_pem(sender_rsa_key_pem).unwrap();
        SigningKey::<Sha256>::new(sender_rsa_key)
    };
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };
    let mut signer_info_builder = SignerInfoBuilder::new(
        &signer,
        signer_identifier(1),
        digest_algorithm.clone(),
        &content,
        None,
    )
    .unwrap();

    // For a SCEP pkiMessage, we need to add signed the following attributes:
    // - messageType
    // - senderNonce
    // - transactionID
    let mut message_type_value: SetOfVec<AttributeValue> = Default::default();
    let pkcsreq = 19_i8; // Numerical value of PKCSReq messageType
                         // TODO bk: is the correct way to create an `Int` from an `i8`?
    let pkcsreq_bytes = pkcsreq.to_be_bytes();
    let pkcsreq_as_int = Int::new(&pkcsreq_bytes).unwrap();
    message_type_value
        .insert(Any::new(Tag::Integer, pkcsreq_as_int.as_bytes()).unwrap())
        .unwrap();
    let message_type = Attribute {
        oid: RFC8894_ID_MESSAGE_TYPE,
        values: message_type_value,
    };
    let mut sender_nonce_value: SetOfVec<AttributeValue> = Default::default();
    let nonce = OctetString::new(*&[42; 32]).unwrap();
    sender_nonce_value
        .insert(Any::new(Tag::OctetString, nonce.as_bytes()).unwrap())
        .unwrap();
    let sender_nonce = Attribute {
        oid: RFC8894_ID_SENDER_NONCE,
        values: sender_nonce_value,
    };
    let mut transaction_id_value: SetOfVec<AttributeValue> = Default::default();
    let id = PrintableString::try_from(String::from("Test Transaction ID")).unwrap();
    transaction_id_value.insert(Any::from(&id)).unwrap();
    let transaction_id = Attribute {
        oid: RFC8894_ID_TRANSACTION_ID,
        values: transaction_id_value,
    };

    signer_info_builder
        .add_signed_attribute(message_type)
        .unwrap();
    signer_info_builder
        .add_signed_attribute(sender_nonce)
        .unwrap();
    signer_info_builder
        .add_signed_attribute(transaction_id)
        .unwrap();

    let certificate_buf = include_bytes!("examples/sceptest_cert-selfsigned.pem");
    let certificate = x509_cert::Certificate::from_pem(certificate_buf).unwrap();

    let mut builder = SignedDataBuilder::new(&content);

    let signed_data_pkcs7 = builder
        .add_digest_algorithm(digest_algorithm)
        .unwrap()
        .add_certificate(CertificateChoices::Certificate(certificate))
        .unwrap()
        .add_signer_info::<SigningKey<Sha256>, rsa::pkcs1v15::Signature>(signer_info_builder)
        .unwrap()
        .build()
        .unwrap();
    let signed_data_pkcs7_der = signed_data_pkcs7.to_der().unwrap();
    println!(
        "{}",
        pem_rfc7468::encode_string("PKCS7", LineEnding::LF, &signed_data_pkcs7_der).unwrap()
    );

    // TODO bk
    // Check signature
    // Decode Message including decrypted enveloped content
    // Check CSR
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
