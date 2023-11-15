#![cfg(feature = "builder")]

use aes::Aes128;
use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, KeyIvInit};
use cms::builder::{
    create_signing_time_attribute, ContentEncryptionAlgorithm, EnvelopedDataBuilder,
    KeyEncryptionInfo, KeyTransRecipientInfoBuilder, SignedDataBuilder, SignerInfoBuilder,
};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::ContentInfo;
use cms::enveloped_data::RecipientInfo::Ktri;
use cms::enveloped_data::{EnvelopedData, RecipientIdentifier, RecipientInfo};
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier};
use const_oid::ObjectIdentifier;
use der::asn1::{OctetString, PrintableString, SetOfVec, Utf8StringRef};
use der::{Any, AnyRef, Decode, DecodePem, Encode, Tag, Tagged};
use p256::{pkcs8::DecodePrivateKey, NistP256};
use pem_rfc7468::LineEnding;
use rand::rngs::OsRng;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use signature::Verifier;
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::{Attribute, AttributeTypeAndValue, AttributeValue};
use x509_cert::name::{RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;

// TODO bk replace this by const_oid definitions as soon as released
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
    SigningKey::<Sha256>::new(private_key)
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
    let mut rng = OsRng;
    let bits = 2048;
    let recipient_private_key =
        RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let recipient_public_key = RsaPublicKey::from(&recipient_private_key);

    let recipient_info_builder = KeyTransRecipientInfoBuilder::new(
        recipient_identifier,
        KeyEncryptionInfo::Rsa(recipient_public_key),
        &mut rng,
    )
    .expect("Could not create a KeyTransRecipientInfoBuilder");

    let mut rng = OsRng;
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
        .build_with_rng(&mut rng)
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
fn test_build_pkcs7_scep_pkcsreq() {
    // This test demonstrates how to build a PKCS7 message for the SCEP PKCSReq pkiMessage
    // according to RFC 8894.
    // We use the key transport mechanism in this example, which means, we have the recipient
    // public (RSA) key.
    // Prerequisites are
    // - the recipients public RSA key,
    // - an RSA key pair of the sender and
    // - a CSR (PKCS #10) signed with the sender's key
    //
    // A CMS `SignedData` message is roughly structured as follows:
    // cms_message: ContentInfo ::= SEQUENCE
    //     contentType: ContentType = id-signed-data
    //     content: ANY == SignedData
    //         version: CMSVersion
    //         digestAlgorithms*: DigestAlgorithmIdentifiers
    //         encapContentInfo: EncapsulatedContentInfo ::= SEQUENCE
    //             eContentType: ContentType = id-data
    //             eContent: OCTET STRING
    //                 value_of_econtent_without_tag_and_length_bytes: ContentInfo
    //                     contentType: ContentType = id-enveloped-data
    //                     content: ANY == EnvelopeData ::= SEQUENCE
    //                         version: CMSVersion
    //                         [originatorInfo]: OriginatorInfo
    //                         recipientInfos: RecipientInfos ::= SET OF RecipientInfo
    //                             e.g. KeyTransRecipientInfo ::= SEQUENCE
    //                                 version: CMSVersion
    //                                 rid: RecipientIdentifier
    //                                 keyEncryptionAlgorithm: KeyEncryptionAlgorithmIdentifier
    //                                 encryptedKey: EncryptedKey
    //                         encryptedContentInfo: EncryptedContentInfo ::= SEQUENCE
    //                             contentType: ContentType
    //                             contentEncryptionAlgorithm: ContentEncryptionAlgorithmIdentifier
    //                             [encryptedContent]: EncryptedContent == OCTET STRING
    //                         [unprotectedAttrs*]
    //         [certificates*]
    //         [crls*]
    //         signerInfos*: SET OF SignerInfo
    //             version: CMSVersion
    //             sid: SignerIdentifier
    //             digestAlgorithm: DigestAlgorithmIdentifier
    //             [signedAttrs*]: SignedAttributes
    //             signatureAlgorithm: SignatureAlgorithmIdentifier
    //             signature: SignatureValue
    //             [unsignedAttrs*]: UnsignedAttributes
    //
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

    // Generate a random number generator
    let mut rng = rand::thread_rng();

    // Create recipient info
    let recipient_identifier = recipient_identifier(42);
    let recipient_private_key =
        rsa::RsaPrivateKey::from_pkcs1_der(RSA_2048_PRIV_DER_EXAMPLE).unwrap();
    let recipient_public_key = RsaPublicKey::from(&recipient_private_key);

    //----------------------------------------------------------------------------------------------
    // Create enveloped data
    let recipient_info_builder = KeyTransRecipientInfoBuilder::new(
        recipient_identifier.clone(),
        KeyEncryptionInfo::Rsa(recipient_public_key),
        &mut rng,
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

    let mut rng = rand::thread_rng();

    // Add recipient info. Multiple recipients are possible, but not used here.
    let enveloped_data = enveloped_data_builder
        .add_recipient_info(recipient_info_builder)
        .unwrap()
        .build_with_rng(&mut rng)
        .unwrap();

    let enveloped_data_der = enveloped_data.to_der().unwrap();
    let content = AnyRef::try_from(enveloped_data_der.as_slice()).unwrap();
    let content_info = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_ENVELOPED_DATA,
        content: Any::from(content),
    };

    //----------------------------------------------------------------------------------------------
    // Create signed data

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
    let message_type = PrintableString::try_from("19".to_string()).unwrap();
    message_type_value.insert(Any::from(&message_type)).unwrap();
    let message_type = Attribute {
        oid: RFC8894_ID_MESSAGE_TYPE,
        values: message_type_value,
    };
    let mut sender_nonce_value: SetOfVec<AttributeValue> = Default::default();
    let nonce = OctetString::new([42; 32]).unwrap();
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

    //----------------------------------------------------------------------------------------------
    // Verify

    // Decode Message including decrypted enveloped content
    // Check signature
    // Decrypt content-encryption key
    // Decrypt content
    let ci = ContentInfo::from_der(signed_data_pkcs7_der.as_slice()).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_SIGNED_DATA);

    // Decode CMS message (by converting `Any` to `SignedData`)
    let signed_data_der = ci.content.to_der().unwrap();
    let signed_data = SignedData::from_der(signed_data_der.as_slice()).unwrap();

    // Check signatures (only one in this test)
    for signer_info in signed_data.signer_infos.0.iter() {
        let signature =
            rsa::pkcs1v15::Signature::try_from(signer_info.signature.as_bytes()).unwrap();
        let signed_attributes_der = signer_info.signed_attrs.clone().unwrap().to_der().unwrap();
        let verifier = {
            let verifier_rsa_key_pem = include_str!("examples/sceptest_key.pem");
            let verifier_rsa_key = RsaPrivateKey::from_pkcs8_pem(verifier_rsa_key_pem).unwrap();
            VerifyingKey::<Sha256>::new(RsaPublicKey::from(verifier_rsa_key))
        };
        assert!(verifier
            .verify(signed_attributes_der.as_slice(), &signature)
            .is_ok());
    }

    // Decode contained enveloped data
    let encap_content_info = signed_data.encap_content_info;
    assert_eq!(
        encap_content_info.econtent_type,
        const_oid::db::rfc5911::ID_DATA
    );
    let econtent = encap_content_info
        .econtent
        .expect("this cms must contain content");
    // let octet_string = OctetString::from_der(econtent.value()).unwrap();
    // let ci = ContentInfo::from_der(octet_string.as_bytes()).unwrap();
    let ci = ContentInfo::from_der(econtent.value()).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_ENVELOPED_DATA);
    let enveloped_data_der = ci.content.to_der().unwrap();
    let enveloped_data = EnvelopedData::from_der(enveloped_data_der.as_slice()).unwrap();
    let my_recipient_info: &RecipientInfo = enveloped_data
        .recip_infos
        .0
        .iter()
        .find(|&recipient_info| match recipient_info {
            Ktri(ri) => ri.rid == recipient_identifier,
            _ => false,
        })
        .unwrap();
    let key_trans_recipient_info = if let Ktri(recipient_info) = my_recipient_info {
        recipient_info // this must succeed
    } else {
        panic!();
    };
    let encrypted_key = &key_trans_recipient_info.enc_key;

    // Decrypt the content-encryption key
    let content_encryption_key = recipient_private_key
        .decrypt(Pkcs1v15Encrypt, encrypted_key.as_bytes())
        .unwrap();

    // Decrypt the CSR
    let encryption_info = enveloped_data.encrypted_content;
    assert_eq!(
        encryption_info.content_enc_alg.oid,
        const_oid::db::rfc5911::ID_AES_128_CBC
    );
    let iv_octet_string = OctetString::from_der(
        encryption_info
            .content_enc_alg
            .parameters
            .unwrap()
            .to_der()
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let iv = iv_octet_string.as_bytes();
    let encrypted_content_octet_string = encryption_info.encrypted_content.unwrap();
    let encrypted_content = encrypted_content_octet_string.as_bytes();
    let csr_der_decrypted =
        cbc::Decryptor::<Aes128>::new(content_encryption_key.as_slice().into(), iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(encrypted_content)
            .unwrap();
    assert_eq!(csr_der_decrypted.as_slice(), csr_der)
}

#[test]
fn test_degenerate_certificates_only_cms() {
    let cert_buf = include_bytes!("examples/ValidCertificatePathTest1EE.pem");
    let cert = x509_cert::Certificate::from_pem(cert_buf).unwrap();
    let certs = vec![cert];

    let encapsulated_content_info = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: None,
    };
    let mut signed_data_builder = SignedDataBuilder::new(&encapsulated_content_info);

    for cert in certs {
        signed_data_builder
            .add_certificate(CertificateChoices::Certificate(cert.clone()))
            .unwrap();
    }

    let degenerate_certificates_only_cms = signed_data_builder.build().unwrap();

    // Extract certificates from `degenerate_certificates_only_cms`
    let signed_data = SignedData::from_der(
        degenerate_certificates_only_cms
            .content
            .to_der()
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let certs = signed_data.certificates.unwrap();
    let CertificateChoices::Certificate(extracted_cert) = certs.0.get(0).unwrap() else {
        panic!("Invalid certificate choice encountered");
    };

    let original_cert = x509_cert::Certificate::from_pem(cert_buf).unwrap();
    assert_eq!(original_cert.signature, extracted_cert.signature)
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
