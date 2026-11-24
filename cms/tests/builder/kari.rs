use aes_kw::AesKw;
use cipher::KeyInit;
use cms::{
    builder::{
        AesCbcContentDecryptor, AesKeyWrap, ContentDecryptor, ContentEncryptionAlgorithm,
        DhSinglePassStdDhKdf, EcKeyEncryptionInfo, EccCmsSharedInfo, EcdhKeyAgreement,
        EnvelopedDataBuilder, KeyAgreeRecipientInfoBuilder,
    },
    cert::IssuerAndSerialNumber,
    content_info::ContentInfo,
    enveloped_data::{
        KeyAgreeRecipientIdentifier, OriginatorIdentifierOrKey, RecipientInfo, UserKeyingMaterial,
    },
};
use der::{
    Any, AnyRef, Encode,
    asn1::{ObjectIdentifier, OctetString},
};
use p256::{SecretKey, pkcs8::DecodePrivateKey};
use pem_rfc7468::LineEnding;
use spki::AlgorithmIdentifierOwned;
use x509_cert::serial_number::SerialNumber;

fn key_agreement_recipient_identifier(id: i32) -> KeyAgreeRecipientIdentifier {
    let issuer = format!("CN=test client {id}").parse().unwrap();
    KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer,
        serial_number: SerialNumber::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
            .expect("failed to create a serial number"),
    })
}

/// Generate a CMS message encrypted with recipient public EC key, and decrypt it as the recipient.
///
/// Can also be decrypted using:
/// ```bash
/// openssl cms -decrypt -inkey cms/tests/examples/p256-priv.der -inform PEM
/// ```
#[test]
fn test_build_enveloped_data_ec() {
    // Recipient identifier
    let key_agreement_recipient_identifier = key_agreement_recipient_identifier(1);

    // Recipient key material
    let recipient_private_key_der = include_bytes!("../examples/p256-priv.der");
    let recipient_private_key = SecretKey::from_pkcs8_der(recipient_private_key_der)
        .expect("could not parse in private key");
    let recipient_public_key = recipient_private_key.public_key();

    // KARI builder
    let ukm = UserKeyingMaterial::new(b"user keying material".to_vec()).unwrap();
    let kari_builder = KeyAgreeRecipientInfoBuilder::new(
        Some(ukm.clone()),
        key_agreement_recipient_identifier,
        EcdhKeyAgreement::new(
            EcKeyEncryptionInfo::Ec(recipient_public_key),
            DhSinglePassStdDhKdf::<sha2::Sha256>::new(),
        ),
        AesKeyWrap::<aes::Aes192>::new(),
    )
    .expect("Could not create a KeyAgreeRecipientInfoBuilder");

    // Enveloped data builder
    let mut rng = rand::rng();
    let content = "Arbitrary unencrypted content, encrypted using ECC".as_bytes();
    let mut builder =
        EnvelopedDataBuilder::new(None, content, ContentEncryptionAlgorithm::Aes128Cbc, None)
            .expect("Could not create an EnvelopedData builder.");

    // Enveloped data
    let enveloped_data = builder
        .add_recipient_info(kari_builder)
        .expect("Could not add a recipient info")
        .build_with_rng(&mut rng)
        .expect("Building EnvelopedData failed");
    let enveloped_data_der = enveloped_data
        .to_der()
        .expect("conversion of enveloped data to DER failed.");

    // Content info
    let content_info = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_ENVELOPED_DATA,
        content: Any::from(AnyRef::try_from(enveloped_data_der.as_slice()).unwrap()),
    };
    println!(
        "{}",
        pem_rfc7468::encode_string("CMS", LineEnding::LF, &content_info.to_der().unwrap())
            .expect("PEM encoding of enveloped data DER failed")
    );

    // Decrypt as the recipient: ECDH with the originator's ephemeral key, ANSI X9.63 KDF over
    // the EccCmsSharedInfo, AES key unwrap, then content decryption.
    let Some(RecipientInfo::Kari(kari)) = enveloped_data.recip_infos.0.get(0) else {
        panic!("expected one KeyAgreeRecipientInfo");
    };
    assert_eq!(
        kari.key_enc_alg.oid,
        const_oid::db::rfc5753::DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME
    );
    let OriginatorIdentifierOrKey::OriginatorKey(originator_key) = &kari.originator else {
        panic!("expected an originator public key");
    };
    let ephemeral_public_key =
        p256::PublicKey::from_sec1_bytes(originator_key.public_key.raw_bytes()).unwrap();
    let shared_secret = elliptic_curve::ecdh::diffie_hellman(
        recipient_private_key.to_nonzero_scalar(),
        ephemeral_public_key.as_affine(),
    );
    let shared_info = EccCmsSharedInfo {
        key_info: AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.25"), // id-aes192-wrap
            parameters: None,
        },
        entity_u_info: Some(ukm),
        supp_pub_info: OctetString::new(192u32.to_be_bytes()).unwrap(),
    };
    let mut kek = [0u8; 24];
    ansi_x963_kdf::derive_key_into::<sha2::Sha256>(
        shared_secret.raw_secret_bytes(),
        &shared_info.to_der().unwrap(),
        &mut kek,
    )
    .unwrap();

    let wrapped_key = kari.recipient_enc_keys[0].enc_key.as_bytes();
    let mut content_encryption_key = [0u8; 16];
    // The key-encryption key is the derived one, not all zeros.
    assert!(
        AesKw::<aes::Aes192>::new(&[0u8; 24].into())
            .unwrap_key(wrapped_key, &mut content_encryption_key)
            .is_err()
    );
    AesKw::<aes::Aes192>::new(&kek.into())
        .unwrap_key(wrapped_key, &mut content_encryption_key)
        .expect("the content-encryption key unwraps with the derived key-encryption key");

    let encrypted_content = &enveloped_data.encrypted_content;
    let decrypted = AesCbcContentDecryptor
        .decrypt_content(
            &encrypted_content.content_enc_alg,
            &content_encryption_key,
            encrypted_content
                .encrypted_content
                .as_ref()
                .unwrap()
                .as_bytes(),
            None,
            None,
        )
        .unwrap();
    assert_eq!(decrypted.as_slice(), content);
}
