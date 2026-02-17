use aes_kw::AesKw;
use cms::{
    builder::{
        ContentEncryptionAlgorithm, DhSinglePassStdDhKdf, EcKeyEncryptionInfo,
        EnvelopedDataBuilder, KeyAgreeRecipientInfoBuilder,
    },
    cert::IssuerAndSerialNumber,
    content_info::ContentInfo,
    enveloped_data::KeyAgreeRecipientIdentifier,
};
use der::{Any, AnyRef, Encode};
use p256::{SecretKey, pkcs8::DecodePrivateKey};
use pem_rfc7468::LineEnding;
use x509_cert::serial_number::SerialNumber;

fn key_agreement_recipient_identifier(id: i32) -> KeyAgreeRecipientIdentifier {
    let issuer = format!("CN=test client {id}").parse().unwrap();
    KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer,
        serial_number: SerialNumber::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
            .expect("failed to create a serial number"),
    })
}

/// Generate a CMS message encrypted with recipient public EC key
///
/// Can be decrypted using:
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
    let kari_builder = KeyAgreeRecipientInfoBuilder::<
        _,
        _,
        DhSinglePassStdDhKdf<sha2::Sha256>,
        AesKw<aes::Aes192>,
        aes::Aes128,
    >::new(
        None,
        key_agreement_recipient_identifier,
        EcKeyEncryptionInfo::Ec(recipient_public_key),
    )
    .expect("Could not create a KeyAgreeRecipientInfoBuilder");

    // Enveloped data builder
    let mut rng = rand::rng();
    let mut builder = EnvelopedDataBuilder::new(
        None,
        "Arbitrary unencrypted content, encrypted using ECC".as_bytes(),
        ContentEncryptionAlgorithm::Aes128Cbc,
        None,
    )
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
    let content = AnyRef::try_from(enveloped_data_der.as_slice()).unwrap();
    let content_info = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_ENVELOPED_DATA,
        content: Any::from(content),
    };
    let content_info_der = content_info.to_der().unwrap();

    println!(
        "{}",
        pem_rfc7468::encode_string("CMS", LineEnding::LF, &content_info_der)
            .expect("PEM encoding of enveloped data DER failed")
    );
}
