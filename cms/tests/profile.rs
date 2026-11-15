//! Certificate profiles apply to CMS certificates and issuer/serial identifiers.

use cms::{
    attr::Countersignature,
    authenticated_data::AuthenticatedData,
    authenveloped_data::AuthEnvelopedData,
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::{CmsVersion, ContentInfo},
    enveloped_data::{
        EncryptedContentInfo, EnvelopedData, KeyAgreeRecipientIdentifier, KeyAgreeRecipientInfo,
        KeyTransRecipientInfo, OriginatorIdentifierOrKey, OriginatorInfo, RecipientEncryptedKey,
        RecipientIdentifier, RecipientInfo, RecipientInfos,
    },
    kemri::KemRecipientInfo,
    signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo},
};
use const_oid::db::rfc5911;
use core::fmt::Debug;
use der::{
    Decode, Encode, ErrorKind, Tag,
    asn1::{OctetString, Uint},
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{Certificate, certificate::Raw, serial_number::SerialNumber};

const SSCEP_PKCSREQ: &[u8] = include_bytes!("examples/sscep_pkcsreq.der");
const SSCEP_SERIAL: &[u8] = b"902D285FA28C818DA746C386D2C9387\0";

fn sscep_signed_data() -> SignedData<Raw> {
    ContentInfo::from_der(SSCEP_PKCSREQ)
        .unwrap()
        .content
        .decode_as()
        .unwrap()
}

fn assert_raw_roundtrip<Strict, RawValue>(value: &RawValue)
where
    Strict: for<'a> Decode<'a, Error = der::Error> + Debug,
    RawValue: for<'a> Decode<'a, Error = der::Error> + Encode,
{
    let bytes = value.to_der().unwrap();
    assert_eq!(
        Strict::from_der(&bytes).unwrap_err().kind(),
        ErrorKind::Value { tag: Tag::Integer }
    );
    assert_eq!(RawValue::from_der(&bytes).unwrap().to_der().unwrap(), bytes);
}

#[test]
fn sscep_requires_explicit_profile() {
    let content = ContentInfo::from_der(SSCEP_PKCSREQ).unwrap();
    assert!(content.content.decode_as::<SignedData>().is_err());

    let signed = sscep_signed_data();
    assert_eq!(signed.to_der().unwrap(), content.content.to_der().unwrap());
    assert_eq!(signed.signer_infos.0.len(), 1);
    let signer = signed.signer_infos.0.get(0).unwrap();
    let SignerIdentifier::IssuerAndSerialNumber(identifier) = &signer.sid else {
        panic!("expected issuer and serial number");
    };
    assert_eq!(identifier.serial_number.as_bytes(), SSCEP_SERIAL);
    assert_raw_roundtrip::<SignerInfo, _>(signer);
    assert_raw_roundtrip::<Countersignature, Countersignature<Raw>>(signer);

    let certificates = signed.certificates.as_ref().unwrap();
    assert_eq!(certificates.0.len(), 1);
    let CertificateChoices::Certificate(certificate) = certificates.0.get(0).unwrap() else {
        panic!("expected X.509 certificate");
    };
    assert_eq!(
        certificate.tbs_certificate().serial_number().as_bytes(),
        SSCEP_SERIAL
    );
    assert_eq!(SignerIdentifier::from(certificate), signer.sid);
    assert_raw_roundtrip::<Certificate, _>(certificate);
}

#[test]
fn certificates_only_preserves_profile() {
    let signed = sscep_signed_data();
    let certificates = signed.certificates.unwrap();
    let CertificateChoices::Certificate(certificate) = certificates.0.get(0).unwrap() else {
        panic!("expected X.509 certificate");
    };

    for content in [
        ContentInfo::try_from(certificate.clone()).unwrap(),
        ContentInfo::try_from(vec![certificate.clone()]).unwrap(),
    ] {
        let decoded = content.content.decode_as::<SignedData<Raw>>().unwrap();
        assert!(decoded.signer_infos.0.is_empty());
        assert_eq!(decoded.certificates.as_ref().unwrap(), &certificates);
        assert_raw_roundtrip::<SignedData, _>(&decoded);
    }

    #[cfg(feature = "builder")]
    {
        let content = EncapsulatedContentInfo {
            econtent_type: rfc5911::ID_DATA,
            econtent: None,
        };
        let built = cms::builder::SignedDataBuilder::new(&content)
            .add_certificate(CertificateChoices::Certificate(certificate.clone()))
            .unwrap()
            .build()
            .unwrap();
        let decoded = built.content.decode_as::<SignedData<Raw>>().unwrap();
        assert!(decoded.signer_infos.0.is_empty());
        assert_eq!(decoded.certificates.as_ref().unwrap(), &certificates);
        assert_raw_roundtrip::<SignedData, _>(&decoded);
    }
}

#[test]
fn identifier_serial_boundaries() {
    for (length, accepted_by_default) in [(21, true), (22, false), (32, false)] {
        let serial = Uint::new(&vec![0x11; length]).unwrap().to_der().unwrap();
        let identifier = IssuerAndSerialNumber::<Raw> {
            issuer: Default::default(),
            serial_number: SerialNumber::from_der(&serial).unwrap(),
        };
        let bytes = identifier.to_der().unwrap();

        assert_eq!(
            <IssuerAndSerialNumber>::from_der(&bytes).is_ok(),
            accepted_by_default
        );
        assert_eq!(
            <SignerIdentifier>::from_der(&bytes).is_ok(),
            accepted_by_default
        );
        assert_eq!(
            <RecipientIdentifier>::from_der(&bytes).is_ok(),
            accepted_by_default
        );
        assert_eq!(
            <OriginatorIdentifierOrKey>::from_der(&bytes).is_ok(),
            accepted_by_default
        );
        assert_eq!(
            <KeyAgreeRecipientIdentifier>::from_der(&bytes).is_ok(),
            accepted_by_default
        );

        assert_eq!(
            IssuerAndSerialNumber::<Raw>::from_der(&bytes).unwrap(),
            identifier
        );
        assert_eq!(
            SignerIdentifier::<Raw>::from_der(&bytes)
                .unwrap()
                .to_der()
                .unwrap(),
            bytes
        );
        assert_eq!(
            RecipientIdentifier::<Raw>::from_der(&bytes)
                .unwrap()
                .to_der()
                .unwrap(),
            bytes
        );
        assert_eq!(
            OriginatorIdentifierOrKey::<Raw>::from_der(&bytes)
                .unwrap()
                .to_der()
                .unwrap(),
            bytes
        );
        assert_eq!(
            KeyAgreeRecipientIdentifier::<Raw>::from_der(&bytes)
                .unwrap()
                .to_der()
                .unwrap(),
            bytes
        );
    }

    // The raw profile does not disable ASN.1 INTEGER canonicality or length checks.
    for bytes in [
        [0x30, 0x06, 0x30, 0x00, 0x02, 0x02, 0x00, 0x01].as_slice(),
        &[0x30, 0x04, 0x30, 0x00, 0x02, 0x00],
        &[0x30, 0x05, 0x30, 0x00, 0x02, 0x01],
    ] {
        assert!(IssuerAndSerialNumber::<Raw>::from_der(bytes).is_err());
    }
}

#[test]
fn recipient_containers_propagate_profile() {
    let signed = sscep_signed_data();
    let SignerIdentifier::IssuerAndSerialNumber(identifier) =
        &signed.signer_infos.0.get(0).unwrap().sid
    else {
        panic!("expected issuer and serial number");
    };
    let algorithm = AlgorithmIdentifierOwned {
        oid: rfc5911::ID_AES_128_CBC,
        parameters: None,
    };
    let encrypted_key = OctetString::new([0x01, 0x23, 0x45]).unwrap();
    let recipient = KeyTransRecipientInfo {
        version: CmsVersion::V0,
        rid: RecipientIdentifier::IssuerAndSerialNumber(identifier.clone()),
        key_enc_alg: algorithm.clone(),
        enc_key: encrypted_key.clone(),
    };
    let agreement = KeyAgreeRecipientInfo {
        version: CmsVersion::V3,
        originator: OriginatorIdentifierOrKey::IssuerAndSerialNumber(identifier.clone()),
        ukm: None,
        key_enc_alg: algorithm.clone(),
        recipient_enc_keys: vec![RecipientEncryptedKey {
            rid: KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(identifier.clone()),
            enc_key: encrypted_key.clone(),
        }],
    };
    assert_raw_roundtrip::<KeyTransRecipientInfo, _>(&recipient);
    assert_raw_roundtrip::<KeyAgreeRecipientInfo, _>(&agreement);

    for recipient_info in [
        RecipientInfo::Ktri(recipient),
        RecipientInfo::Kari(agreement),
    ] {
        let recipients = RecipientInfos::try_from(vec![recipient_info]).unwrap();
        let encrypted_content = EncryptedContentInfo {
            content_type: rfc5911::ID_DATA,
            content_enc_alg: algorithm.clone(),
            encrypted_content: Some(OctetString::new([0x67, 0x89]).unwrap()),
        };
        let envelope = EnvelopedData {
            version: CmsVersion::V2,
            originator_info: None,
            recip_infos: recipients.clone(),
            encrypted_content: encrypted_content.clone(),
            unprotected_attrs: None,
        };
        assert_raw_roundtrip::<EnvelopedData, _>(&envelope);
        assert_raw_roundtrip::<AuthenticatedData, _>(&AuthenticatedData {
            version: CmsVersion::V0,
            originator_info: None,
            recip_infos: recipients.clone(),
            mac_alg: algorithm.clone(),
            digest_alg: None,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: rfc5911::ID_DATA,
                econtent: None,
            },
            auth_attrs: None,
            mac: OctetString::new([0xab]).unwrap(),
            unauth_attrs: None,
        });
        assert_raw_roundtrip::<AuthEnvelopedData, _>(&AuthEnvelopedData {
            version: CmsVersion::V0,
            originator_info: None,
            recip_infos: recipients,
            auth_encrypted_content_info: encrypted_content,
            auth_attrs: None,
            mac: OctetString::new([0xab]).unwrap(),
            unauth_attrs: None,
        });
    }

    assert_raw_roundtrip::<OriginatorInfo, _>(&OriginatorInfo {
        certs: signed.certificates,
        crls: None,
    });
    assert_raw_roundtrip::<KemRecipientInfo, _>(&KemRecipientInfo {
        version: CmsVersion::V0,
        rid: RecipientIdentifier::IssuerAndSerialNumber(identifier.clone()),
        kem: algorithm.clone(),
        kem_ct: encrypted_key.clone(),
        kdf: algorithm.clone(),
        kek_length: 16,
        ukm: None,
        wrap: algorithm,
        encrypted_key,
    });
}

#[test]
#[cfg(feature = "builder")]
fn signed_data_builder_preserves_profile() {
    use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
    use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs1v15};
    use signature::{Keypair, Verifier};

    let sid = sscep_signed_data()
        .signer_infos
        .0
        .get(0)
        .unwrap()
        .sid
        .clone();
    let content = EncapsulatedContentInfo {
        econtent_type: rfc5911::ID_DATA,
        econtent: Some(
            der::Any::encode_from(&OctetString::new(*b"profile test").unwrap()).unwrap(),
        ),
    };
    let digest = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };
    let key = rsa::PrivateKey::from_pkcs1_der(include_bytes!("examples/rsa2048-priv.der")).unwrap();
    let signer = pkcs1v15::SigningKey::<sha2::Sha256>::new(key);
    let signer_builder =
        SignerInfoBuilder::new(sid.clone(), digest.clone(), &content, None).unwrap();
    let built = SignedDataBuilder::new(&content)
        .add_digest_algorithm(digest)
        .unwrap()
        .add_signer_info_cb::<_, pkcs1v15::Signature, _>(signer_builder, &signer, |info| {
            assert_eq!(info.sid, sid);
            Ok(())
        })
        .unwrap()
        .build()
        .unwrap();

    let signed = built.content.decode_as::<SignedData<Raw>>().unwrap();
    assert_raw_roundtrip::<SignedData, _>(&signed);
    assert_eq!(signed.encap_content_info, content);
    assert_eq!(signed.signer_infos.0.len(), 1);
    let info = signed.signer_infos.0.get(0).unwrap();
    assert_eq!(info.sid, sid);
    signer
        .verifying_key()
        .verify(
            &info.signed_attrs.as_ref().unwrap().to_der().unwrap(),
            &pkcs1v15::Signature::try_from(info.signature.as_bytes()).unwrap(),
        )
        .unwrap();
}

#[test]
#[cfg(feature = "builder")]
fn enveloped_data_builder_preserves_profile() {
    use cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
    use cms::builder::{
        ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyEncryptionInfo,
        KeyTransRecipientInfoBuilder,
    };
    use rsa::{Pkcs1v15Encrypt, pkcs1::DecodeRsaPrivateKey};

    let signed = sscep_signed_data();
    let SignerIdentifier::IssuerAndSerialNumber(identifier) =
        &signed.signer_infos.0.get(0).unwrap().sid
    else {
        panic!("expected issuer and serial number");
    };
    let rid = RecipientIdentifier::IssuerAndSerialNumber(identifier.clone());
    let key = rsa::PrivateKey::from_pkcs1_der(include_bytes!("examples/rsa2048-priv.der")).unwrap();
    let recipient = KeyTransRecipientInfoBuilder::new(
        rid.clone(),
        KeyEncryptionInfo::Rsa(rsa::PublicKey::from(&key)),
    )
    .unwrap();
    let content = b"raw serial envelope";
    let envelope = EnvelopedDataBuilder::new(
        Some(OriginatorInfo {
            certs: signed.certificates,
            crls: None,
        }),
        content,
        ContentEncryptionAlgorithm::Aes128Cbc,
        None,
    )
    .unwrap()
    .add_recipient_info(recipient)
    .unwrap()
    .build_with_rng(&mut rand::rng())
    .unwrap();
    assert_raw_roundtrip::<EnvelopedData, _>(&envelope);
    let decoded = EnvelopedData::<Raw>::from_der(&envelope.to_der().unwrap()).unwrap();
    let RecipientInfo::Ktri(recipient) = decoded.recip_infos.0.get(0).unwrap() else {
        panic!("expected key transport recipient");
    };
    assert_eq!(recipient.rid, rid);
    let cek = key
        .decrypt(Pkcs1v15Encrypt, recipient.enc_key.as_bytes())
        .unwrap();
    let encrypted = decoded.encrypted_content;
    let iv = encrypted
        .content_enc_alg
        .parameters
        .unwrap()
        .decode_as::<OctetString>()
        .unwrap();
    let plaintext = cbc::Decryptor::<aes::Aes128>::new_from_slices(&cek, iv.as_bytes())
        .unwrap()
        .decrypt_padded_vec::<Pkcs7>(encrypted.encrypted_content.unwrap().as_bytes())
        .unwrap();
    assert_eq!(plaintext, content);
}
