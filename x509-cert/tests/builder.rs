#![cfg(all(feature = "builder", feature = "pem"))]

use der::{pem::LineEnding, referenced::RefToOwned, Decode, Encode, EncodePem};
use rsa::pkcs1::DecodeRsaPrivateKey;
use spki::SubjectPublicKeyInfoOwned;
use std::{str::FromStr, time::Duration};
use x509_cert::{
    builder::{CertificateBuilder, CertificateVersion, Profile, Signer, UniqueIds},
    certificate::TbsCertificate,
    constants,
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};
use x509_cert_test_support::{openssl, zlint};

const RSA_2048_DER_EXAMPLE: &[u8] = include_bytes!("examples/rsa2048-pub.der");

#[test]
fn root_ca_certificate() {
    let uids = UniqueIds {
        issuer_unique_id: None,
        subject_unique_id: None,
    };

    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let profile = Profile::Root;
    let subject = Name::from_str("CN=World domination corporation,O=World domination Inc,C=US")
        .unwrap()
        .to_der()
        .unwrap();
    let subject = Name::from_der(&subject).unwrap();
    let pub_key =
        SubjectPublicKeyInfoOwned::try_from(RSA_2048_DER_EXAMPLE).expect("get rsa pub key");

    let mut signer = RsaCertSigner;
    let mut builder = CertificateBuilder::new(
        profile,
        CertificateVersion::V3(uids),
        serial_number,
        validity,
        subject,
        pub_key,
        &mut signer,
    )
    .expect("Create certificate");

    let certificate = builder.build().unwrap().unwrap();

    let pem = certificate.to_pem(LineEnding::LF).expect("generate pem");
    println!("{}", openssl::check_certificate(pem.as_bytes()));

    let ignored = &[];
    zlint::check_certificate(pem.as_bytes(), ignored);
}

#[test]
fn sub_ca_certificate() {
    let uids = UniqueIds {
        issuer_unique_id: None,
        subject_unique_id: None,
    };

    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();

    let issuer = Name::from_str("CN=World domination corporation,O=World domination Inc,C=US")
        .unwrap()
        .to_der()
        .unwrap();
    let issuer = Name::from_der(&issuer).unwrap();
    let profile = Profile::SubCA {
        issuer,
        path_len_constraint: Some(0),
    };

    let subject = Name::from_str("CN=World domination task force,O=World domination Inc,C=US")
        .unwrap()
        .to_der()
        .unwrap();
    let subject = Name::from_der(&subject).unwrap();
    let pub_key =
        SubjectPublicKeyInfoOwned::try_from(RSA_2048_DER_EXAMPLE).expect("get rsa pub key");

    let mut signer = RsaCertSigner;
    let mut builder = CertificateBuilder::new(
        profile,
        CertificateVersion::V3(uids),
        serial_number,
        validity,
        subject,
        pub_key,
        &mut signer,
    )
    .expect("Create certificate");

    let certificate = builder.build().unwrap().unwrap();

    let pem = certificate.to_pem(LineEnding::LF).expect("generate pem");
    println!("{}", openssl::check_certificate(pem.as_bytes()));

    // TODO(baloo): not too sure we should tackle those in this API.
    let ignored = &[
        "w_sub_ca_aia_missing",
        "e_sub_ca_crl_distribution_points_missing",
        "e_sub_ca_certificate_policies_missing",
        "w_sub_ca_aia_does_not_contain_issuing_ca_url",
    ];

    zlint::check_certificate(pem.as_bytes(), ignored);
}

const RSA_2048_PRIV_DER_EXAMPLE: &[u8] = include_bytes!("examples/rsa2048-priv.der");

struct RsaCertSigner;

impl Signer for RsaCertSigner {
    type Err = ();

    fn signature_algorithm(&self) -> constants::CertificateSignatureAlgorithmOwned {
        constants::SHA_256_WITH_RSA_ENCRYPTION.ref_to_owned()
    }

    fn public_key(&self) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned::try_from(RSA_2048_DER_EXAMPLE).expect("get rsa pub key")
    }

    fn sign(&mut self, input: &TbsCertificate) -> Result<Vec<u8>, Self::Err> {
        use rsa::{
            pkcs1v15::SigningKey,
            signature::{RandomizedSigner, SignatureEncoding},
        };
        use sha2::Sha256;

        let private_key = rsa::RsaPrivateKey::from_pkcs1_der(RSA_2048_PRIV_DER_EXAMPLE).unwrap();
        let signing_key = SigningKey::<Sha256>::new_with_prefix(private_key);

        let mut rng = rand::thread_rng();
        let data: Vec<u8> = input.to_der().unwrap();
        let signature = signing_key.sign_with_rng(&mut rng, &data);

        Ok(signature.to_vec())
    }
}
