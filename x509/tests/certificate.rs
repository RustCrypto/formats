//! Certificate tests
use der::asn1::UIntBytes;
use der::{Decodable, Tag};
use x509::Certificate;

///   TBSCertificate  ::=  SEQUENCE  {
///       version         [0]  Version DEFAULT v1,
///       serialNumber         CertificateSerialNumber,
///       signature            AlgorithmIdentifier{SIGNATURE-ALGORITHM, {SignatureAlgorithms}},
///       issuer               Name,
///       validity             Validity,
///       subject              Name,
///       subjectPublicKeyInfo SubjectPublicKeyInfo,
///       ... ,
///       [[2:               -- If present, version MUST be v2
///       issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///       subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL
///       ]],
///       [[3:               -- If present, version MUST be v3 --
///       extensions      [3]  Extensions{{CertExtensions}} OPTIONAL
///       ]], ... }

/// Certificate  ::=  SEQUENCE  {
///      tbsCertificate       TBSCertificate,
///      signatureAlgorithm   AlgorithmIdentifier,
///      signature            BIT STRING  }

#[test]
fn decode_cert() {
    let der_encoded_cert = include_bytes!("examples/GoodCACert.crt");
    let result = Certificate::from_der(der_encoded_cert);
    let cert: Certificate = result.unwrap();

    assert_eq!(cert.tbs_certificate.version, 2);
    let target_serial: [u8; 1] = [2];
    assert_eq!(
        cert.tbs_certificate.serial_number,
        UIntBytes::new(&target_serial).unwrap()
    );
    assert_eq!(
        cert.tbs_certificate.signature.oid.to_string(),
        "1.2.840.113549.1.1.11"
    );
    assert_eq!(
        cert.tbs_certificate.signature.parameters.unwrap().tag(),
        Tag::Null
    );
    assert_eq!(
        cert.tbs_certificate.signature.parameters.unwrap().is_null(),
        true
    );

    let mut counter = 0;
    let i = cert.tbs_certificate.issuer.iter();
    for rdn in i {
        let i1 = rdn.iter();
        for atav in i1 {
            if 0 == counter {
                assert_eq!(atav.oid.to_string(), "2.5.4.6");
                assert_eq!(atav.value.printable_string().unwrap().to_string(), "US");
            } else if 1 == counter {
                assert_eq!(atav.oid.to_string(), "2.5.4.10");
                assert_eq!(
                    atav.value.printable_string().unwrap().to_string(),
                    "Test Certificates 2011"
                );
            } else if 2 == counter {
                assert_eq!(atav.oid.to_string(), "2.5.4.3");
                assert_eq!(
                    atav.value.printable_string().unwrap().to_string(),
                    "Trust Anchor"
                );
            }
            counter += 1;
        }
    }

    assert_eq!(
        cert.tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs(),
        1262334600
    );
    assert_eq!(
        cert.tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
        1924936200
    );

    counter = 0;
    let i = cert.tbs_certificate.subject.iter();
    for rdn in i {
        let i1 = rdn.iter();
        for atav in i1 {
            if 0 == counter {
                assert_eq!(atav.oid.to_string(), "2.5.4.6");
                assert_eq!(atav.value.printable_string().unwrap().to_string(), "US");
            } else if 1 == counter {
                assert_eq!(atav.oid.to_string(), "2.5.4.10");
                assert_eq!(
                    atav.value.printable_string().unwrap().to_string(),
                    "Test Certificates 2011"
                );
            } else if 2 == counter {
                assert_eq!(atav.oid.to_string(), "2.5.4.3");
                assert_eq!(
                    atav.value.printable_string().unwrap().to_string(),
                    "Good CA"
                );
            }
            counter += 1;
        }
    }

    assert_eq!(
        cert.tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            .to_string(),
        "1.2.840.113549.1.1.1"
    );
    assert_eq!(
        cert.tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters
            .unwrap()
            .tag(),
        Tag::Null
    );
    assert_eq!(
        cert.tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters
            .unwrap()
            .is_null(),
        true
    );

    // TODO - parse and compare public key

    counter = 0;
    let exts = cert.tbs_certificate.extensions.unwrap();
    let i = exts.iter();
    for ext in i {
        // TODO - parse and compare extension values
        if 0 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.35");
            assert_eq!(ext.critical, Option::None);
        } else if 1 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.14");
            assert_eq!(ext.critical, Option::None);
        } else if 2 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.15");
            assert_eq!(ext.critical, Option::Some(true));
        } else if 3 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.32");
            assert_eq!(ext.critical, Option::None);
        } else if 4 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.19");
            assert_eq!(ext.critical, Option::Some(true));
        }

        counter += 1;
    }
    assert_eq!(
        cert.signature_algorithm.oid.to_string(),
        "1.2.840.113549.1.1.11"
    );
    assert_eq!(
        cert.signature_algorithm.parameters.unwrap().tag(),
        Tag::Null
    );
    assert_eq!(cert.signature_algorithm.parameters.unwrap().is_null(), true);

    // TODO - parse and compare signature value
}
