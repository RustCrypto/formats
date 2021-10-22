//! Certificate tests
use der::asn1::UIntBytes;
use der::{Decodable, Tag};
use hex_literal::hex;
use x509::{
    BasicConstraints, Certificate, CertificatePolicies, DeferCertificate, KeyUsage,
    SubjectKeyIdentifier,
};

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
    let result2 = DeferCertificate::from_der(der_encoded_cert);
    let cert2 = result2.unwrap();
    assert_eq!(
        cert2.tbs_certificate,
        &hex!("30820264A003020102020102300D06092A864886F70D01010B05003045310B3009060355040613025553311F301D060355040A131654657374204365727469666963617465732032303131311530130603550403130C547275737420416E63686F72301E170D3130303130313038333030305A170D3330313233313038333030305A3040310B3009060355040613025553311F301D060355040A1316546573742043657274696669636174657320323031313110300E06035504031307476F6F6420434130820122300D06092A864886F70D01010105000382010F003082010A028201010090589A47628DFB5DF6FBA0948F7BE5AF7D3973206DB5590ECCC8C6C6B4AFE6F267A30B347A73E7FFA498441FF39C0D232C5EAF21E645DA046A962BEBD2C03FCFCE9E4E606A6D5E618F72D843B40C25ADA7E418E4B81AA209F3E93D5C62ACFAF4145C92AC3A4E3B46ECC3E8F66EA6AE2CD7AC5A2D5A986D40B6E94718D3C1A99E82CD1C9652FC4997C35659DDDE18663365A48A5614D1E750699D88629750F5FFF47D1F563200690C239C601BA60C82BA65A0CC8C0FA57F84945394AF7CFB06856714A8485F37BE566406496C59C6F58350DF74525D2D2C4A4B824DCE571501E15506B9FD793893A9828D7189B20D3E65ADD7855D6B637DCAB34A96824664DA8B0203010001A37C307A301F0603551D23041830168014E47D5FD15C9586082C05AEBE75B665A7D95DA866301D0603551D0E04160414580184241BBC2B52944A3DA510721451F5AF3AC9300E0603551D0F0101FF04040302010630170603551D200410300E300C060A60864801650302013001300F0603551D130101FF040530030101FF")[..]
    );

    let result = Certificate::from_der(der_encoded_cert);
    let cert: Certificate = result.unwrap();

    assert_eq!(cert.tbs_certificate.version, Some(2));
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
            //let akid = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes()).unwrap();
            //assert_eq!(akid.keyIdentifier.unwrap().as_bytes(), &hex!("580184241BBC2B52944A3DA510721451F5AF3AC9")[..]);
        } else if 1 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.14");
            assert_eq!(ext.critical, Option::None);
            let skid = SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()).unwrap();
            assert_eq!(
                skid.as_bytes(),
                &hex!("580184241BBC2B52944A3DA510721451F5AF3AC9")[..]
            );
        } else if 2 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.15");
            assert_eq!(ext.critical, Option::Some(true));
            #[cfg(feature = "alloc")]
            {
                use x509::extensions_utils::KeyUsageValues;
                let ku = KeyUsage::from_der(ext.extn_value.as_bytes()).unwrap();
                let kuv = x509::extensions_utils::get_key_usage_values(&ku);
                let mut count = 0;
                for v in kuv {
                    if 0 == count {
                        assert_eq!(v, KeyUsageValues::KeyCertSign);
                    } else if 1 == count {
                        assert_eq!(v, KeyUsageValues::CRLSign);
                    } else {
                        panic!("Should not occur");
                    }
                    count += 1;
                }
            }
        } else if 3 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.32");
            assert_eq!(ext.critical, Option::None);
            let r = CertificatePolicies::from_der(ext.extn_value.as_bytes());
            let cp = r.unwrap();
            let i = cp.iter();
            for p in i {
                assert_eq!(p.policy_identifier.to_string(), "2.16.840.1.101.3.2.1.48.1");
            }
        } else if 4 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.19");
            assert_eq!(ext.critical, Option::Some(true));
            let bc = BasicConstraints::from_der(ext.extn_value.as_bytes()).unwrap();
            assert_eq!(bc.ca, Option::Some(true));
            assert_eq!(bc.path_len_constraint, Option::None);
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
