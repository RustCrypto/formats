//! Certificate tests
use der::asn1::{UIntBytes, Utf8String};
use der::{Decodable, Length, Tag};
use hex_literal::hex;
#[cfg(feature = "alloc")]
use x509::KeyUsage;
use x509::*;
use x509::{
    BasicConstraints, Certificate, CertificatePolicies, DeferCertificate, GeneralName, OtherName,
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
    let o2parse = ObjectIdentifier::from_der(&hex!("0603550406")).unwrap();
    let o2str = o2parse.to_string();
    assert_eq!("2.5.4.6", o2str);

    let o1parse = ObjectIdentifier::from_der(&hex!(
        "06252B060104018237150885C8B86B87AFF00383A99F3C96C34081ADE6494D82B0E91D85B2873D"
    ))
    .unwrap();
    let o1str = o1parse.to_string();
    assert_eq!(
        o1str,
        "1.3.6.1.4.1.311.21.8.11672683.15464451.6967228.369088.2847561.77.4994205.11305917"
    );
    let o1 = ObjectIdentifier::new(
        "1.3.6.1.4.1.311.21.8.11672683.15464451.6967228.369088.2847561.77.4994205.11305917",
    );
    assert_eq!(
        o1.to_string(),
        "1.3.6.1.4.1.311.21.8.11672683.15464451.6967228.369088.2847561.77.4994205.11305917"
    );

    let dns_name = GeneralName::from_der(&hex!("820C616D617A6F6E2E636F2E756B")[..]).unwrap();
    match dns_name {
        GeneralName::DnsName(dns_name) => assert_eq!(dns_name.to_string(), "amazon.co.uk"),
        _ => panic!("No good"),
    }

    let rfc822 = GeneralName::from_der(
        &hex!("811B456D61696C5F38303837323037343440746D612E6F73642E6D696C")[..],
    )
    .unwrap();
    match rfc822 {
        GeneralName::Rfc822Name(rfc822) => {
            assert_eq!(rfc822.to_string(), "Email_808720744@tma.osd.mil")
        }
        _ => panic!("No good"),
    }

    let on = OtherName::from_der(
        &hex!("3021060A2B060104018237140203A0130C1155706E5F323134393530313330406D696C")[..],
    )
    .unwrap();

    let onval = Utf8String::from_der(on.value.value()).unwrap();
    assert_eq!(onval.to_string(), "Upn_214950130@mil");

    let other_name = GeneralName::from_der(
        &hex!("A021060A2B060104018237140203A0130C1155706E5F323134393530313330406D696C")[..],
    )
    .unwrap();
    match other_name {
        GeneralName::OtherName(other_name) => {
            let onval = Utf8String::from_der(other_name.value.value()).unwrap();
            assert_eq!(onval.to_string(), "Upn_214950130@mil");
        }
        _ => panic!("No good"),
    }

    // cloned cert with variety of interesting bits, including subject DN encoded backwards, large
    // policy mapping set, large policy set (including one with qualifiers), fairly typical set of
    // extensions otherwise
    let der_encoded_cert =
        include_bytes!("examples/026EDA6FA1EDFA8C253936C75B5EEBD954BFF452.fake.der");
    let result = Certificate::from_der(der_encoded_cert);
    let cert: Certificate = result.unwrap();
    let exts = cert.tbs_certificate.extensions.unwrap();
    let i = exts.iter();
    let mut counter = 0;
    for ext in i {
        // TODO - parse and compare extension values
        if 0 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.15");
            assert_eq!(ext.critical, Option::Some(true));

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
        } else if 1 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.19");
            assert_eq!(ext.critical, Option::Some(true));
            let bc = BasicConstraints::from_der(ext.extn_value.as_bytes()).unwrap();
            assert_eq!(true, bc.ca.unwrap());
            assert!(bc.path_len_constraint.is_none());
        } else if 2 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.33");
            assert_eq!(ext.critical, None);
            let pm = PolicyMappings::from_der(ext.extn_value.as_bytes()).unwrap();
            assert_eq!(19, pm.len());

            let subject_domain_policy: [&str; 19] = [
                "2.16.840.1.101.3.2.1.48.2",
                "2.16.840.1.101.3.2.1.48.2",
                "2.16.840.1.101.3.2.1.48.3",
                "2.16.840.1.101.3.2.1.48.3",
                "2.16.840.1.101.3.2.1.48.5",
                "2.16.840.1.101.3.2.1.48.5",
                "2.16.840.1.101.3.2.1.48.4",
                "2.16.840.1.101.3.2.1.48.4",
                "2.16.840.1.101.3.2.1.48.6",
                "2.16.840.1.101.3.2.1.48.6",
                "2.16.840.1.101.3.2.1.48.78",
                "2.16.840.1.101.3.2.1.48.78",
                "2.16.840.1.101.3.2.1.48.78",
                "2.16.840.1.101.3.2.1.48.79",
                "2.16.840.1.101.3.2.1.48.80",
                "2.16.840.1.101.3.2.1.48.99",
                "2.16.840.1.101.3.2.1.48.99",
                "2.16.840.1.101.3.2.1.48.100",
                "2.16.840.1.101.3.2.1.48.100",
            ];

            let issuer_domain_policy: [&str; 19] = [
                "2.16.840.1.113839.0.100.2.1",
                "2.16.840.1.113839.0.100.2.2",
                "2.16.840.1.113839.0.100.3.1",
                "2.16.840.1.113839.0.100.3.2",
                "2.16.840.1.113839.0.100.14.1",
                "2.16.840.1.113839.0.100.14.2",
                "2.16.840.1.113839.0.100.12.1",
                "2.16.840.1.113839.0.100.12.2",
                "2.16.840.1.113839.0.100.15.1",
                "2.16.840.1.113839.0.100.15.2",
                "2.16.840.1.113839.0.100.18.0",
                "2.16.840.1.113839.0.100.18.1",
                "2.16.840.1.113839.0.100.18.2",
                "2.16.840.1.113839.0.100.19.1",
                "2.16.840.1.113839.0.100.20.1",
                "2.16.840.1.113839.0.100.37.1",
                "2.16.840.1.113839.0.100.37.2",
                "2.16.840.1.113839.0.100.38.1",
                "2.16.840.1.113839.0.100.38.2",
            ];

            let mut counter_pm = 0;
            for mapping in pm {
                assert_eq!(
                    issuer_domain_policy[counter_pm],
                    mapping.issuer_domain_policy.to_string()
                );
                assert_eq!(
                    subject_domain_policy[counter_pm],
                    mapping.subject_domain_policy.to_string()
                );
                counter_pm += 1;
            }
        } else if 3 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.32");
            assert_eq!(ext.critical, None);
            let cps = CertificatePolicies::from_der(ext.extn_value.as_bytes()).unwrap();
            assert_eq!(19, cps.len());

            let ids: [&str; 19] = [
                "2.16.840.1.113839.0.100.2.1",
                "2.16.840.1.113839.0.100.2.2",
                "2.16.840.1.113839.0.100.3.1",
                "2.16.840.1.113839.0.100.3.2",
                "2.16.840.1.113839.0.100.14.1",
                "2.16.840.1.113839.0.100.14.2",
                "2.16.840.1.113839.0.100.12.1",
                "2.16.840.1.113839.0.100.12.2",
                "2.16.840.1.113839.0.100.15.1",
                "2.16.840.1.113839.0.100.15.2",
                "2.16.840.1.113839.0.100.18.0",
                "2.16.840.1.113839.0.100.18.1",
                "2.16.840.1.113839.0.100.18.2",
                "2.16.840.1.113839.0.100.19.1",
                "2.16.840.1.113839.0.100.20.1",
                "2.16.840.1.113839.0.100.37.1",
                "2.16.840.1.113839.0.100.37.2",
                "2.16.840.1.113839.0.100.38.1",
                "2.16.840.1.113839.0.100.38.2",
            ];

            let mut cp_counter = 0;
            for cp in cps {
                assert_eq!(ids[cp_counter], cp.policy_identifier.to_string());
                if 18 == cp_counter {
                    assert!(cp.policy_qualifiers.is_some());
                    let pq = cp.policy_qualifiers.unwrap();
                    let mut counter_pq = 0;
                    for pqi in pq.iter() {
                        if 0 == counter_pq {
                            assert_eq!("1.3.6.1.5.5.7.2.1", pqi.policy_qualifier_id.to_string());
                            let cpsval = pqi.qualifier.unwrap().ia5_string().unwrap();
                            assert_eq!(
                                "https://secure.identrust.com/certificates/policy/IGC/index.html",
                                cpsval.to_string()
                            );
                        } else if 1 == counter_pq {
                            assert_eq!("1.3.6.1.5.5.7.2.2", pqi.policy_qualifier_id.to_string());
                            // TODO VisibleString
                        }
                        counter_pq += 1;
                    }
                } else {
                    assert!(cp.policy_qualifiers.is_none())
                }

                cp_counter += 1;
            }
        } else if 4 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.14");
            assert_eq!(ext.critical, None);
            let skid = SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()).unwrap();
            assert_eq!(Length::new(21), skid.len());
            assert_eq!(
                &hex!("DBD3DEBF0D7B615B32803BC0206CD7AADD39B8ACFF"),
                skid.as_bytes()
            );
        } else if 5 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.31");
            assert_eq!(ext.critical, None);
            let crl_dps = CRLDistributionPoints::from_der(ext.extn_value.as_bytes()).unwrap();
            assert_eq!(2, crl_dps.len());
            let mut crldp_counter = 0;
            for crldp in crl_dps {
                let dpn = crldp.distribution_point.unwrap();
                if 0 == crldp_counter {
                    match dpn {
                        DistributionPointName::FullName(gns) => {
                            assert_eq!(1, gns.len());
                            let gn = gns.get(0).unwrap();
                            match gn {
                                GeneralName::UniformResourceIdentifier(uri) => {
                                    assert_eq!(
                                        "http://crl-pte.identrust.com.test/crl/IGCRootca1.crl",
                                        uri.to_string()
                                    );
                                }
                                _ => {
                                    panic!("Expected UniformResourceIdentifier");
                                }
                            }
                        }
                        _ => {
                            panic!("Expected FullName");
                        }
                    }
                } else if 1 == crldp_counter {
                    match dpn {
                        DistributionPointName::FullName(gns) => {
                            assert_eq!(1, gns.len());
                            let gn = gns.get(0).unwrap();
                            match gn {
                                GeneralName::UniformResourceIdentifier(uri) => {
                                    assert_eq!("ldap://ldap-pte.identrust.com.test/cn%3DIGC%20Root%20CA1%2Co%3DIdenTrust%2Cc%3DUS%3FcertificateRevocationList%3Bbinary", uri.to_string());
                                }
                                _ => {
                                    panic!("Expected UniformResourceIdentifier");
                                }
                            }
                        }
                        _ => {
                            panic!("Expected UniformResourceIdentifier");
                        }
                    }
                }

                crldp_counter += 1;
            }
        } else if 6 == counter {
            assert_eq!(ext.extn_id.to_string(), "1.3.6.1.5.5.7.1.11");
            assert_eq!(ext.critical, None);
            let sias = SubjectInfoAccessSyntax::from_der(ext.extn_value.as_bytes()).unwrap();
            assert_eq!(1, sias.len());
            for sia in sias {
                assert_eq!("1.3.6.1.5.5.7.48.5", sia.access_method.to_string());
                let gn = sia.access_location;
                match gn {
                    GeneralName::UniformResourceIdentifier(gn) => {
                        assert_eq!(
                            "http://http.cite.fpki-lab.gov.test/bridge/caCertsIssuedBytestFBCA.p7c",
                            gn.to_string()
                        );
                    }
                    _ => {
                        panic!("Expected UniformResourceIdentifier");
                    }
                }
            }
        } else if 7 == counter {
            assert_eq!(ext.extn_id.to_string(), "1.3.6.1.5.5.7.1.1");
            assert_eq!(ext.critical, None);
            let aias = AuthorityInfoAccessSyntax::from_der(ext.extn_value.as_bytes()).unwrap();
            assert_eq!(2, aias.len());
            let mut aia_counter = 0;
            for aia in aias {
                if 0 == aia_counter {
                    assert_eq!("1.3.6.1.5.5.7.48.2", aia.access_method.to_string());
                    let gn = aia.access_location;
                    match gn {
                        GeneralName::UniformResourceIdentifier(gn) => {
                            assert_eq!(
                                "http://apps-stg.identrust.com.test/roots/IGCRootca1.p7c",
                                gn.to_string()
                            );
                        }
                        _ => {
                            panic!("Expected UniformResourceIdentifier");
                        }
                    }
                } else if 1 == aia_counter {
                    assert_eq!("1.3.6.1.5.5.7.48.1", aia.access_method.to_string());
                    let gn = aia.access_location;
                    match gn {
                        GeneralName::UniformResourceIdentifier(gn) => {
                            assert_eq!(
                                "http://igcrootpte.ocsp.identrust.com.test:8125",
                                gn.to_string()
                            );
                        }
                        _ => {
                            panic!("Expected UniformResourceIdentifier");
                        }
                    }
                }

                aia_counter += 1;
            }
        } else if 8 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.54");
            assert_eq!(ext.critical, None);
            let iap = InhibitAnyPolicy::from_der(ext.extn_value.as_bytes()).unwrap();
            assert_eq!(0, iap);
        } else if 9 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.35");
            assert_eq!(ext.critical, None);
            let akid = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes()).unwrap();
            assert_eq!(
                &hex!("7C4C863AB80BD589870BEDB7E11BBD2A08BB3D23FF"),
                akid.key_identifier.unwrap().as_bytes()
            );
        }

        counter += 1;
    }

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
