//! Certificate tests
use der::asn1::{BitString, UIntBytes, Utf8String};
use der::{Decodable, Encodable, ErrorKind, Length, Tag, Tagged};
use hex_literal::hex;
#[cfg(feature = "alloc")]
use x509::KeyUsage;
use x509::*;
use x509::{
    BasicConstraints, Certificate, CertificatePolicies, GeneralName, OtherName,
    SubjectKeyIdentifier,
};

fn spin_over_exts<'a>(exts: Extensions<'a>) {
    let i = exts.iter();
    for ext in i {
        if "2.5.29.9" == ext.extn_id.to_string() {
            let sdac_result = SubjectDirectoryAttributes::from_der(ext.extn_value);
            assert!(sdac_result.is_ok());

            let sdac = sdac_result.unwrap();
            let reencoded = sdac.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.5.29.14" == ext.extn_id.to_string() {
            let skid_result = SubjectKeyIdentifier::from_der(ext.extn_value);
            assert!(skid_result.is_ok());

            let skid = skid_result.unwrap();
            let reencoded = skid.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.5.29.15" == ext.extn_id.to_string() {
            let ku_result = KeyUsage::from_der(ext.extn_value);
            assert!(ku_result.is_ok());

            let ku = ku_result.unwrap();
            let reencoded = ku.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.5.29.16" == ext.extn_id.to_string() {
            let pku_result = PrivateKeyUsagePeriod::from_der(ext.extn_value);
            assert!(pku_result.is_ok());

            let pku = pku_result.unwrap();
            let reencoded = pku.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.5.29.17" == ext.extn_id.to_string() {
            let san_result = SubjectAltName::from_der(ext.extn_value);
            assert!(san_result.is_ok());

            let san = san_result.unwrap();
            let reencoded = san.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.5.29.18" == ext.extn_id.to_string() {
            let ian_result = IssuerAltName::from_der(ext.extn_value);
            assert!(ian_result.is_ok());

            let ian = ian_result.unwrap();
            let reencoded = ian.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.5.29.19" == ext.extn_id.to_string() {
            let bc_result = BasicConstraints::from_der(ext.extn_value);
            assert!(bc_result.is_ok());

            let bc = bc_result.unwrap();
            let reencoded = bc.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.5.29.30" == ext.extn_id.to_string() {
            let nc_result = NameConstraints::from_der(ext.extn_value);
            assert!(nc_result.is_ok());

            let nc = nc_result.unwrap();
            let reencoded = nc.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.5.29.31" == ext.extn_id.to_string() {
            let crldps_result = CRLDistributionPoints::from_der(ext.extn_value);
            assert!(crldps_result.is_ok());

            let crldps = crldps_result.unwrap();
            let reencoded = crldps.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.5.29.32" == ext.extn_id.to_string() {
            let pols_result = CertificatePolicies::from_der(ext.extn_value);
            assert!(pols_result.is_ok());

            let pols = pols_result.unwrap();
            let reencoded = pols.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.5.29.33" == ext.extn_id.to_string() {
            let pms_result = PolicyMappings::from_der(ext.extn_value);
            assert!(pms_result.is_ok());

            let pms = pms_result.unwrap();
            let reencoded = pms.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.5.29.35" == ext.extn_id.to_string() {
            let akid_result = AuthorityKeyIdentifier::from_der(ext.extn_value);
            assert!(akid_result.is_ok());

            let akid = akid_result.unwrap();
            let reencoded = akid.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.5.29.36" == ext.extn_id.to_string() {
            let pc_result = PolicyConstraints::from_der(ext.extn_value);
            assert!(pc_result.is_ok());

            let pc = pc_result.unwrap();
            let reencoded = pc.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.5.29.37" == ext.extn_id.to_string() {
            let eku_result = ExtendedKeyUsage::from_der(ext.extn_value);
            assert!(eku_result.is_ok());

            let eku = eku_result.unwrap();
            let reencoded = eku.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.5.29.46" == ext.extn_id.to_string() {
            let fc_result = FreshestCRL::from_der(ext.extn_value);
            assert!(fc_result.is_ok());

            let fc = fc_result.unwrap();
            let reencoded = fc.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.5.29.54" == ext.extn_id.to_string() {
            let iap_result = InhibitAnyPolicy::from_der(ext.extn_value);
            assert!(iap_result.is_ok());

            let iap = iap_result.unwrap();
            let reencoded = iap.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "1.3.6.1.5.5.7.1.1" == ext.extn_id.to_string() {
            let aia_result = AuthorityInfoAccessSyntax::from_der(ext.extn_value);
            assert!(aia_result.is_ok());

            let aia = aia_result.unwrap();
            let reencoded = aia.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "1.3.6.1.5.5.7.1.11" == ext.extn_id.to_string() {
            let sia_result = SubjectInfoAccessSyntax::from_der(ext.extn_value);
            assert!(sia_result.is_ok());

            let sia = sia_result.unwrap();
            let reencoded = sia.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "1.3.6.1.5.5.7.48.1.5" == ext.extn_id.to_string() {
            let nc_result = OcspNoCheck::from_der(ext.extn_value);
            assert!(nc_result.is_ok());

            let nc = nc_result.unwrap();
            let reencoded = nc.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.16.840.1.113730.1.1" == ext.extn_id.to_string() {
            let nct_result = BitString::from_der(ext.extn_value);
            assert!(nct_result.is_ok());

            let nct = nct_result.unwrap();
            let reencoded = nct.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "2.16.840.1.101.3.6.9.1" == ext.extn_id.to_string() {
            let pni_result = PivNaciIndicator::from_der(ext.extn_value);
            assert!(pni_result.is_ok());

            let pni = pni_result.unwrap();
            let reencoded = pni.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if "1.2.840.113533.7.65.0" == ext.extn_id.to_string() {
            println!(
                "Ignoring Entrust version info ({}) with criticality {}",
                ext.extn_id.to_string(),
                ext.critical
            );
        } else if "2.16.840.1.114027.30.1" == ext.extn_id.to_string() {
            println!(
                "Ignoring some (likely) Entrust extension ({}) with criticality {}",
                ext.extn_id.to_string(),
                ext.critical
            );
        } else if "1.3.6.1.4.1.311.20.2" == ext.extn_id.to_string() {
            println!(
                "Ignoring enrollCerttypeExtension ({}) with criticality {}",
                ext.extn_id.to_string(),
                ext.critical
            );
        } else if "1.3.6.1.4.1.311.21.1" == ext.extn_id.to_string() {
            println!(
                "Ignoring cAKeyCertIndexPair ({}) with criticality {}",
                ext.extn_id.to_string(),
                ext.critical
            );
        } else if "1.3.6.1.4.1.311.21.2" == ext.extn_id.to_string() {
            println!(
                "Ignoring certSrvPreviousCertHash ({}) with criticality {}",
                ext.extn_id.to_string(),
                ext.critical
            );
        } else if "1.3.6.1.4.1.311.21.7" == ext.extn_id.to_string() {
            println!(
                "Ignoring certificateTemplate ({}) with criticality {}",
                ext.extn_id.to_string(),
                ext.critical
            );
        } else if "1.3.6.1.4.1.311.21.10" == ext.extn_id.to_string() {
            println!(
                "Ignoring applicationCertPolicies ({}) with criticality {}",
                ext.extn_id.to_string(),
                ext.critical
            );
        } else if "1.3.6.1.5.5.7.1.3" == ext.extn_id.to_string() {
            println!(
                "Ignoring qcStatements ({}) with criticality {}",
                ext.extn_id.to_string(),
                ext.critical
            );
        } else {
            println!(
                "Unrecognized extension ({}) with criticality {}",
                ext.extn_id.to_string(),
                ext.critical
            );
        }
    }
}

#[test]
fn decode_general_name() {
    // DnsName
    let dns_name = GeneralName::from_der(&hex!("820C616D617A6F6E2E636F2E756B")[..]).unwrap();
    match dns_name {
        GeneralName::DnsName(dns_name) => assert_eq!(dns_name.to_string(), "amazon.co.uk"),
        _ => panic!("Failed to parse DnsName from GeneralName"),
    }

    // Rfc822Name
    let rfc822 = GeneralName::from_der(
        &hex!("811B456D61696C5F38303837323037343440746D612E6F73642E6D696C")[..],
    )
    .unwrap();
    match rfc822 {
        GeneralName::Rfc822Name(rfc822) => {
            assert_eq!(rfc822.to_string(), "Email_808720744@tma.osd.mil")
        }
        _ => panic!("Failed to parse Rfc822Name from GeneralName"),
    }

    // OtherName
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
        _ => panic!("Failed to parse OtherName from GeneralName"),
    }
}

#[test]
fn decode_cert() {
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
        if 0 == counter {
            assert_eq!(ext.extn_id.to_string(), PKIX_CE_KEY_USAGE.to_string());
            assert_eq!(ext.critical, true);

            use x509::extensions_utils::KeyUsageValues;
            let ku = KeyUsage::from_der(ext.extn_value).unwrap();
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

            let reencoded = ku.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if 1 == counter {
            assert_eq!(
                ext.extn_id.to_string(),
                PKIX_CE_BASIC_CONSTRAINTS.to_string()
            );
            assert_eq!(ext.critical, true);
            let bc = BasicConstraints::from_der(ext.extn_value).unwrap();
            assert_eq!(true, bc.ca);
            assert!(bc.path_len_constraint.is_none());

            let reencoded = bc.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if 2 == counter {
            assert_eq!(ext.extn_id.to_string(), PKIX_CE_POLICY_MAPPINGS.to_string());
            assert_eq!(ext.critical, false);
            let pm = PolicyMappings::from_der(ext.extn_value).unwrap();
            assert_eq!(19, pm.len());

            let reencoded = pm.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);

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
            assert_eq!(
                ext.extn_id.to_string(),
                PKIX_CE_CERTIFICATE_POLICIES.to_string()
            );
            assert_eq!(ext.critical, false);
            let cps = CertificatePolicies::from_der(ext.extn_value).unwrap();
            assert_eq!(19, cps.len());

            let reencoded = cps.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);

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
            assert_eq!(
                ext.extn_id.to_string(),
                PKIX_CE_SUBJECT_KEY_IDENTIFIER.to_string()
            );
            assert_eq!(ext.critical, false);
            let skid = SubjectKeyIdentifier::from_der(ext.extn_value).unwrap();
            assert_eq!(Length::new(21), skid.len());
            assert_eq!(
                &hex!("DBD3DEBF0D7B615B32803BC0206CD7AADD39B8ACFF"),
                skid.as_bytes()
            );

            let reencoded = skid.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if 5 == counter {
            assert_eq!(
                ext.extn_id.to_string(),
                PKIX_CE_CRL_DISTRIBUTION_POINTS.to_string()
            );
            assert_eq!(ext.critical, false);
            let crl_dps = CRLDistributionPoints::from_der(ext.extn_value).unwrap();
            assert_eq!(2, crl_dps.len());

            let reencoded = crl_dps.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);

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
            assert_eq!(
                ext.extn_id.to_string(),
                PKIX_PE_SUBJECTINFOACCESS.to_string()
            );
            assert_eq!(ext.critical, false);
            let sias = SubjectInfoAccessSyntax::from_der(ext.extn_value).unwrap();
            assert_eq!(1, sias.len());

            let reencoded = sias.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);

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
            assert_eq!(
                ext.extn_id.to_string(),
                PKIX_PE_AUTHORITYINFOACCESS.to_string()
            );
            assert_eq!(ext.critical, false);
            let aias = AuthorityInfoAccessSyntax::from_der(ext.extn_value).unwrap();
            assert_eq!(2, aias.len());
            let mut aia_counter = 0;

            let reencoded = aias.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);

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
            assert_eq!(
                ext.extn_id.to_string(),
                PKIX_CE_INHIBIT_ANY_POLICY.to_string()
            );
            assert_eq!(ext.critical, false);
            let iap = InhibitAnyPolicy::from_der(ext.extn_value).unwrap();
            assert_eq!(0, iap);

            let reencoded = iap.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        } else if 9 == counter {
            assert_eq!(
                ext.extn_id.to_string(),
                PKIX_CE_AUTHORITY_KEY_IDENTIFIER.to_string()
            );
            assert_eq!(ext.critical, false);
            let akid = AuthorityKeyIdentifier::from_der(ext.extn_value).unwrap();
            assert_eq!(
                &hex!("7C4C863AB80BD589870BEDB7E11BBD2A08BB3D23FF"),
                akid.key_identifier.unwrap().as_bytes()
            );

            let reencoded = akid.to_vec().unwrap();
            assert_eq!(ext.extn_value, reencoded);
        }

        counter += 1;
    }

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
        if 0 == counter {
            assert_eq!(
                ext.extn_id.to_string(),
                PKIX_CE_AUTHORITY_KEY_IDENTIFIER.to_string()
            );
            assert_eq!(ext.critical, false);
            let akid = AuthorityKeyIdentifier::from_der(ext.extn_value).unwrap();
            assert_eq!(
                akid.key_identifier.unwrap().as_bytes(),
                &hex!("E47D5FD15C9586082C05AEBE75B665A7D95DA866")[..]
            );
        } else if 1 == counter {
            assert_eq!(
                ext.extn_id.to_string(),
                PKIX_CE_SUBJECT_KEY_IDENTIFIER.to_string()
            );
            assert_eq!(ext.critical, false);
            let skid = SubjectKeyIdentifier::from_der(ext.extn_value).unwrap();
            assert_eq!(
                skid.as_bytes(),
                &hex!("580184241BBC2B52944A3DA510721451F5AF3AC9")[..]
            );
        } else if 2 == counter {
            assert_eq!(ext.extn_id.to_string(), PKIX_CE_KEY_USAGE.to_string());
            assert_eq!(ext.critical, true);
            use x509::extensions_utils::KeyUsageValues;
            let ku = KeyUsage::from_der(ext.extn_value).unwrap();
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
        } else if 3 == counter {
            assert_eq!(
                ext.extn_id.to_string(),
                PKIX_CE_CERTIFICATE_POLICIES.to_string()
            );
            assert_eq!(ext.critical, false);
            let r = CertificatePolicies::from_der(ext.extn_value);
            let cp = r.unwrap();
            let i = cp.iter();
            for p in i {
                assert_eq!(p.policy_identifier.to_string(), "2.16.840.1.101.3.2.1.48.1");
            }
        } else if 4 == counter {
            assert_eq!(
                ext.extn_id.to_string(),
                PKIX_CE_BASIC_CONSTRAINTS.to_string()
            );
            assert_eq!(ext.critical, true);
            let bc = BasicConstraints::from_der(ext.extn_value).unwrap();
            assert_eq!(bc.ca, true);
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

    // This cert adds extended key usage and netscape cert type vs above samples
    let der_encoded_cert = include_bytes!("examples/0954e2343dd5efe0a7f0967d69caf33e5f893720.der");
    let result = Certificate::from_der(der_encoded_cert);
    let cert: Certificate = result.unwrap();
    let exts = cert.tbs_certificate.extensions.unwrap();
    spin_over_exts(exts);

    // This cert adds extended key usage and name constraints vs above samples
    let der_encoded_cert = include_bytes!("examples/0fcc78fbbca9f32b08b19b032b84f2c86a128f35.der");
    let result = Certificate::from_der(der_encoded_cert);
    let cert: Certificate = result.unwrap();
    let exts = cert.tbs_certificate.extensions.unwrap();
    spin_over_exts(exts);

    // This cert adds logotype (which is unrecognized) vs above samples
    let der_encoded_cert = include_bytes!("examples/15b05c4865410c6b3ff76a4e8f3d87276756bd0c.der");
    let result = Certificate::from_der(der_encoded_cert);
    let cert: Certificate = result.unwrap();
    let exts = cert.tbs_certificate.extensions.unwrap();
    spin_over_exts(exts);

    // This cert features an EC key unlike the above samples
    let der_encoded_cert = include_bytes!("examples/16ee54e48c76eaa1052e09010d8faefee95e5ebb.der");
    let result = Certificate::from_der(der_encoded_cert);
    let cert: Certificate = result.unwrap();
    let exts = cert.tbs_certificate.extensions.unwrap();
    spin_over_exts(exts);

    // This cert adds issuer alt name vs above samples
    let der_encoded_cert = include_bytes!("examples/342cd9d3062da48c346965297f081ebc2ef68fdc.der");
    let result = Certificate::from_der(der_encoded_cert);
    let cert: Certificate = result.unwrap();
    let exts = cert.tbs_certificate.extensions.unwrap();
    spin_over_exts(exts);

    // This cert adds policy constraints vs above samples
    let der_encoded_cert = include_bytes!("examples/2049a5b28f104b2c6e1a08546f9cfc0353d6fd30.der");
    let result = Certificate::from_der(der_encoded_cert);
    let cert: Certificate = result.unwrap();
    let exts = cert.tbs_certificate.extensions.unwrap();
    spin_over_exts(exts);

    // This cert adds subject alt name vs above samples
    let der_encoded_cert = include_bytes!("examples/21723e7a0fb61a0bd4a29879b82a02b2fb4ad096.der");
    let result = Certificate::from_der(der_encoded_cert);
    let cert: Certificate = result.unwrap();
    let exts = cert.tbs_certificate.extensions.unwrap();
    spin_over_exts(exts);

    // This cert adds subject directory attributes vs above samples
    let der_encoded_cert =
        include_bytes!("examples/085B1E2F40254F9C7A2387BE9FF4EC116C326E10.fake.der");
    let result = Certificate::from_der(der_encoded_cert);
    let cert: Certificate = result.unwrap();
    let exts = cert.tbs_certificate.extensions.unwrap();
    spin_over_exts(exts);

    // This cert adds private key usage period (and an unprocessed Entrust extension) vs above samples
    let der_encoded_cert =
        include_bytes!("examples/554D5FF11DA613A155584D8D4AA07F67724D8077.fake.der");
    let result = Certificate::from_der(der_encoded_cert);
    let cert: Certificate = result.unwrap();
    let exts = cert.tbs_certificate.extensions.unwrap();
    spin_over_exts(exts);

    // This cert adds OCSP no check vs above samples
    let der_encoded_cert =
        include_bytes!("examples/28879DABB0FD11618FB74E47BE049D2933866D53.fake.der");
    let result = Certificate::from_der(der_encoded_cert);
    let cert: Certificate = result.unwrap();
    let exts = cert.tbs_certificate.extensions.unwrap();
    spin_over_exts(exts);

    // This cert adds PIV NACI indicator vs above samples
    let der_encoded_cert =
        include_bytes!("examples/288C8BCFEE6B89D110DAE2C9873897BF7FF53382.fake.der");
    let result = Certificate::from_der(der_encoded_cert);
    let cert: Certificate = result.unwrap();
    let exts = cert.tbs_certificate.extensions.unwrap();
    spin_over_exts(exts);
}

#[test]
fn decode_idp() {
    use der::TagNumber;

    // IDP from 04A8739769B3C090A11DCDFABA3CF33F4BEF21F3.crl in PKITS 2048 in ficam-scvp-testing repo
    let idp = IssuingDistributionPoint::from_der(&hex!("30038201FF")).unwrap();
    assert_eq!(idp.only_contains_cacerts, true);
    assert_eq!(idp.only_contains_attribute_certs, false);
    assert_eq!(idp.only_contains_user_certs, false);
    assert_eq!(idp.indirect_crl, false);
    assert!(idp.only_some_reasons.is_none());
    assert!(idp.distribution_point.is_none());

    let n =
        Name::from_der(&hex!("305A310B3009060355040613025553311F301D060355040A131654657374204365727469666963617465732032303137311C301A060355040B13136F6E6C79536F6D65526561736F6E7320434133310C300A0603550403130343524C")).unwrap();
    assert_eq!(4, n.len());

    let gn =
        GeneralName::from_der(&hex!("A45C305A310B3009060355040613025553311F301D060355040A131654657374204365727469666963617465732032303137311C301A060355040B13136F6E6C79536F6D65526561736F6E7320434133310C300A0603550403130343524C")).unwrap();
    match gn {
        GeneralName::DirectoryName(gn) => {
            assert_eq!(4, gn.len());
        }
        _ => {}
    }

    let gns =
        GeneralNames::from_der(&hex!("305EA45C305A310B3009060355040613025553311F301D060355040A131654657374204365727469666963617465732032303137311C301A060355040B13136F6E6C79536F6D65526561736F6E7320434133310C300A0603550403130343524C")).unwrap();
    assert_eq!(1, gns.len());
    let gn = gns.get(0).unwrap();
    match gn {
        GeneralName::DirectoryName(gn) => {
            assert_eq!(4, gn.len());
        }
        _ => {}
    }

    //TODO - fix decode impl (expecting a SEQUENCE despite this being a CHOICE). Sort out FixedTag implementation.
    // let dpn =
    //     DistributionPointName::from_der(&hex!("A05EA45C305A310B3009060355040613025553311F301D060355040A131654657374204365727469666963617465732032303137311C301A060355040B13136F6E6C79536F6D65526561736F6E7320434133310C300A0603550403130343524C")).unwrap();
    // match dpn {
    //     DistributionPointName::FullName(dpn) => {
    //         assert_eq!(1, dpn.len());
    //         let gn = dpn.get(0).unwrap();
    //         match gn {
    //             GeneralName::DirectoryName(gn) => {
    //                 assert_eq!(4, gn.len());
    //             }
    //             _ => {}
    //         }
    //     }
    //     _ => {}
    // }

    let dp =
        DistributionPoint::from_der(&hex!("3062A060A05EA45C305A310B3009060355040613025553311F301D060355040A131654657374204365727469666963617465732032303137311C301A060355040B13136F6E6C79536F6D65526561736F6E7320434133310C300A0603550403130343524C")).unwrap();
    let dpn = dp.distribution_point.unwrap();
    match dpn {
        DistributionPointName::FullName(dpn) => {
            assert_eq!(1, dpn.len());
            let gn = dpn.get(0).unwrap();
            match gn {
                GeneralName::DirectoryName(gn) => {
                    assert_eq!(4, gn.len());
                }
                _ => {}
            }
        }
        _ => {}
    }
    assert!(dp.crl_issuer.is_none());
    assert!(dp.reasons.is_none());

    //   0 103: SEQUENCE {
    //   2  96:   [0] {
    //   4  94:     [0] {
    //   6  92:       [4] {
    //   8  90:         SEQUENCE {
    //  10  11:           SET {
    //  12   9:             SEQUENCE {
    //  14   3:               OBJECT IDENTIFIER countryName (2 5 4 6)
    //  19   2:               PrintableString 'US'
    //        :               }
    //        :             }
    //  23  31:           SET {
    //  25  29:             SEQUENCE {
    //  27   3:               OBJECT IDENTIFIER organizationName (2 5 4 10)
    //  32  22:               PrintableString 'Test Certificates 2017'
    //        :               }
    //        :             }
    //  56  28:           SET {
    //  58  26:             SEQUENCE {
    //  60   3:               OBJECT IDENTIFIER organizationalUnitName (2 5 4 11)
    //  65  19:               PrintableString 'onlySomeReasons CA3'
    //        :               }
    //        :             }
    //  86  12:           SET {
    //  88  10:             SEQUENCE {
    //  90   3:               OBJECT IDENTIFIER commonName (2 5 4 3)
    //  95   3:               PrintableString 'CRL'
    //        :               }
    //        :             }
    //        :           }
    //        :         }
    //        :       }
    //        :     }
    // 100   3:   [3] 07 9F 80
    //        :   }
    // IDP from 54B0D2A6F6AA4780771CC4F9F076F623CEB0F57E.crl in PKITS 2048 in ficam-scvp-testing repo
    let idp =
        IssuingDistributionPoint::from_der(&hex!("3067A060A05EA45C305A310B3009060355040613025553311F301D060355040A131654657374204365727469666963617465732032303137311C301A060355040B13136F6E6C79536F6D65526561736F6E7320434133310C300A0603550403130343524C8303079F80")).unwrap();
    assert_eq!(idp.only_contains_cacerts, false);
    assert_eq!(idp.only_contains_attribute_certs, false);
    assert_eq!(idp.only_contains_user_certs, false);
    assert_eq!(idp.indirect_crl, false);
    assert!(idp.only_some_reasons.is_some());
    assert!(idp.distribution_point.is_some());

    let rfv = get_reason_flags_values(&idp.only_some_reasons.unwrap());
    assert_eq!(true, rfv.unused);
    assert_eq!(false, rfv.key_compromise);
    assert_eq!(false, rfv.ca_compromise);
    assert_eq!(true, rfv.affiliation_changed);
    assert_eq!(true, rfv.superseded);
    assert_eq!(true, rfv.cessation_of_operation);
    assert_eq!(true, rfv.certificate_hold);
    assert_eq!(true, rfv.remove_from_crl);
    assert_eq!(true, rfv.aa_compromise);

    //  930  360:             SEQUENCE {
    //  934  353:               [0] {
    //  938  349:                 [0] {
    //  942  117:                   [4] {
    //  944  115:                     SEQUENCE {
    //  946   11:                       SET {
    //  948    9:                         SEQUENCE {
    //  950    3:                           OBJECT IDENTIFIER countryName (2 5 4 6)
    //  955    2:                           PrintableString 'US'
    //          :                           }
    //          :                         }
    //  959   31:                       SET {
    //  961   29:                         SEQUENCE {
    //  963    3:                           OBJECT IDENTIFIER
    //          :                             organizationName (2 5 4 10)
    //  968   22:                           PrintableString 'Test Certificates 2017'
    //          :                           }
    //          :                         }
    //  992   24:                       SET {
    //  994   22:                         SEQUENCE {
    //  996    3:                           OBJECT IDENTIFIER
    //          :                             organizationalUnitName (2 5 4 11)
    // 1001   15:                           PrintableString 'indirectCRL CA5'
    //          :                           }
    //          :                         }
    // 1018   41:                       SET {
    // 1020   39:                         SEQUENCE {
    // 1022    3:                           OBJECT IDENTIFIER commonName (2 5 4 3)
    // 1027   32:                           PrintableString 'indirect CRL for indirectCRL CA6'
    //          :                           }
    //          :                         }
    //          :                       }
    //          :                     }
    // 1061  117:                   [4] {
    // 1063  115:                     SEQUENCE {
    // 1065   11:                       SET {
    // 1067    9:                         SEQUENCE {
    // 1069    3:                           OBJECT IDENTIFIER countryName (2 5 4 6)
    // 1074    2:                           PrintableString 'US'
    //          :                           }
    //          :                         }
    // 1078   31:                       SET {
    // 1080   29:                         SEQUENCE {
    // 1082    3:                           OBJECT IDENTIFIER
    //          :                             organizationName (2 5 4 10)
    // 1087   22:                           PrintableString 'Test Certificates 2017'
    //          :                           }
    //          :                         }
    // 1111   24:                       SET {
    // 1113   22:                         SEQUENCE {
    // 1115    3:                           OBJECT IDENTIFIER
    //          :                             organizationalUnitName (2 5 4 11)
    // 1120   15:                           PrintableString 'indirectCRL CA5'
    //          :                           }
    //          :                         }
    // 1137   41:                       SET {
    // 1139   39:                         SEQUENCE {
    // 1141    3:                           OBJECT IDENTIFIER commonName (2 5 4 3)
    // 1146   32:                           PrintableString 'indirect CRL for indirectCRL CA7'
    //          :                           }
    //          :                         }
    //          :                       }
    //          :                     }
    // 1180  109:                   [4] {
    // 1182  107:                     SEQUENCE {
    // 1184   11:                       SET {
    // 1186    9:                         SEQUENCE {
    // 1188    3:                           OBJECT IDENTIFIER countryName (2 5 4 6)
    // 1193    2:                           PrintableString 'US'
    //          :                           }
    //          :                         }
    // 1197   31:                       SET {
    // 1199   29:                         SEQUENCE {
    // 1201    3:                           OBJECT IDENTIFIER
    //          :                             organizationName (2 5 4 10)
    // 1206   22:                           PrintableString 'Test Certificates 2017'
    //          :                           }
    //          :                         }
    // 1230   24:                       SET {
    // 1232   22:                         SEQUENCE {
    // 1234    3:                           OBJECT IDENTIFIER
    //          :                             organizationalUnitName (2 5 4 11)
    // 1239   15:                           PrintableString 'indirectCRL CA5'
    //          :                           }
    //          :                         }
    // 1256   33:                       SET {
    // 1258   31:                         SEQUENCE {
    // 1260    3:                           OBJECT IDENTIFIER commonName (2 5 4 3)
    // 1265   24:                           PrintableString 'CRL1 for indirectCRL CA5'
    //          :                           }
    //          :                         }
    //          :                       }
    //          :                     }
    //          :                   }
    //          :                 }
    // 1291    1:               [4] FF
    //          :               }
    //          :             }
    //          :           }
    // IDP from 959528526E54B646AF895E2362D3AD20F4B3284D.crl in PKITS 2048 in ficam-scvp-testing repo
    let idp =
        IssuingDistributionPoint::from_der(&hex!("30820168A0820161A082015DA4753073310B3009060355040613025553311F301D060355040A13165465737420436572746966696361746573203230313731183016060355040B130F696E64697265637443524C204341353129302706035504031320696E6469726563742043524C20666F7220696E64697265637443524C20434136A4753073310B3009060355040613025553311F301D060355040A13165465737420436572746966696361746573203230313731183016060355040B130F696E64697265637443524C204341353129302706035504031320696E6469726563742043524C20666F7220696E64697265637443524C20434137A46D306B310B3009060355040613025553311F301D060355040A13165465737420436572746966696361746573203230313731183016060355040B130F696E64697265637443524C204341353121301F0603550403131843524C3120666F7220696E64697265637443524C204341358401FF")).unwrap();
    assert_eq!(idp.only_contains_cacerts, false);
    assert_eq!(idp.only_contains_attribute_certs, false);
    assert_eq!(idp.only_contains_user_certs, false);
    assert_eq!(idp.indirect_crl, true);
    assert!(idp.only_some_reasons.is_none());
    assert!(idp.distribution_point.is_some());
    let dp = idp.distribution_point.unwrap();
    match dp {
        DistributionPointName::FullName(dp) => {
            assert_eq!(3, dp.len());
            for gn in dp {
                match gn {
                    GeneralName::DirectoryName(gn) => {
                        assert_eq!(4, gn.len());
                    }
                    _ => {
                        panic!("Expected DirectoryName")
                    }
                }
            }
        }
        _ => {
            panic!("Expected FullName")
        }
    }

    //---------------------------------
    // Negative tests
    //---------------------------------
    // Value contains more than length value indicates
    let reason_flags = ReasonFlags::from_der(&hex!("0302079F80"));
    let err = reason_flags.err().unwrap();
    assert_eq!(
        ErrorKind::TrailingData {
            decoded: 4u8.into(),
            remaining: 1u8.into()
        },
        err.kind()
    );

    // Value incomplete relative to length value
    let reason_flags = ReasonFlags::from_der(&hex!("0304079F80"));
    let err = reason_flags.err().unwrap();
    assert_eq!(
        ErrorKind::Incomplete {
            expected_len: 3u8.into(),
            actual_len: 2u8.into()
        },
        err.kind()
    );

    // Value incomplete relative to length value
    let idp =
        IssuingDistributionPoint::from_der(&hex!("3067A060A05EA45C305A310B3009060355040613025553311F301D060355040A131654657374204365727469666963617465732032303137311C301A060355040B13136F6E6C79536F6D65526561736F6E7320434133310C300A0603550403130343524C8304079F80"));
    let err = idp.err().unwrap();
    assert_eq!(
        ErrorKind::Incomplete {
            expected_len: 3u8.into(),
            actual_len: 2u8.into()
        },
        err.kind()
    );

    // Truncated
    let reason_flags = ReasonFlags::from_der(&hex!("0303079F"));
    let err = reason_flags.err().unwrap();
    assert_eq!(
        ErrorKind::Incomplete {
            expected_len: 2u8.into(),
            actual_len: 1u8.into()
        },
        err.kind()
    );

    // Nonsensical tag where BIT STRING tag should be
    let reason_flags = ReasonFlags::from_der(&hex!("FF03079F80"));
    let err = reason_flags.err().unwrap();
    assert_eq!(ErrorKind::TagNumberInvalid, err.kind());

    // INTEGER tag where BIT STRING expected
    let reason_flags = ReasonFlags::from_der(&hex!("0203079F80"));
    let err = reason_flags.err().unwrap();
    assert_eq!(
        ErrorKind::TagUnexpected {
            expected: Some(Tag::BitString),
            actual: Tag::Integer
        },
        err.kind()
    );

    // Context specific tag that should be primitive is constructed
    let idp = IssuingDistributionPoint::from_der(&hex!("3003A201FF"));
    let err = idp.err().unwrap();
    assert_eq!(
        ErrorKind::Noncanonical {
            tag: Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(2)
            }
        },
        err.kind()
    );

    // Boolean value is two bytes long
    let idp =
        IssuingDistributionPoint::from_der(&hex!("30820168A0820161A082015DA4753073310B3009060355040613025553311F301D060355040A13165465737420436572746966696361746573203230313731183016060355040B130F696E64697265637443524C204341353129302706035504031320696E6469726563742043524C20666F7220696E64697265637443524C20434136A4753073310B3009060355040613025553311F301D060355040A13165465737420436572746966696361746573203230313731183016060355040B130F696E64697265637443524C204341353129302706035504031320696E6469726563742043524C20666F7220696E64697265637443524C20434137A46D306B310B3009060355040613025553311F301D060355040A13165465737420436572746966696361746573203230313731183016060355040B130F696E64697265637443524C204341353121301F0603550403131843524C3120666F7220696E64697265637443524C204341358402FFFF"));
    let err = idp.err().unwrap();
    assert_eq!(ErrorKind::Length { tag: Tag::Boolean }, err.kind());

    // Boolean value is neither 0x00 nor 0xFF
    let idp =
        IssuingDistributionPoint::from_der(&hex!("30820168A0820161A082015DA4753073310B3009060355040613025553311F301D060355040A13165465737420436572746966696361746573203230313731183016060355040B130F696E64697265637443524C204341353129302706035504031320696E6469726563742043524C20666F7220696E64697265637443524C20434136A4753073310B3009060355040613025553311F301D060355040A13165465737420436572746966696361746573203230313731183016060355040B130F696E64697265637443524C204341353129302706035504031320696E6469726563742043524C20666F7220696E64697265637443524C20434137A46D306B310B3009060355040613025553311F301D060355040A13165465737420436572746966696361746573203230313731183016060355040B130F696E64697265637443524C204341353121301F0603550403131843524C3120666F7220696E64697265637443524C20434135840175"));
    let err = idp.err().unwrap();
    assert_eq!(ErrorKind::Noncanonical { tag: Tag::Boolean }, err.kind());

    // Tag on second RDN in first name is TeletexString (20) instead of PrintableString (19) (and TeletexString is not supported)
    let idp =
        IssuingDistributionPoint::from_der(&hex!("30820168A0820161A082015DA4753073310B3009060355040613025553311F301D060355040A14165465737420436572746966696361746573203230313731183016060355040B130F696E64697265637443524C204341353129302706035504031320696E6469726563742043524C20666F7220696E64697265637443524C20434136A4753073310B3009060355040613025553311F301D060355040A13165465737420436572746966696361746573203230313731183016060355040B130F696E64697265637443524C204341353129302706035504031320696E6469726563742043524C20666F7220696E64697265637443524C20434137A46D306B310B3009060355040613025553311F301D060355040A13165465737420436572746966696361746573203230313731183016060355040B130F696E64697265637443524C204341353121301F0603550403131843524C3120666F7220696E64697265637443524C204341358401FF"));
    let err = idp.err().unwrap();
    assert_eq!(ErrorKind::TagUnknown { byte: 20u8.into() }, err.kind());

    // Length on second RDN in first name indicates more bytes than are present
    let idp =
        IssuingDistributionPoint::from_der(&hex!("30820168A0820161A082015DA4753073310B3009060355040613025553311F301D060355040A13995465737420436572746966696361746573203230313731183016060355040B130F696E64697265637443524C204341353129302706035504031320696E6469726563742043524C20666F7220696E64697265637443524C20434136A4753073310B3009060355040613025553311F301D060355040A13165465737420436572746966696361746573203230313731183016060355040B130F696E64697265637443524C204341353129302706035504031320696E6469726563742043524C20666F7220696E64697265637443524C20434137A46D306B310B3009060355040613025553311F301D060355040A13165465737420436572746966696361746573203230313731183016060355040B130F696E64697265637443524C204341353121301F0603550403131843524C3120666F7220696E64697265637443524C204341358401FF"));
    let err = idp.err().unwrap();
    assert_eq!(
        ErrorKind::Length {
            tag: Tag::PrintableString
        },
        err.kind()
    );
}
