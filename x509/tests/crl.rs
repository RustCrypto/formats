//! CertificateList tests
use crate::AttributeTypeAndValue;
use der::asn1::SetOf;
use der::{Decodable, ErrorKind, Tag};
use hex_literal::hex;
use x509::extensions_utils::*;
use x509::DistributionPoint;
use x509::*;

#[test]
fn decode_crl() {
    let der_encoded_crl = include_bytes!("examples/GoodCACRL.crl");
    let defer_crl = DeferCertificateList::from_der(der_encoded_crl).unwrap();
    assert_eq!(
        defer_crl.tbs_cert_list,
        &hex!("3081E9020101300D06092A864886F70D01010B05003040310B3009060355040613025553311F301D060355040A1316546573742043657274696669636174657320323031313110300E06035504031307476F6F64204341170D3130303130313038333030305A170D3330313233313038333030305A3044302002010E170D3130303130313038333030305A300C300A0603551D1504030A0101302002010F170D3130303130313038333030315A300C300A0603551D1504030A0101A02F302D301F0603551D23041830168014580184241BBC2B52944A3DA510721451F5AF3AC9300A0603551D140403020101")[..]
    );

    let result = CertificateList::from_der(der_encoded_crl);
    let crl: CertificateList = result.unwrap();

    assert_eq!(crl.tbs_cert_list.version, Some(1));
    assert_eq!(
        crl.tbs_cert_list.signature.oid.to_string(),
        "1.2.840.113549.1.1.11"
    );
    assert_eq!(
        crl.tbs_cert_list.signature.parameters.unwrap().tag(),
        Tag::Null
    );
    assert_eq!(
        crl.tbs_cert_list.signature.parameters.unwrap().is_null(),
        true
    );

    let mut counter = 0;
    let i = crl.tbs_cert_list.issuer.iter();
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
        crl.tbs_cert_list.this_update.to_unix_duration().as_secs(),
        1262334600
    );
    assert_eq!(
        crl.tbs_cert_list.next_update.to_unix_duration().as_secs(),
        1924936200
    );

    // TODO - process entries

    counter = 0;
    let exts = crl.tbs_cert_list.crl_extensions.unwrap();
    let i = exts.iter();
    for ext in i {
        // TODO - parse and compare extension values
        if 0 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.35");
            assert_eq!(ext.critical, Option::Some(false));
            //let akid = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes()).unwrap();
            //assert_eq!(akid.keyIdentifier.unwrap().as_bytes(), &hex!("580184241BBC2B52944A3DA510721451F5AF3AC9")[..]);
        } else if 1 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.20");
            assert_eq!(ext.critical, Option::Some(false));
        }
        counter += 1;
    }
    assert_eq!(
        crl.signature_algorithm.oid.to_string(),
        "1.2.840.113549.1.1.11"
    );
    assert_eq!(crl.signature_algorithm.parameters.unwrap().tag(), Tag::Null);
    assert_eq!(crl.signature_algorithm.parameters.unwrap().is_null(), true);

    // TODO - parse and compare signature value
}

#[test]
fn decode_cert_extensions() {
    // AIA from 00AC0C41BFC8019FABB41329424027D8D7605112.fake.der in MF PKI in ficam-scvp-testing repo
    //3082014E06082B06010505070101048201403082013C303206082B060105050730018626687474703A2F2F7373702D6F6373702E766572697369676E2E636F6D2E746573743A38303931305206082B060105050730028646687474703A2F2F7373702D6169612E766572697369676E2E636F6D2E746573742F53535047332F43657274735F6973737565645F746F5F5652534E535350434147332E7037633081B106082B060105050730028681A46C6461703A2F2F7373702D6169612D6C6461702E766572697369676E2E636F6D2E746573742F636E3D566572695369676E253230535350253230496E7465726D65646961746525323043412532302D25323047332C6F3D566572695369676E2C253230496E632E2C6F3D4D6F636B2C633D55533F634143657274696669636174653B62696E6172792C63726F73734365727469666963617465506169723B62696E617279
    //let aias =
    //     AuthorityInfoAccessSyntax::from_der(&hex!("3082014E06082B06010505070101048201403082013C303206082B060105050730018626687474703A2F2F7373702D6F6373702E766572697369676E2E636F6D2E746573743A38303931305206082B060105050730028646687474703A2F2F7373702D6169612E766572697369676E2E636F6D2E746573742F53535047332F43657274735F6973737565645F746F5F5652534E535350434147332E7037633081B106082B060105050730028681A46C6461703A2F2F7373702D6169612D6C6461702E766572697369676E2E636F6D2E746573742F636E3D566572695369676E253230535350253230496E7465726D65646961746525323043412532302D25323047332C6F3D566572695369676E2C253230496E632E2C6F3D4D6F636B2C633D55533F634143657274696669636174653B62696E6172792C63726F73734365727469666963617465506169723B62696E617279")).unwrap();

    //   0  50: SEQUENCE {
    //   2   8:   OBJECT IDENTIFIER ocsp (1 3 6 1 5 5 7 48 1)
    //  12  38:   [6] 'http://ssp-ocsp.verisign.com.test:8091'
    //        :   }
    let ad = AccessDescription::from_der(&hex!("303206082B060105050730018626687474703A2F2F7373702D6F6373702E766572697369676E2E636F6D2E746573743A38303931")).unwrap();
    let am = ad.access_method;
    assert_eq!("1.3.6.1.5.5.7.48.1", am.to_string());
    let al = ad.access_location;
    match al {
        GeneralName::UniformResourceIdentifier(uri) => {
            assert_eq!("http://ssp-ocsp.verisign.com.test:8091", uri.to_string());
        }
        _ => {}
    }
}

#[test]
fn decode_idp() {
    // let rdnr = SetOf::<AttributeTypeAndValue<'_>, 3>::from_der(&hex!("3139301906035504030C12546573742055736572393031353734333830301C060A0992268993F22C640101130E3437303031303030303134373333"));
    // let rnd = rdnr.unwrap();

    // IDP from 04A8739769B3C090A11DCDFABA3CF33F4BEF21F3.crl in PKITS 2048 in ficam-scvp-testing repo
    let idp = IssuingDistributionPoint::from_der(&hex!("30038201FF")).unwrap();
    assert_eq!(idp.only_contains_cacerts, Some(true));
    assert_eq!(idp.only_contains_attribute_certs, Some(false));
    assert_eq!(idp.only_contains_user_certs, Some(false));
    assert_eq!(idp.indirect_crl, Some(false));
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

    let dpn =
        DistributionPointName::from_der(&hex!("3060A05EA45C305A310B3009060355040613025553311F301D060355040A131654657374204365727469666963617465732032303137311C301A060355040B13136F6E6C79536F6D65526561736F6E7320434133310C300A0603550403130343524C")).unwrap();
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
    assert_eq!(idp.only_contains_cacerts, Some(false));
    assert_eq!(idp.only_contains_attribute_certs, Some(false));
    assert_eq!(idp.only_contains_user_certs, Some(false));
    assert_eq!(idp.indirect_crl, Some(false));
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
    assert_eq!(idp.only_contains_cacerts, Some(false));
    assert_eq!(idp.only_contains_attribute_certs, Some(false));
    assert_eq!(idp.only_contains_user_certs, Some(false));
    assert_eq!(idp.indirect_crl, Some(true));
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
    // TODO - restore this test when constructed/primitive enforcement is restored in context specific
    // let idp = IssuingDistributionPoint::from_der(&hex!("3003A201FF"));
    // let err = idp.err().unwrap();
    // assert_eq!(
    //     ErrorKind::Noncanonical {
    //         tag: Tag::ContextSpecific {
    //             constructed: true,
    //             number: TagNumber::new(2)
    //         }
    //     },
    //     err.kind()
    // );

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

#[test]
fn decode_crl_entry_extensions() {
    // CRL entry from TS-Mobile-QCA.crl in MF PKI artifact collection in ficam-scvp-testing repo
    //   6931     51:       SEQUENCE {
    //   6933     20:         INTEGER
    //              :           43 3E 27 CB 0D 6C 8E A4 6A EE 4C 15 FD 7E C9 F0
    //              :           8A 09 CC 22
    //   6955     13:         UTCTime 22/06/2015 19:41:56 GMT
    //   6970     12:         SEQUENCE {
    //   6972     10:           SEQUENCE {
    //   6974      3:             OBJECT IDENTIFIER cRLReason (2 5 29 21)
    //   6979      3:             OCTET STRING, encapsulates {
    //   6981      1:               ENUMERATED 4
    //              :               }
    //              :             }
    //              :           }
    //              :         }
    let crl_entry =
        CrlEntry::from_der(&hex!("30330214433E27CB0D6C8EA46AEE4C15FD7EC9F08A09CC22170D3135303632323139343135365A300C300A0603551D1504030A0104")).unwrap();
    assert_eq!(
        1435002116,
        crl_entry.this_update.to_unix_duration().as_secs()
    );
    let mut counter = 0;
    let exts = crl_entry.crl_entry_extensions.unwrap();
    let i = exts.iter();
    for ext in i {
        // TODO - parse and compare extension values
        if 0 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.21");
            assert_eq!(ext.critical, Option::Some(false));
            let crl_reason = CRLReason::from_der(ext.extn_value.as_bytes()).unwrap();
            assert_eq!(CRLReason::Superseded, crl_reason);
        }
        counter += 1;
    }
}
