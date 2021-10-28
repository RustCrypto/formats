//! CertificateList tests
use der::{Decodable, Tag};
use hex_literal::hex;
use x509::extensions_utils::*;
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
            assert_eq!(ext.critical, Option::None);
            //let akid = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes()).unwrap();
            //assert_eq!(akid.keyIdentifier.unwrap().as_bytes(), &hex!("580184241BBC2B52944A3DA510721451F5AF3AC9")[..]);
        } else if 1 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.20");
            assert_eq!(ext.critical, Option::None);
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
}

#[test]
fn decode_crl_entry_extensions() {
    // ReasonFlags from IDP from 54B0D2A6F6AA4780771CC4F9F076F623CEB0F57E.crl in PKITS 2048 in ficam-scvp-testing repo
    let reason_flags = ReasonFlags::from_der(&hex!("0303079F80")).unwrap();
    let rfv = get_reason_flags_values(&reason_flags);
    assert_eq!(true, rfv.unused);
    assert_eq!(false, rfv.key_compromise);
    assert_eq!(false, rfv.ca_compromise);
    assert_eq!(true, rfv.affiliation_changed);
    assert_eq!(true, rfv.superseded);
    assert_eq!(true, rfv.cessation_of_operation);
    assert_eq!(true, rfv.certificate_hold);
    assert_eq!(true, rfv.remove_from_crl);
    assert_eq!(true, rfv.aa_compromise);

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
            assert_eq!(ext.critical, Option::None);
            let crl_reason = CRLReason::from_der(ext.extn_value.as_bytes()).unwrap();
            assert_eq!(CRLReason::Superseded, crl_reason);
        }
        counter += 1;
    }
}
