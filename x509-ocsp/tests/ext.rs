//! ocsp extension tests

use core::str::FromStr;
use der::{
    DateTime, Encode,
    asn1::{Ia5String, Null, ObjectIdentifier, Uint},
};
use hex_literal::hex;
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    ext::{
        pkix::{name::*, *},
        *,
    },
    name::Name,
};
use x509_ocsp::{OcspGeneralizedTime, ext::*};

const ID_AD_OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");
const ID_PKIX_OCSP_BASIC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");
const ID_PKIX_OCSP_NONCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");
const ID_PKIX_OCSP_CRL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.3");

//  0:d=0  hl=2 l=  25 cons: SEQUENCE
//  2:d=1  hl=2 l=   9 prim: OBJECT            :OCSP Nonce
// 13:d=1  hl=2 l=  12 prim: OCTET STRING      [HEX DUMP]:040A00010203040506070809
// --
//  0:d=0  hl=2 l=  10 prim: OCTET STRING      [HEX DUMP]:00010203040506070809
#[test]
fn as_extension_nonce() {
    let bytes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let ext = Nonce::new(bytes).unwrap();
    assert_eq!(ext.0.as_bytes(), &bytes);
    let ext = ext.to_extension(&Name::default(), &[]).unwrap();
    assert_eq!(
        &ext.to_der().unwrap(),
        &hex!("301906092b0601050507300102040c040a00010203040506070809")[..]
    );
}

#[cfg(feature = "rand")]
#[test]
fn nonce_generation() {
    let mut rng = rand::rng();
    let nonce = Nonce::generate(&mut rng, 10).unwrap();
    assert_eq!(nonce.0.as_bytes().len(), 10);
    let nonce = Nonce::generate(&mut rng, 5).unwrap();
    assert_eq!(nonce.0.as_bytes().len(), 5);
    let nonce = Nonce::generate(&mut rng, 32).unwrap();
    assert_eq!(nonce.0.as_bytes().len(), 32);
    let nonce = Nonce::generate(&mut rng, 4096).unwrap();
    assert_eq!(nonce.0.as_bytes().len(), 4096);
}

//  0:d=0  hl=2 l=  63 cons: SEQUENCE
//  2:d=1  hl=2 l=   9 prim: OBJECT            :OCSP CRL ID
// 13:d=1  hl=2 l=  50 prim: OCTET STRING      [HEX DUMP]:3030A0161614687474703A2F2F3132372E302E302\
//                                                        E312F63726CA103020101A211180F323032303031\
//                                                        30313030303030305A
// --
//  0:d=0  hl=2 l=  48 cons: SEQUENCE
//  2:d=1  hl=2 l=  22 cons: cont [ 0 ]
//  4:d=2  hl=2 l=  20 prim: IA5STRING         :http://127.0.0.1/crl
// 26:d=1  hl=2 l=   3 cons: cont [ 1 ]
// 28:d=2  hl=2 l=   1 prim: INTEGER           :01
// 31:d=1  hl=2 l=  17 cons: cont [ 2 ]
// 33:d=2  hl=2 l=  15 prim: GENERALIZEDTIME   :20200101000000Z
#[test]
fn as_extension_crl_references() {
    let ext = CrlReferences {
        crl_url: Some(Ia5String::new("http://127.0.0.1/crl").unwrap()),
        crl_num: Some(Uint::new(&[1]).unwrap()),
        crl_time: Some(OcspGeneralizedTime::from(
            DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
        )),
    };
    let ext = ext.to_extension(&Name::default(), &[]).unwrap();
    assert_eq!(
        &ext.to_der().unwrap(),
        &hex!(
            "303f06092b060105050730010304323030a0161614687474703a2f2f3132372e30\
             2e302e312f63726ca103020101a211180f32303230303130313030303030305a"
        )[..]
    );
}

//  0:d=0  hl=2 l=  51 cons: SEQUENCE
//  2:d=1  hl=2 l=   9 prim: OBJECT            :Acceptable OCSP Responses
// 13:d=1  hl=2 l=   1 prim: BOOLEAN           :255
// 16:d=1  hl=2 l=  35 prim: OCTET STRING      [HEX DUMP]:302106092B060105050730010106092B060105050\
//                                                        730010206092B0601050507300103
// --
//  0:d=0  hl=2 l=  33 cons: SEQUENCE
//  2:d=1  hl=2 l=   9 prim: OBJECT            :Basic OCSP Response
// 13:d=1  hl=2 l=   9 prim: OBJECT            :OCSP Nonce
// 24:d=1  hl=2 l=   9 prim: OBJECT            :OCSP CRL ID
#[test]
fn as_extension_acceptable_responses() {
    let ext = AcceptableResponses::from(vec![
        ID_PKIX_OCSP_BASIC,
        ID_PKIX_OCSP_NONCE,
        ID_PKIX_OCSP_CRL,
    ]);
    let ext = ext.to_extension(&Name::default(), &[]).unwrap();
    assert_eq!(
        &ext.to_der().unwrap(),
        &hex!(
            "303306092b06010505073001040101ff0423302106092b06010505073001010609\
             2b060105050730010206092b0601050507300103"
        )[..]
    );
}

//  0:d=0  hl=2 l=  30 cons: SEQUENCE
//  2:d=1  hl=2 l=   9 prim: OBJECT            :OCSP Archive Cutoff
// 13:d=1  hl=2 l=  17 prim: OCTET STRING      [HEX DUMP]:180F32303230303130313030303030305A
// --
//  0:d=0  hl=2 l=  15 prim: GENERALIZEDTIME   :20200101000000Z
#[test]
fn as_extension_archive_cutoff() {
    let ext = ArchiveCutoff::from(OcspGeneralizedTime::from(
        DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
    ));
    let ext = ext.to_extension(&Name::default(), &[]).unwrap();
    assert_eq!(
        &ext.to_der().unwrap(),
        &hex!("301e06092b06010505073001060411180f32303230303130313030303030305a")[..]
    );
}

//  0:d=0  hl=2 l= 122 cons: SEQUENCE
//  2:d=1  hl=2 l=   9 prim: OBJECT            :OCSP Service Locator
// 13:d=1  hl=2 l= 109 prim: OCTET STRING      [HEX DUMP]:306B3050310B3009060355040613025553310C300\
//                                                        A060355040A0C036F7267310D300B060355040B0C\
//                                                        047465737431123010060355040B0C09746573742\
//                                                        D646565703110300E06035504030C077365727669\
//                                                        63653017301506082B0601050507300182096C6F6\
//                                                        3616C686F7374
// --
//  0:d=0  hl=2 l= 107 cons: SEQUENCE
//  2:d=1  hl=2 l=  80 cons: SEQUENCE
//  4:d=2  hl=2 l=  11 cons: SET
//  6:d=3  hl=2 l=   9 cons: SEQUENCE
//  8:d=4  hl=2 l=   3 prim: OBJECT            :countryName
// 13:d=4  hl=2 l=   2 prim: PRINTABLESTRING   :US
// 17:d=2  hl=2 l=  12 cons: SET
// 19:d=3  hl=2 l=  10 cons: SEQUENCE
// 21:d=4  hl=2 l=   3 prim: OBJECT            :organizationName
// 26:d=4  hl=2 l=   3 prim: UTF8STRING        :org
// 31:d=2  hl=2 l=  13 cons: SET
// 33:d=3  hl=2 l=  11 cons: SEQUENCE
// 35:d=4  hl=2 l=   3 prim: OBJECT            :organizationalUnitName
// 40:d=4  hl=2 l=   4 prim: UTF8STRING        :test
// 46:d=2  hl=2 l=  18 cons: SET
// 48:d=3  hl=2 l=  16 cons: SEQUENCE
// 50:d=4  hl=2 l=   3 prim: OBJECT            :organizationalUnitName
// 55:d=4  hl=2 l=   9 prim: UTF8STRING        :test-deep
// 66:d=2  hl=2 l=  16 cons: SET
// 68:d=3  hl=2 l=  14 cons: SEQUENCE
// 70:d=4  hl=2 l=   3 prim: OBJECT            :commonName
// 75:d=4  hl=2 l=   7 prim: UTF8STRING        :service
// 84:d=1  hl=2 l=  23 cons: SEQUENCE
// 86:d=2  hl=2 l=  21 cons: SEQUENCE
// 88:d=3  hl=2 l=   8 prim: OBJECT            :OCSP
// 98:d=3  hl=2 l=   9 prim: cont [ 2 ]
#[test]
fn as_extension_service_locator() {
    let ext = ServiceLocator {
        issuer: Name::from_str("CN=service,OU=test-deep,OU=test,O=org,C=US").unwrap(),
        locator: Some(AuthorityInfoAccessSyntax::from(vec![AccessDescription {
            access_method: ID_AD_OCSP,
            access_location: GeneralName::DnsName(Ia5String::new("localhost").unwrap()),
        }])),
    };
    let ext = ext.to_extension(&Name::default(), &[]).unwrap();
    assert_eq!(
        &ext.to_der().unwrap(),
        &hex!(
            "307a06092b0601050507300107046d306b3050310b300906035504061302555331\
             0c300a060355040a0c036f7267310d300b060355040b0c04746573743112301006\
             0355040b0c09746573742d646565703110300e06035504030c0773657276696365\
             3017301506082b0601050507300182096c6f63616c686f7374"
        )[..]
    );
}

//  0:d=0  hl=2 l=  47 cons: SEQUENCE
//  2:d=1  hl=2 l=   9 prim: OBJECT            :Extended OCSP Status
// 13:d=1  hl=2 l=  34 prim: OCTET STRING      [HEX DUMP]:3020301E300D06092A864886F70D01010B0500300\
//                                                        D06092A864886F70D01010B0500
// --
//  0:d=0  hl=2 l=  32 cons: SEQUENCE
//  2:d=1  hl=2 l=  30 cons: SEQUENCE
//  4:d=2  hl=2 l=  13 cons: SEQUENCE
//  6:d=3  hl=2 l=   9 prim: OBJECT            :sha256WithRSAEncryption
// 17:d=3  hl=2 l=   0 prim: NULL
// 19:d=2  hl=2 l=  13 cons: SEQUENCE
// 21:d=3  hl=2 l=   9 prim: OBJECT            :sha256WithRSAEncryption
// 32:d=3  hl=2 l=   0 prim: NULL
#[test]
fn as_extension_pref_sig_algs() {
    let ext = PreferredSignatureAlgorithms::from(vec![PreferredSignatureAlgorithm {
        sig_identifier: AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            parameters: Some(Null.into()),
        },
        cert_identifier: Some(AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            parameters: Some(Null.into()),
        }),
    }]);
    let ext = ext.to_extension(&Name::default(), &[]).unwrap();
    assert_eq!(
        &ext.to_der().unwrap(),
        &hex!(
            "302f06092b060105050730010804223020301e300d06092a864886f70d01010b05\
             00300d06092a864886f70d01010b0500"
        )[..]
    );
}
