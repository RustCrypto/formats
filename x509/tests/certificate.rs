//! Certificate tests
use der::asn1::{BitString, UIntBytes};
use der::{Decodable, Decoder, Encodable, Tag, Tagged};
use hex_literal::hex;
use x509::Certificate;
use x509::*;

///Structure supporting deferred decoding of fields in the Certificate SEQUENCE
pub struct DeferDecodeCertificate<'a> {
    /// tbsCertificate       TBSCertificate,
    pub tbs_certificate: &'a [u8],
    /// signatureAlgorithm   AlgorithmIdentifier,
    pub signature_algorithm: &'a [u8],
    /// signature            BIT STRING
    pub signature: &'a [u8],
}

impl<'a> Decodable<'a> for DeferDecodeCertificate<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<DeferDecodeCertificate<'a>> {
        decoder.sequence(|decoder| {
            let tbs_certificate = decoder.tlv_slice()?;
            let signature_algorithm = decoder.tlv_slice()?;
            let signature = decoder.tlv_slice()?;
            Ok(Self {
                tbs_certificate,
                signature_algorithm,
                signature,
            })
        })
    }
}

///Structure supporting deferred decoding of fields in the TBSCertificate SEQUENCE
pub struct DeferDecodeTBSCertificate<'a> {
    /// Decoded field
    pub version: u8,
    /// Defer decoded field
    pub serial_number: &'a [u8],
    /// Defer decoded field
    pub signature: &'a [u8],
    /// Defer decoded field
    pub issuer: &'a [u8],
    /// Defer decoded field
    pub validity: &'a [u8],
    /// Defer decoded field
    pub subject: &'a [u8],
    /// Defer decoded field
    pub subject_public_key_info: &'a [u8],
    /// Decoded field (never present)
    pub issuer_unique_id: Option<BitString<'a>>,
    /// Decoded field (never present)
    pub subject_unique_id: Option<BitString<'a>>,
    /// Defer decoded field
    pub extensions: &'a [u8],
}

impl<'a> Decodable<'a> for DeferDecodeTBSCertificate<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<DeferDecodeTBSCertificate<'a>> {
        decoder.sequence(|decoder| {
            let version =
                ::der::asn1::ContextSpecific::decode_explicit(decoder, ::der::TagNumber::N0)?
                    .map(|cs| cs.value)
                    .unwrap_or_else(default_zero_u8);
            let serial_number = decoder.tlv_slice()?;
            let signature = decoder.tlv_slice()?;
            let issuer = decoder.tlv_slice()?;
            let validity = decoder.tlv_slice()?;
            let subject = decoder.tlv_slice()?;
            let subject_public_key_info = decoder.tlv_slice()?;
            let issuer_unique_id = decoder.decode()?;
            let subject_unique_id = decoder.decode()?;
            let extensions = decoder.tlv_slice()?;
            Ok(Self {
                version,
                serial_number,
                signature,
                issuer,
                validity,
                subject,
                subject_public_key_info,
                issuer_unique_id,
                subject_unique_id,
                extensions,
            })
        })
    }
}

#[test]
fn reencode_cert() {
    let der_encoded_cert =
        include_bytes!("examples/026EDA6FA1EDFA8C253936C75B5EEBD954BFF452.fake.der");
    let defer_cert = DeferDecodeCertificate::from_der(der_encoded_cert).unwrap();

    let parsed_tbs = TBSCertificate::from_der(defer_cert.tbs_certificate).unwrap();
    let reencoded_tbs = parsed_tbs.to_vec().unwrap();
    assert_eq!(defer_cert.tbs_certificate, reencoded_tbs);

    let parsed_sigalg = AlgorithmIdentifier::from_der(defer_cert.signature_algorithm).unwrap();
    let reencoded_sigalg = parsed_sigalg.to_vec().unwrap();
    assert_eq!(defer_cert.signature_algorithm, reencoded_sigalg);

    let parsed_sig = BitString::from_der(defer_cert.signature).unwrap();
    let reencoded_sig = parsed_sig.to_vec().unwrap();
    assert_eq!(defer_cert.signature, reencoded_sig);

    let parsed_coverage_tbs =
        DeferDecodeTBSCertificate::from_der(defer_cert.tbs_certificate).unwrap();

    // TODO - defer decode then reencode version field

    let encoded_serial = parsed_tbs.serial_number.to_vec().unwrap();
    assert_eq!(parsed_coverage_tbs.serial_number, encoded_serial);

    let encoded_signature = parsed_tbs.signature.to_vec().unwrap();
    assert_eq!(parsed_coverage_tbs.signature, encoded_signature);

    let encoded_issuer = parsed_tbs.issuer.to_vec().unwrap();
    assert_eq!(parsed_coverage_tbs.issuer, encoded_issuer);

    let encoded_validity = parsed_tbs.validity.to_vec().unwrap();
    assert_eq!(parsed_coverage_tbs.validity, encoded_validity);

    let encoded_subject = parsed_tbs.subject.to_vec().unwrap();
    assert_eq!(parsed_coverage_tbs.subject, encoded_subject);

    let encoded_subject_public_key_info = parsed_tbs.subject_public_key_info.to_vec().unwrap();
    assert_eq!(
        parsed_coverage_tbs.subject_public_key_info,
        encoded_subject_public_key_info
    );

    // TODO - either encode as context specific or decode to sequence. for know lop off context
    // specific tag and length
    let encoded_extensions = parsed_tbs.extensions.to_vec().unwrap();
    assert_eq!(&parsed_coverage_tbs.extensions[4..], encoded_extensions);
}

#[test]
fn decode_oversized_oids() {
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
    let enc_oid = o1.to_vec().unwrap();
    assert_eq!(
        &hex!("06252B060104018237150885C8B86B87AFF00383A99F3C96C34081ADE6494D82B0E91D85B2873D"),
        enc_oid.as_slice()
    );
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
    println!("{:?}", cert);
    let exts = cert.tbs_certificate.extensions.unwrap();
    let i = exts.iter();
    let mut counter = 0;
    for ext in i {
        // TODO - parse and compare extension values
        if 0 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.15");
            assert_eq!(ext.critical, true);
        } else if 1 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.19");
            assert_eq!(ext.critical, true);
        } else if 2 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.33");
            assert_eq!(ext.critical, false);
        } else if 3 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.32");
            assert_eq!(ext.critical, false);
        } else if 4 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.14");
            assert_eq!(ext.critical, false);
        } else if 5 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.31");
            assert_eq!(ext.critical, false);
        } else if 6 == counter {
            assert_eq!(ext.extn_id.to_string(), "1.3.6.1.5.5.7.1.11");
            assert_eq!(ext.critical, false);
        } else if 7 == counter {
            assert_eq!(ext.extn_id.to_string(), "1.3.6.1.5.5.7.1.1");
            assert_eq!(ext.critical, false);
        } else if 8 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.54");
            assert_eq!(ext.critical, false);
        } else if 9 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.35");
            assert_eq!(ext.critical, false);
        }

        counter += 1;
    }

    let result = Certificate::from_der(der_encoded_cert);
    let cert: Certificate = result.unwrap();

    assert_eq!(cert.tbs_certificate.version, 2);
    let target_serial: [u8; 16] = [
        0x7F, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x49, 0xCF, 0x70, 0x66, 0x4D, 0x00, 0x00, 0x00,
        0x02,
    ];
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
                assert_eq!(atav.value.printable_string().unwrap().to_string(), "Mock");
            } else if 2 == counter {
                assert_eq!(atav.oid.to_string(), "2.5.4.10");
                assert_eq!(
                    atav.value.utf8_string().unwrap().to_string(),
                    "IdenTrust Services LLC"
                );
            } else if 3 == counter {
                assert_eq!(atav.oid.to_string(), "2.5.4.3");
                assert_eq!(
                    atav.value.utf8_string().unwrap().to_string(),
                    "PTE IdenTrust Global Common Root CA 1"
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
        1416524490
    );
    assert_eq!(
        cert.tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
        1516628593
    );

    counter = 0;
    let i = cert.tbs_certificate.subject.iter();
    for rdn in i {
        let i1 = rdn.iter();
        for atav in i1 {
            // Yes, this cert features RDNs encoded in reverse order
            if 0 == counter {
                assert_eq!(atav.oid.to_string(), "2.5.4.3");
                assert_eq!(
                    atav.value.printable_string().unwrap().to_string(),
                    "Test Federal Bridge CA"
                );
            } else if 1 == counter {
                assert_eq!(atav.oid.to_string(), "2.5.4.11");
                assert_eq!(
                    atav.value.printable_string().unwrap().to_string(),
                    "TestFPKI"
                );
            } else if 2 == counter {
                assert_eq!(atav.oid.to_string(), "2.5.4.10");
                assert_eq!(
                    atav.value.printable_string().unwrap().to_string(),
                    "U.S. Government"
                );
            } else if 3 == counter {
                assert_eq!(atav.oid.to_string(), "2.5.4.6");
                assert_eq!(atav.value.printable_string().unwrap().to_string(), "US");
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
            assert_eq!(ext.extn_id.to_string(), "2.5.29.15");
            assert_eq!(ext.critical, true);
        } else if 1 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.19");
            assert_eq!(ext.critical, true);
        } else if 2 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.33");
            assert_eq!(ext.critical, false);
        } else if 3 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.32");
            assert_eq!(ext.critical, false);
        } else if 4 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.14");
            assert_eq!(ext.critical, false);
        } else if 5 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.31");
            assert_eq!(ext.critical, false);
        } else if 6 == counter {
            assert_eq!(ext.extn_id.to_string(), "1.3.6.1.5.5.7.1.11");
            assert_eq!(ext.critical, false);
        } else if 7 == counter {
            assert_eq!(ext.extn_id.to_string(), "1.3.6.1.5.5.7.1.1");
            assert_eq!(ext.critical, false);
        } else if 8 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.54");
            assert_eq!(ext.critical, false);
        } else if 9 == counter {
            assert_eq!(ext.extn_id.to_string(), "2.5.29.35");
            assert_eq!(ext.critical, false);
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

    assert_eq!(
        &hex!("2A892F357BF3EF19E1211986106803FA18E66237802F1B1B0C6756CE678DB01D72CD0A4EB7171C2CDDF110ACD38AA65C35699E869C219AD7550AA4F287BB784F72EF8C9EA0E3DD103EFE5BF182EA36FFBCB45AAE65840263680534789C4F3215AF5454AD48CBC4B7A881E0135401A0BD5A849C11101DD1C66178E762C00DF59DD50F8DE9ED46FC6A0D742AE5697D87DD08DAC5291A75FB13C82FF2865C9E36799EA726137E1814E6A878C9532E8FC3D0A2A942D1CCC668FFCEAC255E6002FDE5ACDF2CE47556BB141C3A797A4BFDB673F6F1C229D7914FFEEF1505EE36F8038137D1B8F90106994BAB3E6FF0F60360A2E32F7A30B7ECEC1502DF3CC725BD6E436BA8F96A1847C9CEBB3F5A5906472292501D59BE1A98475BB1F30B677FAA8A45E351640C85B1B22661D33BD23EC6C0CA33DDD79E1120C7FC869EC4D0175ADB4A258AEAC5E8D2F0F578B8BF4B2C5DCC3269768AAA5B9E26D0592C5BB09C702C72E0A60F66D3EEB2B4983279634D59B0A2011B0E26AE796CC95D3243DF49615434E5CC06C374C3F936C005D360CAE6101F3AE7E97E29A157F5020770D4648D7877EBF8248CF3F3E68F9957A36F92D50616F2C60D3842327EF9BC0312CFF03A48C78E97254C2ADEADCA05069168443D833831FF66295A2EED685F164F1DBE01F8C897E1F63D42851682CBEE7B5A64D7BA2923D33644DBF1F7B3EDCE996F9928F043"),
        cert.signature.raw_bytes()
    );
}
