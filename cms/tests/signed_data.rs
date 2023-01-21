//! SignedData tests

use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfos};
use der::{AnyRef, Decode, Encode, ErrorKind, Tag};

#[test]
fn trust_list_sd_test() {
    let der_signed_data_in_ci = include_bytes!("examples/authroot.stl.sd");
    let _ci = SignedData::from_der(der_signed_data_in_ci).unwrap();
}
#[test]
fn trust_list_test() {
    let der_signed_data_in_ci = include_bytes!("examples/authroot.stl");
    let ci = ContentInfo::from_der(der_signed_data_in_ci).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_SIGNED_DATA);

    // re-encode the AnyRef to get the SignedData bytes
    let bytes = ci.content.to_vec().unwrap();

    // parse as SignedData then re-encode
    let sd = SignedData::from_der(bytes.as_slice()).unwrap();
    let reencoded_signed_data = sd.to_vec().unwrap();
    assert_eq!(
        sd.encap_content_info.econtent_type.to_string(),
        "1.3.6.1.4.1.311.10.1"
    );

    // assemble a new ContentInfo and encode it
    let ci2 = ContentInfo {
        content_type: ci.content_type,
        content: AnyRef::try_from(reencoded_signed_data.as_slice())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let reencoded_der_signed_data_in_ci = ci2.to_vec().unwrap();

    // should match the original
    assert_eq!(reencoded_der_signed_data_in_ci, der_signed_data_in_ci)
}

#[test]
fn reencode_signed_data_test() {
    // read SignedData object created via:
    //  openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365
    //  openssl cms -sign -in data.txt -nodetach -inkey key.pem -signer cert.pem -out sd.cms -outform DER
    let der_signed_data_in_ci = include_bytes!("examples/sd.cms");
    let ci = ContentInfo::from_der(der_signed_data_in_ci).unwrap();
    assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_SIGNED_DATA);

    // re-encode the AnyRef to get the SignedData bytes
    let bytes = ci.content.to_vec().unwrap();

    // parse as SignedData then re-encode
    let sd = SignedData::from_der(bytes.as_slice()).unwrap();
    let reencoded_signed_data = sd.to_vec().unwrap();

    // assemble a new ContentInfo and encode it
    let ci2 = ContentInfo {
        content_type: ci.content_type,
        content: AnyRef::try_from(reencoded_signed_data.as_slice())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let reencoded_der_signed_data_in_ci = ci2.to_vec().unwrap();

    // should match the original
    assert_eq!(reencoded_der_signed_data_in_ci, der_signed_data_in_ci)
}

#[test]
fn misencoded_signer_infos_tests() {
    // TODO the error contents need work

    let der_signer_infos = include_bytes!("examples/signer_info_explicit_attrs.bin");
    let si = SignerInfos::from_der(der_signer_infos);
    assert!(si.is_err());
    let e = si.err().unwrap();
    assert_eq!(
        e.kind(),
        ErrorKind::TagUnexpected {
            expected: Some(Tag::Sequence),
            actual: Tag::Set
        }
    );
    // this probably ought feature the offset of the explicit tag
    //assert_eq!(e.position(), Some(Length::new(185)));

    let der_signer_infos = include_bytes!("examples/signer_info_sequence_not_set.bin");
    let si = SignerInfos::from_der(der_signer_infos);
    assert!(si.is_err());
    let e = si.err().unwrap();
    assert_eq!(
        e.kind(),
        ErrorKind::TagUnexpected {
            expected: Some(Tag::Set),
            actual: Tag::Sequence
        }
    );
    // this probably ought feature the offset of the explicit tag
    //assert_eq!(e.position(), Some(Length::ZERO));
}

#[test]
fn misencoded_signed_data_tests() {}
