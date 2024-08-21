use cms::authenveloped_data::AuthEnvelopedData;
use cms::content_info::{CmsVersion, ContentInfo};
use cms::enveloped_data::{EnvelopedData, RecipientIdentifier, RecipientInfo};
use cms::kemri::ID_ORI_KEM;
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use hex_literal::hex;

#[test]
fn kemri_auth_enveloped_data() {
    let data = include_bytes!("examples/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_kemri_auth.der");
    let ci = ContentInfo::from_der(data).unwrap();
    let aed = AuthEnvelopedData::from_der(&ci.content.to_der().unwrap()).unwrap();
    for ri in aed.recip_infos.0.iter() {
        if let RecipientInfo::Ori(ori) = ri {
            let ori_value = ori.ori_value.to_der().unwrap();
            assert_eq!(ori.ori_type, ID_ORI_KEM);
            let kemri = cms::kemri::KemRecipientInfo::from_der(&ori_value).unwrap();
            let reenc = kemri.to_der().unwrap();
            assert_eq!(reenc, ori_value);
        } else {
            panic!("Unexpected recipient info type");
        }
    }
}

#[test]
fn kemri_enveloped_data() {
    let data = include_bytes!(
        "examples/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_kemri_id-alg-hkdf-with-sha256.der"
    );
    let ci = ContentInfo::from_der(data).unwrap();
    let ed = EnvelopedData::from_der(&ci.content.to_der().unwrap()).unwrap();
    for ri in ed.recip_infos.0.iter() {
        if let RecipientInfo::Ori(ori) = ri {
            let ori_value = ori.ori_value.to_der().unwrap();
            assert_eq!(ori.ori_type, ID_ORI_KEM);
            let kemri = cms::kemri::KemRecipientInfo::from_der(&ori_value).unwrap();
            let reenc = kemri.to_der().unwrap();
            assert_eq!(reenc, ori_value);
        } else {
            panic!("Unexpected recipient info type");
        }
    }
}

#[test]
fn kemri_enveloped_data_ukm() {
    let data = include_bytes!("examples/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_kemri_ukm.der");
    let ci = ContentInfo::from_der(data).unwrap();
    let ed = EnvelopedData::from_der(&ci.content.to_der().unwrap()).unwrap();
    for ri in ed.recip_infos.0.iter() {
        if let RecipientInfo::Ori(ori) = ri {
            let ori_value = ori.ori_value.to_der().unwrap();
            assert_eq!(ori.ori_type, ID_ORI_KEM);
            let kemri = cms::kemri::KemRecipientInfo::from_der(&ori_value).unwrap();

            assert_eq!(kemri.version, CmsVersion::V0);

            if let RecipientIdentifier::SubjectKeyIdentifier(skid) = &kemri.rid {
                let rid = hex!("B17B1D588029CA33201230C50CE75F57E6AAC916");
                assert_eq!(skid.0.as_bytes(), rid);
            } else {
                panic!("Unexpected recipient identifier type");
            }

            pub const ML_KEM_512_IPD: ObjectIdentifier =
                ObjectIdentifier::new_unwrap("1.3.6.1.4.1.22554.5.6.1");
            assert_eq!(kemri.kem.oid, ML_KEM_512_IPD);

            pub const ID_KMAC128: ObjectIdentifier =
                ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.21");
            assert_eq!(kemri.kdf.oid, ID_KMAC128);

            assert_eq!(
                kemri.ukm.clone().unwrap().as_bytes(),
                "This is some User Keying Material\n".as_bytes()
            );

            let enc_key = hex!(
                "B9F524FB59CAD7420127B1FEA61D5F15F5BED04078AB7A3BEDD501B6B215D6AA417BDA0303C78A6C"
            );
            assert_eq!(kemri.encrypted_key.as_bytes(), enc_key);

            let reenc = kemri.to_der().unwrap();
            assert_eq!(reenc, ori_value);
        } else {
            panic!("Unexpected recipient info type");
        }
    }
}
