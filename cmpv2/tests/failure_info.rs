//! `PKIFailureInfo` tests.

use cmpv2::body::PkiBody;
use cmpv2::message::PkiMessage;
use cmpv2::status::{PkiFailureInfo, PkiFailureInfoValues};
use der::{Decode, Encode};
use hex_literal::hex;

/// `PKIFailureInfo ::= BIT STRING { badAlg (0), badMessageCheck (1), badRequest (2), ... }`:
/// each named value is the bit at that position.
#[test]
fn failure_info_bit_positions() {
    let cases: [(PkiFailureInfoValues, &[u8]); 6] = [
        (PkiFailureInfoValues::BadAlg, &hex!("03020780")),
        (PkiFailureInfoValues::BadMessageCheck, &hex!("03020640")),
        (PkiFailureInfoValues::BadRequest, &hex!("03020520")),
        (PkiFailureInfoValues::WrongAuthority, &hex!("03020102")),
        (PkiFailureInfoValues::BadPOP, &hex!("0303060040")),
        (
            PkiFailureInfoValues::DuplicateCertReq,
            &hex!("03050500000020"),
        ),
    ];
    for (value, der) in cases {
        let info = PkiFailureInfo::from(value);
        assert_eq!(info.to_der().unwrap(), der, "{value:?}");
        assert_eq!(PkiFailureInfo::from_der(der).unwrap(), info, "{value:?}");
    }
}

/// The failInfo in `failed_kur_rsp_01.bin` (an OpenSSL error response, statusString
/// "wrong certid") is `03 02 05 20`: bit 2, badRequest.
#[test]
fn failure_info_from_openssl_response() {
    let message = PkiMessage::from_der(include_bytes!("examples/failed_kur_rsp_01.bin")).unwrap();
    let PkiBody::Error(err) = &message.body else {
        panic!("expected error");
    };
    let fail_info = err.pki_status_info.fail_info.unwrap();
    assert_eq!(
        fail_info,
        PkiFailureInfo::from(PkiFailureInfoValues::BadRequest)
    );
}
