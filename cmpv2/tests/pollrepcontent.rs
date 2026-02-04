use cmpv2::poll::{PollRepContent, PollRepContentInner};
use der::{Encode, asn1::Int};
use hex_literal::hex;

/// Verify that PollRepContent is properly encoded, i.e. according to RFC 4210 the minimal example should be encoded as follows:
///     <30 08 30 06 02 01 00 02 01 3C>
///   0   8: SEQUENCE {
///     <30 06 02 01 00 02 01 3C>
///   2   6:   SEQUENCE {
///     <02 01 00>
///   4   1:     INTEGER 0
///     <02 01 3C>
///   7   1:     INTEGER 60
///        :     }
///        :   }
#[test]
fn test_encoding() {
    let expected = hex!(
        "30 08
         30 06
         02 01 00
         02 01 3c"
    );
    let prc = PollRepContent(
        [PollRepContentInner {
            cert_req_id: Int::new(&[0]).unwrap(),
            check_after: 60,
            reason: None,
        }]
        .to_vec(),
    );

    let prc_encoded = prc.to_der().unwrap();
    assert_eq!(prc_encoded, expected);
}

/// Verify that indexing of PollRepContent is nice. ;-)
/// This basically makes sure that core::ops::Index is implemented, so we can use `prc[0]` instead of `prc.0[0]`.
#[test]
fn test_indexing() {
    let prc = PollRepContent(
        [PollRepContentInner {
            cert_req_id: Int::new(&[0]).unwrap(),
            check_after: 60,
            reason: None,
        }]
        .to_vec(),
    );
    assert_eq!(prc[0].check_after, 60);
}

/// Verify that we can create `PollRepContent` from a `Vec<PollRepContentInner>`.
#[test]
fn test_from_inner() {
    let inner_content_1 = PollRepContentInner {
        cert_req_id: Int::new(&[1]).unwrap(),
        check_after: 11,
        reason: None,
    };
    let inner_content_2 = PollRepContentInner {
        cert_req_id: Int::new(&[2]).unwrap(),
        check_after: 22,
        reason: None,
    };
    let prc = PollRepContent::from(vec![inner_content_1, inner_content_2]);
    assert_eq!(prc[0].check_after, 11);
    assert_eq!(prc[1].check_after, 22);
}
