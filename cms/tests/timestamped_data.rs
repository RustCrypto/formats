//! TimeStampedData / EvidenceRecord tests.
//!
//! RFC 4998 (ERS) and RFC 5544 (TimeStampedData) define their ASN.1 modules with
//! `DEFINITIONS IMPLICIT TAGS`, so their context-specific tags replace the inner type's tag.

use cms::timestamped_data::{Evidence, EvidenceRecord};
use der::{Decode, Encode};
use hex_literal::hex;

/// An `EvidenceRecord` encoded by pyasn1 from the RFC 4998 ASN.1 module, with
/// `encryptionInfo [1]` and one `ArchiveTimeStamp` carrying `digestAlgorithm [0]` and
/// `reducedHashtree [2]`.
const EVIDENCE_RECORD: &[u8] = &hex!(
    "3064020101300d300b0609608648016503040201a10606022a030500304830463044a00b0609608648016503040201"
    "a224302204201111111111111111111111111111111111111111111111111111111111111111"
    "300f06092a864886f70d010702a0020500"
);

#[test]
fn evidence_record_implicit_tags_round_trip() {
    let record = EvidenceRecord::from_der(EVIDENCE_RECORD).unwrap();
    assert!(record.encryption_info.is_some());
    assert_eq!(record.archive_timestamp_sequence.len(), 1);
    assert_eq!(record.archive_timestamp_sequence[0].len(), 1);
    assert_eq!(record.to_der().unwrap(), EVIDENCE_RECORD);
}

#[test]
fn evidence_choice_implicit_tags_round_trip() {
    // ersEvidence [1] EvidenceRecord: the SEQUENCE tag (0x30) is replaced by [1] (0xa1).
    let mut ers = EVIDENCE_RECORD.to_vec();
    ers[0] = 0xa1;
    let evidence = Evidence::from_der(&ers).unwrap();
    assert!(matches!(evidence, Evidence::ErsEvidence(_)));
    assert_eq!(evidence.to_der().unwrap(), ers);
}
