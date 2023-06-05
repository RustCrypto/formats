use cms::{
    cert::x509::{
        ext::{pkix::name::GeneralName, Extensions},
        spki::AlgorithmIdentifier,
    },
    content_info::ContentInfo,
};
use der::{
    asn1::{GeneralizedTime, Int, OctetString},
    oid::ObjectIdentifier,
    Any, Enumerated, Sequence,
};

#[derive(Clone, Copy, Debug, Enumerated, Eq, PartialEq, PartialOrd, Ord)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum TspVersion {
    /// syntax version 0
    V1 = 1,
}

/// ```text
/// TimeStampReq ::= SEQUENCE  {
///    version               INTEGER  { v1(1) },
///    messageImprint        MessageImprint,
///    reqPolicy             TSAPolicyId              OPTIONAL,
///    nonce                 INTEGER                  OPTIONAL,
///    certReq               BOOLEAN                  DEFAULT FALSE,
///    extensions            [0] IMPLICIT Extensions  OPTIONAL  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampReq {
    pub version: TspVersion,
    pub message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    pub req_policy: Option<TSAPolicyId>,
    #[asn1(optional = "true")]
    pub nonce: Option<u64>,
    pub cert_req: bool,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<Extensions>,
}

/// ```text
/// TSAPolicyId ::= OBJECT IDENTIFIER
/// ```
pub type TSAPolicyId = ObjectIdentifier;

/// ```text
/// MessageImprint ::= SEQUENCE  {
///    hashAlgorithm                AlgorithmIdentifier,
///    hashedMessage                OCTET STRING  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct MessageImprint {
    pub hash_algorithm: AlgorithmIdentifier<Any>,
    pub hashed_message: OctetString,
}

/// ```text
/// TimeStampResp ::= SEQUENCE  {
///     status                  PKIStatusInfo,
///     timeStampToken          TimeStampToken     OPTIONAL  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampResp {
    pub status: PKIStatusInfo,
    #[asn1(optional = "true")]
    pub time_stamp_token: Option<TimeStampToken>,
}

/// ```text
/// PKIStatusInfo ::= SEQUENCE {
///     status        PKIStatus,
///     statusString  PKIFreeText     OPTIONAL,
///     failInfo      PKIFailureInfo  OPTIONAL  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PKIStatusInfo {
    pub status: PKIStatus,
    #[asn1(optional = "true")]
    pub status_string: Option<PKIFreeText>,
    #[asn1(optional = "true")]
    pub fail_info: Option<PKIFailureInfo>,
}

pub type PKIFreeText = String;

/// ```text
/// PKIStatus ::= INTEGER {
///     granted                (0),
///       -- when the PKIStatus contains the value zero a TimeStampToken, as
///          requested, is present.
///     grantedWithMods        (1),
///       -- when the PKIStatus contains the value one a TimeStampToken,
///          with modifications, is present.
///     rejection              (2),
///     waiting                (3),
///     revocationWarning      (4),
///       -- this message contains a warning that a revocation is
///       -- imminent
///     revocationNotification (5)
///       -- notification that a revocation has occurred  }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum PKIStatus {
    Granted = 0,
    GrantedWithMods = 1,
    Rejection = 2,
    Waiting = 3,
    RevocationWarning = 4,
    RevocationNotification = 5,
}

/// ```text
/// PKIFailureInfo ::= BIT STRING {
///     badAlg               (0),
///       -- unrecognized or unsupported Algorithm Identifier
///     badRequest           (2),
///       -- transaction not permitted or supported
///     badDataFormat        (5),
///       -- the data submitted has the wrong format
///     timeNotAvailable    (14),
///       -- the TSA's time source is not available
///     unacceptedPolicy    (15),
///       -- the requested TSA policy is not supported by the TSA
///     unacceptedExtension (16),
///       -- the requested extension is not supported by the TSA
///     addInfoNotAvailable (17)
///       -- the additional information requested could not be understood
///       -- or is not available
///     systemFailure       (25)
///       -- the request cannot be handled due to system failure  }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Enumerated)]
// #[asn1(type = "BIT STRING")]
#[repr(u8)]
pub enum PKIFailureInfo {
    BadAlg = 0,
    BadRequest = 2,
    BadDataFormat = 5,
    TimeNotAvailable = 14,
    UnacceptedPolicy = 15,
    UnacceptedExtension = 16,
    AddInfoNotAvailable = 17,
    SystemFailure = 25,
}

/// ```text
/// TimeStampToken ::= ContentInfo
/// ```
pub type TimeStampToken = ContentInfo;

/// ```text
/// TSTInfo ::= SEQUENCE  {
///     version                      INTEGER  { v1(1) },
///     policy                       TSAPolicyId,
///     messageImprint               MessageImprint,
///       -- MUST have the same value as the similar field in
///       -- TimeStampReq
///     serialNumber                 INTEGER,
///       -- Time-Stamping users MUST be ready to accommodate integers
///       -- up to 160 bits.
///     genTime                      GeneralizedTime,
///     accuracy                     Accuracy                 OPTIONAL,
///     ordering                     BOOLEAN             DEFAULT FALSE,
///     nonce                        INTEGER                  OPTIONAL,
///       -- MUST be present if the similar field was present
///       -- in TimeStampReq.  In that case it MUST have the same value.
///     tsa                          [0] GeneralName          OPTIONAL,
///     extensions                   [1] IMPLICIT Extensions   OPTIONAL  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TSTInfo {
    pub version: TspVersion,
    pub policy: TSAPolicyId,
    pub message_imprint: MessageImprint,
    pub serial_number: Int,
    pub gen_time: GeneralizedTime,
    #[asn1(optional = "true")]
    pub accuracy: Option<Accuracy>,
    pub ordering: bool,
    #[asn1(optional = "true")]
    pub nonce: Option<i32>,
    #[asn1(context_specific = "0", optional = "true")]
    pub tsa: Option<GeneralName>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<Extensions>,
}

/// ```text
/// Accuracy ::= SEQUENCE {
///     seconds        INTEGER              OPTIONAL,
///     millis     [0] INTEGER  (1..999)    OPTIONAL,
///     micros     [1] INTEGER  (1..999)    OPTIONAL  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Accuracy {
    #[asn1(optional = "true")]
    pub seconds: Option<u64>,
    #[asn1(context_specific = "0", optional = "true")]
    pub millis: Option<u64>,
    #[asn1(context_specific = "1", optional = "true")]
    pub micros: Option<u64>,
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn it_works() {
        assert_eq!(4, 4);
    }
}
