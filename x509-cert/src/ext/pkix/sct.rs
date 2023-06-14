#![cfg(feature = "sct")]

use const_oid::{db::rfc6962, AssociatedOid, ObjectIdentifier};
use der::asn1::OctetString;
//TODO: Remove use::alloc::format explicit use required by the #[derive(TlsSerialize)] on SignagureAndHashAlgorithms
//once the PR: https://github.com/RustCrypto/formats/pull/1103 is merged
// use std::format;
use alloc::{format, vec::Vec};
use tls_codec::{
    DeserializeBytes, Serialize, Size, TlsDeserializeBytes, TlsSerialize, TlsSize, TlsVecU16,
};

// TODO: Review what should be pub
// TODO: Update docs
// TODO: Review naming

// TODO: Remove this constant when const_oid version is updated which includes this PR:
// https://github.com/RustCrypto/formats/pull/1094
// TODO: Do not publish this as pub, this is for testing only
/// OID for signed certificate timestamps extension
// pub const CT_PRECERT_SCTS: ObjectIdentifier =
//     ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");

#[derive(Debug, PartialEq)]
pub struct SignedCertificateTimestampList(OctetString);

impl AssociatedOid for SignedCertificateTimestampList {
    const OID: ObjectIdentifier = rfc6962::CT_PRECERT_SCTS;
}

impl_newtype!(SignedCertificateTimestampList, OctetString);
impl_extension!(SignedCertificateTimestampList, critical = false);

#[derive(PartialEq, Debug)]
pub enum Error {
    Der(der::Error),
    Tls(tls_codec::Error),
}

impl From<der::Error> for Error {
    fn from(value: der::Error) -> Self {
        Error::Der(value)
    }
}

impl From<tls_codec::Error> for Error {
    fn from(value: tls_codec::Error) -> Self {
        Error::Tls(value)
    }
}

impl SignedCertificateTimestampList {
    /// Creates a new [SignedCertificateTimestamp] from a slice of [SerializedSct]s
    pub fn new(serialized_scts: &[SerializedSct]) -> Result<Self, Error> {
        let mut result: Vec<u8> = Vec::new();
        for timestamp in serialized_scts {
            let mut buffer: Vec<u8> = Vec::with_capacity(timestamp.tls_serialized_len());
            let bytes_written = timestamp.tls_serialize(&mut buffer)?;
            assert!(bytes_written == timestamp.tls_serialized_len());
            result.extend(buffer);
        }
        let tls_vec = TlsVecU16::<u8>::new(result);
        let mut buffer: Vec<u8> = Vec::with_capacity(tls_vec.tls_serialized_len());
        let bytes_written = tls_vec.tls_serialize(&mut buffer)?;
        assert!(bytes_written == tls_vec.tls_serialized_len());
        Ok(SignedCertificateTimestampList(OctetString::new(buffer)?))
    }

    /// Parses the encoded [SerializedSct]s and returns a Vec containing them
    pub fn parse_timestamps(&self) -> Result<Vec<SerializedSct>, Error> {
        let (tls_vec, rest) = TlsVecU16::<u8>::tls_deserialize(self.0.as_bytes())?;
        if !rest.is_empty() {
            return Err(tls_codec::Error::TrailingData)?;
        }
        let mut bytes = tls_vec.as_slice();
        let mut result = Vec::new();
        while !bytes.is_empty() {
            let (serialized_sct, rest) = SerializedSct::tls_deserialize(&bytes)?;
            result.push(serialized_sct);
            bytes = rest;
        }
        Ok(result)
    }
}

#[derive(PartialEq, Debug, TlsDeserializeBytes, TlsSerialize, TlsSize)]
pub struct SerializedSct {
    data: TlsVecU16<u8>,
}

impl SerializedSct {
    pub fn new(timestamp: SignedCertificateTimestamp) -> Result<Self, tls_codec::Error> {
        let mut buffer: Vec<u8> = Vec::with_capacity(timestamp.tls_serialized_len());
        let bytes_written = timestamp.tls_serialize(&mut buffer)?;
        assert!(bytes_written == timestamp.tls_serialized_len());
        Ok(SerializedSct {
            data: TlsVecU16::from_slice(&buffer),
        })
    }

    pub fn parse_timestamp(&self) -> Result<SignedCertificateTimestamp, Error> {
        let (sct, rest) = SignedCertificateTimestamp::tls_deserialize(self.data.as_slice())?;
        if !rest.is_empty() {
            return Err(tls_codec::Error::TrailingData)?;
        }
        Ok(sct)
    }
}

#[derive(PartialEq, Debug, TlsDeserializeBytes, TlsSerialize, TlsSize)]
pub struct SignedCertificateTimestamp {
    version: Version,
    log_id: LogId,
    timestamp: u64,
    extensions: TlsVecU16<u8>,
    sign: DigitallySigned,
}

#[derive(PartialEq, Debug, TlsDeserializeBytes, TlsSerialize, TlsSize)]
#[repr(u8)]
pub enum Version {
    V1 = 0,
}

#[derive(PartialEq, Debug, TlsDeserializeBytes, TlsSerialize, TlsSize)]
pub struct LogId {
    key_id: [u8; 32],
}

#[derive(PartialEq, Debug, TlsDeserializeBytes, TlsSerialize, TlsSize)]
pub struct DigitallySigned {
    /// [SignatureAndHashAlgorithm] of the struct
    pub algorithm: SignatureAndHashAlgorithm,
    /// Signature of the struct
    pub signature: TlsVecU16<u8>,
}

#[derive(PartialEq, Debug, TlsDeserializeBytes, TlsSerialize, TlsSize)]
pub struct SignatureAndHashAlgorithm {
    hash: HashAlgorithm,
    signature: SignatureAlgorithm,
}

#[derive(PartialEq, Debug, TlsDeserializeBytes, TlsSerialize, TlsSize)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    /// Anonymous signature algorithm
    Anonymous = 0,
    /// RSA signature algorithm
    Rsa = 1,
    /// DSA signature algorithm
    Dsa = 2,
    /// ECDSA signature algorithm
    Ecdsa = 3,
    /// ED25519 signature algorithm
    Ed25519 = 7,
    /// ED448 signature algorithm
    Ed448 = 8,
}

#[derive(PartialEq, Debug, TlsDeserializeBytes, TlsSerialize, TlsSize)]
#[repr(u8)]
pub enum HashAlgorithm {
    /// No algorithm
    None = 0,
    /// MD5 algorithm
    Md5 = 1,
    /// SHA1 algorithm
    Sha1 = 2,
    /// SHA224 algorithm
    Sha224 = 3,
    /// SHA256 algorithm
    Sha256 = 4,
    /// SHA384 algorithm
    Sha384 = 5,
    /// SHA512 algorithm
    Sha512 = 6,
    /// Intrinsic algorithm
    Intrinsic = 8,
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use der::{asn1::OctetString, Decode, Encode};
    use tls_codec::{DeserializeBytes, Serialize, Size, TlsVecU16};

    use crate::ext::pkix::sct::LogId;

    use super::{
        DigitallySigned, HashAlgorithm, SerializedSct, SignatureAlgorithm,
        SignatureAndHashAlgorithm, SignedCertificateTimestamp, SignedCertificateTimestampList,
        Version,
    };

    fn run_deserialization_test<'a, T: DeserializeBytes + PartialEq + core::fmt::Debug>(
        bytes: &'a [u8],
        expected_result: Result<(T, &[u8]), tls_codec::Error>,
    ) -> Result<(T, &'a [u8]), tls_codec::Error> {
        let actual_result = T::tls_deserialize(&bytes);
        assert_eq!(actual_result, expected_result);
        actual_result
    }

    #[test]
    fn test_hash_algorithm_deserialization() {
        let bytes = [0, 1, 2, 3, 4, 5, 6, 8];

        let result = run_deserialization_test(
            &bytes,
            Ok((HashAlgorithm::None, [1, 2, 3, 4, 5, 6, 8].as_slice())),
        );
        let result = run_deserialization_test(
            &result.unwrap().1,
            Ok((HashAlgorithm::Md5, [2, 3, 4, 5, 6, 8].as_slice())),
        );
        let result = run_deserialization_test(
            &result.unwrap().1,
            Ok((HashAlgorithm::Sha1, [3, 4, 5, 6, 8].as_slice())),
        );
        let result = run_deserialization_test(
            &result.unwrap().1,
            Ok((HashAlgorithm::Sha224, [4, 5, 6, 8].as_slice())),
        );
        let result = run_deserialization_test(
            &result.unwrap().1,
            Ok((HashAlgorithm::Sha256, [5, 6, 8].as_slice())),
        );
        let result = run_deserialization_test(
            &result.unwrap().1,
            Ok((HashAlgorithm::Sha384, [6, 8].as_slice())),
        );
        let result = run_deserialization_test(
            &result.unwrap().1,
            Ok((HashAlgorithm::Sha512, [8].as_slice())),
        );
        let result = run_deserialization_test(
            &result.unwrap().1,
            Ok((HashAlgorithm::Intrinsic, [].as_slice())),
        );
        let _ = run_deserialization_test::<HashAlgorithm>(
            &result.unwrap().1,
            Err(tls_codec::Error::EndOfStream),
        );
        let _ =
            run_deserialization_test::<HashAlgorithm>(&[7], Err(tls_codec::Error::UnknownValue(7)));
        let _ =
            run_deserialization_test::<HashAlgorithm>(&[9], Err(tls_codec::Error::UnknownValue(9)));
    }

    #[test]
    fn test_hash_algorithm_serialization() {
        fn run_test(hash_algorithm: HashAlgorithm, expected_int: u8) {
            let mut buffer = Vec::with_capacity(hash_algorithm.tls_serialized_len());
            let result = hash_algorithm.tls_serialize(&mut buffer);
            assert_eq!([expected_int], buffer[..1]);
            assert_eq!(result, Ok(1));
        }

        run_test(HashAlgorithm::None, 0);
        run_test(HashAlgorithm::Md5, 1);
        run_test(HashAlgorithm::Sha1, 2);
        run_test(HashAlgorithm::Sha224, 3);
        run_test(HashAlgorithm::Sha256, 4);
        run_test(HashAlgorithm::Sha384, 5);
        run_test(HashAlgorithm::Sha512, 6);
        run_test(HashAlgorithm::Intrinsic, 8);
    }

    #[test]
    fn test_signature_algorithm_deserialization() {
        let bytes = [0, 1, 2, 3, 7, 8];

        let result = run_deserialization_test(
            &bytes,
            Ok((SignatureAlgorithm::Anonymous, [1, 2, 3, 7, 8].as_slice())),
        );
        let result = run_deserialization_test(
            &result.unwrap().1,
            Ok((SignatureAlgorithm::Rsa, [2, 3, 7, 8].as_slice())),
        );
        let result = run_deserialization_test(
            &result.unwrap().1,
            Ok((SignatureAlgorithm::Dsa, [3, 7, 8].as_slice())),
        );
        let result = run_deserialization_test(
            &result.unwrap().1,
            Ok((SignatureAlgorithm::Ecdsa, [7, 8].as_slice())),
        );
        let result = run_deserialization_test(
            &result.unwrap().1,
            Ok((SignatureAlgorithm::Ed25519, [8].as_slice())),
        );
        let result = run_deserialization_test(
            &result.unwrap().1,
            Ok((SignatureAlgorithm::Ed448, [].as_slice())),
        );
        let _ = run_deserialization_test::<SignatureAlgorithm>(
            &result.unwrap().1,
            Err(tls_codec::Error::EndOfStream),
        );
        let _ = run_deserialization_test::<SignatureAlgorithm>(
            &[4],
            Err(tls_codec::Error::UnknownValue(4)),
        );
        let _ = run_deserialization_test::<SignatureAlgorithm>(
            &[5],
            Err(tls_codec::Error::UnknownValue(5)),
        );
        let _ = run_deserialization_test::<SignatureAlgorithm>(
            &[6],
            Err(tls_codec::Error::UnknownValue(6)),
        );
        let _ = run_deserialization_test::<SignatureAlgorithm>(
            &[9],
            Err(tls_codec::Error::UnknownValue(9)),
        );
    }

    #[test]
    fn test_signature_algorithm_serialization() {
        fn run_test(signature_algorithm: SignatureAlgorithm, expected_int: u8) {
            let mut buffer = Vec::with_capacity(signature_algorithm.tls_serialized_len());
            let result = signature_algorithm.tls_serialize(&mut buffer);
            assert_eq!([expected_int], buffer[..1]);
            assert_eq!(result, Ok(1));
        }

        run_test(SignatureAlgorithm::Anonymous, 0);
        run_test(SignatureAlgorithm::Rsa, 1);
        run_test(SignatureAlgorithm::Dsa, 2);
        run_test(SignatureAlgorithm::Ecdsa, 3);
        run_test(SignatureAlgorithm::Ed25519, 7);
        run_test(SignatureAlgorithm::Ed448, 8);
    }

    #[test]
    fn test_signature_and_hash_algorithm_deserialization() {
        let bytes = [4, 3, 2, 1];

        let result = run_deserialization_test(
            &bytes,
            Ok((
                SignatureAndHashAlgorithm {
                    hash: HashAlgorithm::Sha256,
                    signature: SignatureAlgorithm::Ecdsa,
                },
                [2, 1].as_slice(),
            )),
        );

        let _ = run_deserialization_test(
            &result.unwrap().1,
            Ok((
                SignatureAndHashAlgorithm {
                    hash: HashAlgorithm::Sha1,
                    signature: SignatureAlgorithm::Rsa,
                },
                [].as_slice(),
            )),
        );
    }

    #[test]
    fn test_signature_and_hash_algorithm_serialization() {
        fn run_test(
            algorithm: SignatureAndHashAlgorithm,
            expected_hash_int: u8,
            expected_signature_int: u8,
        ) {
            let mut buffer = Vec::with_capacity(algorithm.tls_serialized_len());
            let result = algorithm.tls_serialize(&mut buffer);
            assert_eq!(expected_hash_int, buffer[0]);
            assert_eq!(expected_signature_int, buffer[1]);
            assert_eq!(result, Ok(2));
        }

        run_test(
            SignatureAndHashAlgorithm {
                hash: HashAlgorithm::Sha1,
                signature: SignatureAlgorithm::Rsa,
            },
            2,
            1,
        );
        run_test(
            SignatureAndHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Ecdsa,
            },
            4,
            3,
        );
    }

    #[test]
    fn test_digitally_signed_deserialization() {
        let bytes = [4, 3, 0, 3, 2, 1, 0, 2, 1, 0, 1, 9];

        let result = run_deserialization_test(
            &bytes,
            Ok((
                DigitallySigned {
                    algorithm: SignatureAndHashAlgorithm {
                        hash: HashAlgorithm::Sha256,
                        signature: SignatureAlgorithm::Ecdsa,
                    },
                    signature: TlsVecU16::<u8>::from_slice(&[2, 1, 0]),
                },
                [2, 1, 0, 1, 9].as_slice(),
            )),
        );

        let _ = run_deserialization_test(
            &result.unwrap().1,
            Ok((
                DigitallySigned {
                    algorithm: SignatureAndHashAlgorithm {
                        hash: HashAlgorithm::Sha1,
                        signature: SignatureAlgorithm::Rsa,
                    },
                    signature: TlsVecU16::<u8>::from_slice(&[9]),
                },
                [].as_slice(),
            )),
        );
    }

    #[test]
    fn test_digitally_signed_serialization() {
        fn run_test(digitally_signed: DigitallySigned, expected_bytes: &[u8]) {
            let mut buffer = Vec::with_capacity(digitally_signed.tls_serialized_len());
            let result = digitally_signed.tls_serialize(&mut buffer);
            assert_eq!(expected_bytes, &buffer);
            assert_eq!(result, Ok(expected_bytes.len()));
        }

        run_test(
            DigitallySigned {
                algorithm: SignatureAndHashAlgorithm {
                    hash: HashAlgorithm::Sha256,
                    signature: SignatureAlgorithm::Ecdsa,
                },
                signature: TlsVecU16::<u8>::from_slice(&[0, 1, 2]),
            },
            &[4, 3, 0, 3, 0, 1, 2],
        );
        run_test(
            DigitallySigned {
                algorithm: SignatureAndHashAlgorithm {
                    hash: HashAlgorithm::Sha1,
                    signature: SignatureAlgorithm::Rsa,
                },
                signature: TlsVecU16::<u8>::from_slice(&[0, 1, 2]),
            },
            &[2, 1, 0, 3, 0, 1, 2],
        );
    }

    #[test]
    fn test_version_deserialization() {
        let bytes = [0, 0];

        let result = run_deserialization_test(&bytes, Ok((Version::V1, [0].as_slice())));

        let _ = run_deserialization_test(&result.unwrap().1, Ok((Version::V1, [].as_slice())));
        let _ = run_deserialization_test::<Version>(&[1], Err(tls_codec::Error::UnknownValue(1)));
    }

    #[test]
    fn test_version_serialization() {
        fn run_test(version: Version, expected_bytes: &[u8]) {
            let mut buffer = Vec::with_capacity(version.tls_serialized_len());
            let result = version.tls_serialize(&mut buffer);
            assert_eq!(expected_bytes, &buffer);
            assert_eq!(result, Ok(expected_bytes.len()));
        }

        run_test(Version::V1, &[0]);
    }

    #[test]
    fn test_log_id_deserialization() {
        let bytes = [42; 36];

        let _ =
            run_deserialization_test(&bytes, Ok((LogId { key_id: [42; 32] }, [42; 4].as_slice())));
    }

    #[test]
    fn test_log_id_serialization() {
        fn run_test(log_id: LogId, expected_bytes: &[u8]) {
            let mut buffer = Vec::with_capacity(log_id.tls_serialized_len());
            let result = log_id.tls_serialize(&mut buffer);
            assert_eq!(expected_bytes, &buffer);
            assert_eq!(result, Ok(expected_bytes.len()));
        }

        run_test(LogId { key_id: [3; 32] }, &[3; 32]);
    }

    const TLS_SCT_EXAMPLE: [u8; 119] = [
        0, 122, 50, 140, 84, 216, 183, 45, 182, 32, 234, 56, 224, 82, 30, 233, 132, 22, 112, 50,
        19, 133, 77, 59, 210, 43, 193, 58, 87, 163, 82, 235, 82, 0, 0, 1, 135, 224, 74, 186, 106,
        0, 0, 4, 3, 0, 72, 48, 70, 2, 33, 0, 170, 82, 81, 162, 157, 234, 14, 189, 167, 13, 247,
        211, 97, 112, 248, 172, 149, 125, 58, 18, 238, 60, 150, 157, 124, 245, 188, 138, 102, 212,
        244, 187, 2, 33, 0, 209, 79, 31, 63, 208, 79, 240, 233, 193, 187, 28, 33, 190, 95, 130, 66,
        183, 222, 187, 42, 22, 83, 0, 119, 226, 246, 19, 197, 47, 237, 198, 149,
    ];

    #[test]
    fn test_sct_deserialization() {
        let _ = run_deserialization_test(
            &TLS_SCT_EXAMPLE,
            Ok((
                SignedCertificateTimestamp {
                    version: Version::V1,
                    log_id: LogId {
                        key_id: TLS_SCT_EXAMPLE[1..33].try_into().unwrap(),
                    },
                    timestamp: u64::from_be_bytes(TLS_SCT_EXAMPLE[33..41].try_into().unwrap()),
                    extensions: TlsVecU16::from_slice(&[]),
                    sign: DigitallySigned {
                        algorithm: SignatureAndHashAlgorithm {
                            hash: HashAlgorithm::Sha256,
                            signature: SignatureAlgorithm::Ecdsa,
                        },
                        signature: TlsVecU16::from_slice(&TLS_SCT_EXAMPLE[47..]),
                    },
                },
                &[],
            )),
        );
    }

    #[test]
    fn test_sct_serialization() {
        fn run_test(sct: SignedCertificateTimestamp, expected_bytes: &[u8]) {
            let mut buffer = Vec::with_capacity(sct.tls_serialized_len());
            let result = sct.tls_serialize(&mut buffer);
            assert_eq!(expected_bytes, &buffer);
            assert_eq!(result, Ok(expected_bytes.len()));
        }

        run_test(
            SignedCertificateTimestamp {
                version: Version::V1,
                log_id: LogId {
                    key_id: TLS_SCT_EXAMPLE[1..33].try_into().unwrap(),
                },
                timestamp: u64::from_be_bytes(TLS_SCT_EXAMPLE[33..41].try_into().unwrap()),
                extensions: TlsVecU16::from_slice(&[]),
                sign: DigitallySigned {
                    algorithm: SignatureAndHashAlgorithm {
                        hash: HashAlgorithm::Sha256,
                        signature: SignatureAlgorithm::Ecdsa,
                    },
                    signature: TlsVecU16::from_slice(&TLS_SCT_EXAMPLE[47..]),
                },
            },
            &TLS_SCT_EXAMPLE,
        );
    }

    const SCT_EXAMPLE: [u8; 245] = [
        4, 129, 242, 0, 240, 0, 119, 0, 122, 50, 140, 84, 216, 183, 45, 182, 32, 234, 56, 224, 82,
        30, 233, 132, 22, 112, 50, 19, 133, 77, 59, 210, 43, 193, 58, 87, 163, 82, 235, 82, 0, 0,
        1, 135, 224, 74, 186, 106, 0, 0, 4, 3, 0, 72, 48, 70, 2, 33, 0, 170, 82, 81, 162, 157, 234,
        14, 189, 167, 13, 247, 211, 97, 112, 248, 172, 149, 125, 58, 18, 238, 60, 150, 157, 124,
        245, 188, 138, 102, 212, 244, 187, 2, 33, 0, 209, 79, 31, 63, 208, 79, 240, 233, 193, 187,
        28, 33, 190, 95, 130, 66, 183, 222, 187, 42, 22, 83, 0, 119, 226, 246, 19, 197, 47, 237,
        198, 149, 0, 117, 0, 173, 247, 190, 250, 124, 255, 16, 200, 139, 157, 61, 156, 30, 62, 24,
        106, 180, 103, 41, 93, 207, 177, 12, 36, 202, 133, 134, 52, 235, 220, 130, 138, 0, 0, 1,
        135, 224, 74, 186, 164, 0, 0, 4, 3, 0, 70, 48, 68, 2, 32, 29, 110, 144, 37, 157, 227, 170,
        70, 67, 16, 68, 195, 212, 168, 246, 37, 94, 69, 210, 136, 42, 113, 217, 230, 34, 152, 253,
        116, 13, 174, 232, 191, 2, 32, 16, 25, 200, 223, 59, 176, 40, 145, 76, 85, 242, 133, 130,
        212, 61, 216, 83, 238, 115, 130, 82, 240, 196, 162, 249, 54, 199, 120, 175, 72, 223, 14,
    ];

    #[test]
    fn test_sct_list_deserialization() {
        fn run_test(
            bytes: &[u8],
            expected_result: Result<SignedCertificateTimestampList, der::Error>,
        ) -> Result<SignedCertificateTimestampList, der::Error> {
            let actual_result = SignedCertificateTimestampList::from_der(&bytes);
            assert_eq!(actual_result, expected_result);
            actual_result
        }

        let result = run_test(
            &SCT_EXAMPLE,
            Ok(SignedCertificateTimestampList(
                OctetString::new(&SCT_EXAMPLE[3..]).unwrap(),
            )),
        );
        let scts = result.unwrap().parse_timestamps().unwrap();
        assert_eq!(
            scts[0].parse_timestamp(),
            Ok(SignedCertificateTimestamp {
                version: Version::V1,
                log_id: LogId {
                    key_id: SCT_EXAMPLE[8..40].try_into().unwrap(),
                },
                timestamp: u64::from_be_bytes(SCT_EXAMPLE[40..48].try_into().unwrap()),
                extensions: TlsVecU16::from_slice(&[]),
                sign: DigitallySigned {
                    algorithm: SignatureAndHashAlgorithm {
                        hash: HashAlgorithm::Sha256,
                        signature: SignatureAlgorithm::Ecdsa,
                    },
                    signature: TlsVecU16::from_slice(&SCT_EXAMPLE[54..126]),
                },
            })
        );
        assert_eq!(
            scts[1].parse_timestamp(),
            Ok(SignedCertificateTimestamp {
                version: Version::V1,
                log_id: LogId {
                    key_id: SCT_EXAMPLE[129..161].try_into().unwrap(),
                },
                timestamp: u64::from_be_bytes(SCT_EXAMPLE[161..169].try_into().unwrap()),
                extensions: TlsVecU16::from_slice(&[]),
                sign: DigitallySigned {
                    algorithm: SignatureAndHashAlgorithm {
                        hash: HashAlgorithm::Sha256,
                        signature: SignatureAlgorithm::Ecdsa,
                    },
                    signature: TlsVecU16::from_slice(&SCT_EXAMPLE[175..]),
                },
            })
        );
    }

    #[test]
    fn test_sct_list_serialization() {
        let serialized_sct1 = SerializedSct::new(SignedCertificateTimestamp {
            version: Version::V1,
            log_id: LogId {
                key_id: SCT_EXAMPLE[8..40].try_into().unwrap(),
            },
            timestamp: u64::from_be_bytes(SCT_EXAMPLE[40..48].try_into().unwrap()),
            extensions: TlsVecU16::from_slice(&[]),
            sign: DigitallySigned {
                algorithm: SignatureAndHashAlgorithm {
                    hash: HashAlgorithm::Sha256,
                    signature: SignatureAlgorithm::Ecdsa,
                },
                signature: TlsVecU16::from_slice(&SCT_EXAMPLE[54..126]),
            },
        })
        .unwrap();
        let serialized_sct2 = SerializedSct::new(SignedCertificateTimestamp {
            version: Version::V1,
            log_id: LogId {
                key_id: SCT_EXAMPLE[129..161].try_into().unwrap(),
            },
            timestamp: u64::from_be_bytes(SCT_EXAMPLE[161..169].try_into().unwrap()),
            extensions: TlsVecU16::from_slice(&[]),
            sign: DigitallySigned {
                algorithm: SignatureAndHashAlgorithm {
                    hash: HashAlgorithm::Sha256,
                    signature: SignatureAlgorithm::Ecdsa,
                },
                signature: TlsVecU16::from_slice(&SCT_EXAMPLE[175..]),
            },
        })
        .unwrap();
        let list =
            SignedCertificateTimestampList::new(&[serialized_sct1, serialized_sct2]).unwrap();
        let der = list.to_der().unwrap();
        assert_eq!(der.as_slice(), SCT_EXAMPLE.as_slice());
    }
}
