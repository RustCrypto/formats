#![cfg(feature = "sct")]

use const_oid::{db::rfc6962, AssociatedOid, ObjectIdentifier};
use der::asn1::OctetString;
//TODO: Remove use::alloc::format explicit use required by the #[derive(TlsSerialize)] on SignagureAndHashAlgorithms
//once the PR: https://github.com/RustCrypto/formats/pull/1103 is merged
// use std::format;
use alloc::format;
use tls_codec::{TlsDeserializeBytes, TlsSerialize, TlsSize, TlsVecU16};

// TODO: Review what should be pub
// TODO: Update docs
// TODO: Review naming

// TODO: Remove this constant when const_oid version is updated which includes this PR:
// https://github.com/RustCrypto/formats/pull/1094
// TODO: Do not publish this as pub, this is for testing only
/// OID for signed certificate timestamps extension
// pub const CT_PRECERT_SCTS: ObjectIdentifier =
//     ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");

pub struct SignedCertificateTimestampList(OctetString);

impl AssociatedOid for SignedCertificateTimestampList {
    const OID: ObjectIdentifier = rfc6962::CT_PRECERT_SCTS;
}

impl_newtype!(SignedCertificateTimestampList, OctetString);
impl_extension!(SignedCertificateTimestampList, critical = false);

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
    use tls_codec::{DeserializeBytes, Error, Serialize, Size, TlsVecU16};

    use crate::ext::pkix::sct::LogId;

    use super::{
        DigitallySigned, HashAlgorithm, SignatureAlgorithm, SignatureAndHashAlgorithm,
        SignedCertificateTimestamp, Version,
    };

    #[test]
    fn test_hash_algorithm_deserialization() {
        fn run_test<'a>(
            bytes: &'a [u8],
            expected_result: Result<(HashAlgorithm, &[u8]), Error>,
        ) -> Result<(HashAlgorithm, &'a [u8]), Error> {
            let actual_result = HashAlgorithm::tls_deserialize(&bytes);
            assert_eq!(actual_result, expected_result);
            actual_result
        }
        let bytes = [0, 1, 2, 3, 4, 5, 6, 8];

        let result = run_test(
            &bytes,
            Ok((HashAlgorithm::None, [1, 2, 3, 4, 5, 6, 8].as_slice())),
        );
        let result = run_test(
            &result.unwrap().1,
            Ok((HashAlgorithm::Md5, [2, 3, 4, 5, 6, 8].as_slice())),
        );
        let result = run_test(
            &result.unwrap().1,
            Ok((HashAlgorithm::Sha1, [3, 4, 5, 6, 8].as_slice())),
        );
        let result = run_test(
            &result.unwrap().1,
            Ok((HashAlgorithm::Sha224, [4, 5, 6, 8].as_slice())),
        );
        let result = run_test(
            &result.unwrap().1,
            Ok((HashAlgorithm::Sha256, [5, 6, 8].as_slice())),
        );
        let result = run_test(
            &result.unwrap().1,
            Ok((HashAlgorithm::Sha384, [6, 8].as_slice())),
        );
        let result = run_test(
            &result.unwrap().1,
            Ok((HashAlgorithm::Sha512, [8].as_slice())),
        );
        let result = run_test(
            &result.unwrap().1,
            Ok((HashAlgorithm::Intrinsic, [].as_slice())),
        );
        let _ = run_test(&result.unwrap().1, Err(Error::EndOfStream));
        let _ = run_test(&[7], Err(Error::UnknownValue(7)));
        let _ = run_test(&[9], Err(Error::UnknownValue(9)));
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
        fn run_test<'a>(
            bytes: &'a [u8],
            expected_result: Result<(SignatureAlgorithm, &[u8]), Error>,
        ) -> Result<(SignatureAlgorithm, &'a [u8]), Error> {
            let actual_result = SignatureAlgorithm::tls_deserialize(&bytes);
            assert_eq!(actual_result, expected_result);
            actual_result
        }
        let bytes = [0, 1, 2, 3, 7, 8];

        let result = run_test(
            &bytes,
            Ok((SignatureAlgorithm::Anonymous, [1, 2, 3, 7, 8].as_slice())),
        );
        let result = run_test(
            &result.unwrap().1,
            Ok((SignatureAlgorithm::Rsa, [2, 3, 7, 8].as_slice())),
        );
        let result = run_test(
            &result.unwrap().1,
            Ok((SignatureAlgorithm::Dsa, [3, 7, 8].as_slice())),
        );
        let result = run_test(
            &result.unwrap().1,
            Ok((SignatureAlgorithm::Ecdsa, [7, 8].as_slice())),
        );
        let result = run_test(
            &result.unwrap().1,
            Ok((SignatureAlgorithm::Ed25519, [8].as_slice())),
        );
        let result = run_test(
            &result.unwrap().1,
            Ok((SignatureAlgorithm::Ed448, [].as_slice())),
        );
        let _ = run_test(&result.unwrap().1, Err(Error::EndOfStream));
        let _ = run_test(&[4], Err(Error::UnknownValue(4)));
        let _ = run_test(&[5], Err(Error::UnknownValue(5)));
        let _ = run_test(&[6], Err(Error::UnknownValue(6)));
        let _ = run_test(&[9], Err(Error::UnknownValue(9)));
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
        fn run_test<'a>(
            bytes: &'a [u8],
            expected_result: Result<(SignatureAndHashAlgorithm, &[u8]), Error>,
        ) -> Result<(SignatureAndHashAlgorithm, &'a [u8]), Error> {
            let actual_result = SignatureAndHashAlgorithm::tls_deserialize(&bytes);
            assert_eq!(actual_result, expected_result);
            actual_result
        }
        let bytes = [4, 3, 2, 1];

        let result = run_test(
            &bytes,
            Ok((
                SignatureAndHashAlgorithm {
                    hash: HashAlgorithm::Sha256,
                    signature: SignatureAlgorithm::Ecdsa,
                },
                [2, 1].as_slice(),
            )),
        );

        let _ = run_test(
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
        fn run_test<'a>(
            bytes: &'a [u8],
            expected_result: Result<(DigitallySigned, &[u8]), Error>,
        ) -> Result<(DigitallySigned, &'a [u8]), Error> {
            let actual_result = DigitallySigned::tls_deserialize(&bytes);
            assert_eq!(actual_result, expected_result);
            actual_result
        }
        let bytes = [4, 3, 0, 3, 2, 1, 0, 2, 1, 0, 1, 9];

        let result = run_test(
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

        let _ = run_test(
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
        fn run_test<'a>(
            bytes: &'a [u8],
            expected_result: Result<(Version, &[u8]), Error>,
        ) -> Result<(Version, &'a [u8]), Error> {
            let actual_result = Version::tls_deserialize(&bytes);
            assert_eq!(actual_result, expected_result);
            actual_result
        }
        let bytes = [0, 0];

        let result = run_test(&bytes, Ok((Version::V1, [0].as_slice())));

        let _ = run_test(&result.unwrap().1, Ok((Version::V1, [].as_slice())));
        let _ = run_test(&[1], Err(Error::UnknownValue(1)));
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
        fn run_test<'a>(
            bytes: &'a [u8],
            expected_result: Result<(LogId, &[u8]), Error>,
        ) -> Result<(LogId, &'a [u8]), Error> {
            let actual_result = LogId::tls_deserialize(&bytes);
            assert_eq!(actual_result, expected_result);
            actual_result
        }
        let bytes = [42; 36];

        let _ = run_test(&bytes, Ok((LogId { key_id: [42; 32] }, [42; 4].as_slice())));
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

    const SCT_EXAMPLE: [u8; 119] = [
        0, 122, 50, 140, 84, 216, 183, 45, 182, 32, 234, 56, 224, 82, 30, 233, 132, 22, 112, 50,
        19, 133, 77, 59, 210, 43, 193, 58, 87, 163, 82, 235, 82, 0, 0, 1, 135, 224, 74, 186, 106,
        0, 0, 4, 3, 0, 72, 48, 70, 2, 33, 0, 170, 82, 81, 162, 157, 234, 14, 189, 167, 13, 247,
        211, 97, 112, 248, 172, 149, 125, 58, 18, 238, 60, 150, 157, 124, 245, 188, 138, 102, 212,
        244, 187, 2, 33, 0, 209, 79, 31, 63, 208, 79, 240, 233, 193, 187, 28, 33, 190, 95, 130, 66,
        183, 222, 187, 42, 22, 83, 0, 119, 226, 246, 19, 197, 47, 237, 198, 149,
    ];

    #[test]
    fn test_sct_deserialization() {
        fn run_test<'a>(
            bytes: &'a [u8],
            expected_result: Result<(SignedCertificateTimestamp, &[u8]), Error>,
        ) -> Result<(SignedCertificateTimestamp, &'a [u8]), Error> {
            let actual_result = SignedCertificateTimestamp::tls_deserialize(&bytes);
            assert_eq!(actual_result, expected_result);
            actual_result
        }

        let _ = run_test(
            &SCT_EXAMPLE,
            Ok((
                SignedCertificateTimestamp {
                    version: Version::V1,
                    log_id: LogId {
                        key_id: SCT_EXAMPLE[1..33].try_into().unwrap(),
                    },
                    timestamp: u64::from_be_bytes(SCT_EXAMPLE[33..41].try_into().unwrap()),
                    extensions: TlsVecU16::from_slice(&[]),
                    sign: DigitallySigned {
                        algorithm: SignatureAndHashAlgorithm {
                            hash: HashAlgorithm::Sha256,
                            signature: SignatureAlgorithm::Ecdsa,
                        },
                        signature: TlsVecU16::from_slice(&SCT_EXAMPLE[47..]),
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
                    key_id: SCT_EXAMPLE[1..33].try_into().unwrap(),
                },
                timestamp: u64::from_be_bytes(SCT_EXAMPLE[33..41].try_into().unwrap()),
                extensions: TlsVecU16::from_slice(&[]),
                sign: DigitallySigned {
                    algorithm: SignatureAndHashAlgorithm {
                        hash: HashAlgorithm::Sha256,
                        signature: SignatureAlgorithm::Ecdsa,
                    },
                    signature: TlsVecU16::from_slice(&SCT_EXAMPLE[47..]),
                },
            },
            &SCT_EXAMPLE,
        );
    }
}
