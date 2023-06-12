use const_oid::{db::rfc6962, AssociatedOid, ObjectIdentifier};
use der::asn1::OctetString;
//TODO: Remove this explicit use required by the #[derive(TlsSerialize)] on SignagureAndHashAlgorithms
//once the PR: https://github.com/RustCrypto/formats/pull/1103 is merged
use std::format;
use tls_codec::{TlsDeserializeBytes, TlsSerialize, TlsSize};

// TODO: Review what should be pub
// TODO: Update docs
// TODO: Review naming

// TODO: Remove this constant when const_oid version is updated which includes this PR:
// https://github.com/RustCrypto/formats/pull/1094
// TODO: Do not publish this as pub, this is for testing only
/// OID for signed certificate timestamps extension
// pub const CT_PRECERT_SCTS: ObjectIdentifier =
//     ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");

pub struct SctList(OctetString);

impl AssociatedOid for SctList {
    const OID: ObjectIdentifier = rfc6962::CT_PRECERT_SCTS;
}

impl_newtype!(SctList, OctetString);
impl_extension!(SctList, critical = false);

#[derive(PartialEq, Debug, TlsDeserializeBytes, TlsSerialize, TlsSize)]
pub struct SignatureAndHashAlgorithm {
    signature: SignatureAlgorithm,
    hash: HashAlgorithm,
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
    use tls_codec::{DeserializeBytes, Error, Serialize, Size};

    use super::{HashAlgorithm, SignatureAlgorithm};

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
}
