use const_oid::{db::rfc6962, AssociatedOid, ObjectIdentifier};
use der::asn1::OctetString;
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
#[repr(u8)]
pub enum HashAlgo {
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
    use tls_codec::DeserializeBytes;

    use super::HashAlgo;

    #[test]
    fn test_hash_algo_deserialization() {
        let bytes = [0, 1, 2, 3, 4, 5, 6, 8];

        let hash_algo = HashAlgo::tls_deserialize(&bytes);
        assert_eq!(
            hash_algo,
            Ok((HashAlgo::None, [1, 2, 3, 4, 5, 6, 8].as_slice()))
        );

        let hash_algo = HashAlgo::tls_deserialize(&hash_algo.unwrap().1);
        assert_eq!(
            hash_algo,
            Ok((HashAlgo::Md5, [2, 3, 4, 5, 6, 8].as_slice()))
        );

        let hash_algo = HashAlgo::tls_deserialize(&hash_algo.unwrap().1);
        assert_eq!(hash_algo, Ok((HashAlgo::Sha1, [3, 4, 5, 6, 8].as_slice())));

        let hash_algo = HashAlgo::tls_deserialize(&hash_algo.unwrap().1);
        assert_eq!(hash_algo, Ok((HashAlgo::Sha224, [4, 5, 6, 8].as_slice())));

        let hash_algo = HashAlgo::tls_deserialize(&hash_algo.unwrap().1);
        assert_eq!(hash_algo, Ok((HashAlgo::Sha256, [5, 6, 8].as_slice())));

        let hash_algo = HashAlgo::tls_deserialize(&hash_algo.unwrap().1);
        assert_eq!(hash_algo, Ok((HashAlgo::Sha384, [6, 8].as_slice())));

        let hash_algo = HashAlgo::tls_deserialize(&hash_algo.unwrap().1);
        assert_eq!(hash_algo, Ok((HashAlgo::Sha512, [8].as_slice())));

        let hash_algo = HashAlgo::tls_deserialize(&hash_algo.unwrap().1);
        assert_eq!(hash_algo, Ok((HashAlgo::Intrinsic, [].as_slice())));

        let hash_algo = HashAlgo::tls_deserialize(&hash_algo.unwrap().1);
        assert_eq!(hash_algo, Err(tls_codec::Error::EndOfStream));

        let hash_algo = HashAlgo::tls_deserialize(&[7]);
        assert_eq!(hash_algo, Err(tls_codec::Error::UnknownValue(7)));
    }
}
