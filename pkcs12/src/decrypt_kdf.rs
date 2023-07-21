//! Convenience functions for working with some common PKCS #12 use cases

use crate::pbe_params::Pkcs12PbeParams;
use alloc::vec::Vec;
use pkcs5::pbes2::EncryptionScheme;
use spki::AlgorithmIdentifierOwned;

use crate::decrypt::{Error, Result};
use crate::safe_bag::PrivateKeyInfo;
use der::asn1::OctetString;
use der::{Decode, Encode};

#[cfg(all(feature = "kdf", feature = "insecure", feature = "decrypt"))]
pub(crate) fn pkcs12_pbe_key(
    encrypted_content: OctetString,
    password: &[u8],
    alg: &AlgorithmIdentifierOwned,
) -> Result<PrivateKeyInfo> {
    let plaintext = pkcs12_pbe(encrypted_content, password, alg)?;
    Ok(PrivateKeyInfo::from_der(&plaintext)?)
}

#[cfg(all(feature = "kdf", feature = "insecure", feature = "decrypt"))]
pub(crate) fn pkcs12_pbe(
    encrypted_content: OctetString,
    password: &[u8],
    alg: &AlgorithmIdentifierOwned,
) -> Result<Vec<u8>> {
    use crate::kdf::*;
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use core::str;
    use sha1::Sha1;

    let enc_params = match &alg.parameters {
        Some(params) => params.to_der()?,
        None => return Err(Error::MissingParameters),
    };

    let p12_pbe_params = Pkcs12PbeParams::from_der(&enc_params)?;
    let s = str::from_utf8(password).map_err(|e| Error::Utf8Error(e))?;

    let iv = derive_key::<Sha1>(
        &s,
        p12_pbe_params.salt.as_bytes(),
        Pkcs12KeyType::Iv,
        p12_pbe_params.iterations,
        8,
    );
    let es = match alg.oid {
        crate::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC => EncryptionScheme::DesEde3Cbc {
            iv: iv.as_slice().try_into().unwrap(),
        },
        // PKCS_12_PBE_WITH_SHAAND2_KEY_TRIPLE_DES_CBC
        // PKCS_12_PBE_WITH_SHAAND128_BIT_RC4
        // PKCS_12_PBE_WITH_SHAAND40_BIT_RC4
        // PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC
        // PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC
        _ => return Err(Error::UnexpectedAlgorithm(alg.oid)),
    };
    let key = derive_key::<Sha1>(
        &s,
        p12_pbe_params.salt.as_bytes(),
        Pkcs12KeyType::EncryptionKey,
        p12_pbe_params.iterations,
        es.key_size(),
    );

    let mut ciphertext = encrypted_content.as_bytes().to_vec();
    let plaintext = cbc::Decryptor::<des::TdesEde3>::new_from_slices(key.as_slice(), iv.as_slice())
        .map_err(|_| es.to_alg_params_invalid())
        .map_err(|_| Error::EncryptionScheme)?
        .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
        .unwrap();

    Ok(plaintext.to_vec())
}
