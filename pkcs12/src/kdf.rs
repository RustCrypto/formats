//! Implementation of the key derivation function
//! [RFC 7292 Appendix B](https://datatracker.ietf.org/doc/html/rfc7292#appendix-B)

use alloc::vec::Vec;
use digest::{core_api::BlockSizeUser, Digest, FixedOutputReset, OutputSizeUser, Update};
use zeroize::Zeroize;

/// Transform a utf-8 string in a unicode (utf16) string as binary array.
/// The Utf16 code points are stored in big endian format with two trailing zero bytes.
pub fn str_to_unicode(utf8_str: &str) -> Vec<u8> {
    let mut utf16_bytes = Vec::new();
    // reserve max number of required bytes to avoid re-allocation
    utf16_bytes.reserve(utf8_str.len() * 2 + 2);
    for code_point in utf8_str.encode_utf16() {
        utf16_bytes.extend(code_point.to_be_bytes());
    }
    utf16_bytes.push(0);
    utf16_bytes.push(0);
    utf16_bytes
}

/// Specify the usage type of the generated key
/// This allows to derive distinct encryption keys, IVs and MAC from the same password or text
/// string.
pub enum Pkcs12KeyType {
    /// Use key for encryption
    EncryptionKey = 1,
    /// Use key as initial vector
    Iv = 2,
    /// Use key as MAC
    Mac = 3,
}

/// Derives `key` of type `id` from `pass` and `salt` with length `key_len` using `rounds`
/// iterations of the algorithm
/// ```rust
/// let key = pkcs12::kdf::derive_key::<sha2::Sha256>("top-secret", &[0x1, 0x2, 0x3, 0x4],
///     pkcs12::kdf::Pkcs12KeyType::EncryptionKey, 1000, 32);
/// ```
pub fn derive_key<D>(
    pass: &str,
    salt: &[u8],
    id: Pkcs12KeyType,
    rounds: i32,
    key_len: usize,
) -> Vec<u8>
where
    D: Digest + FixedOutputReset + BlockSizeUser,
{
    let mut digest = D::new();
    let mut pass_utf16 = str_to_unicode(pass);
    let output_size = <D as OutputSizeUser>::output_size();
    let block_size = D::block_size();
    let slen = block_size * ((salt.len() + block_size - 1) / block_size);
    let plen = block_size * ((pass_utf16.len() + block_size - 1) / block_size);
    let ilen = slen + plen;
    let mut init_key = vec![0u8; ilen];
    for i in 0..slen {
        init_key[i] = salt[i % salt.len()];
    }
    for i in 0..plen {
        init_key[slen + i] = pass_utf16[i % pass_utf16.len()];
    }
    pass_utf16.zeroize();

    let id_block = match id {
        Pkcs12KeyType::EncryptionKey => vec![1u8; block_size],
        Pkcs12KeyType::Iv => vec![2u8; block_size],
        Pkcs12KeyType::Mac => vec![3u8; block_size],
    };

    let mut m = key_len;
    let mut n = 0;
    let mut out = vec![0u8; key_len];
    loop {
        <D as Update>::update(&mut digest, &id_block);
        <D as Update>::update(&mut digest, &init_key);
        let mut result = digest.finalize_fixed_reset();
        for _ in 1..rounds {
            <D as Update>::update(&mut digest, &result[0..output_size]);
            result = digest.finalize_fixed_reset();
        }
        let new_bytes_num = m.min(output_size);
        out[n..n + new_bytes_num].copy_from_slice(&result[0..new_bytes_num]);
        n += new_bytes_num;
        if m <= new_bytes_num {
            break;
        }

        // prepare `init_key` for next block if `ouput_size` is smaller than `key_len`
        m -= new_bytes_num;
        let mut j = 0;
        while j < ilen {
            let mut c = 1_u16;
            let mut k = block_size - 1;
            loop {
                c += init_key[k + j] as u16 + result[k % output_size] as u16;
                init_key[j + k] = (c & 0x00ff) as u8;
                c >>= 8;
                if k == 0 {
                    break;
                }
                k -= 1;
            }
            j += block_size;
        }
    }
    init_key.zeroize();
    out
}
