//! Implementation of the key derivation function 
//! [RFC 7292 Appendix B](https://datatracker.ietf.org/doc/html/rfc7292#appendix-B)

use super::Result;
use alloc::vec::Vec;
use digest::{core_api::BlockSizeUser, Digest, FixedOutputReset, OutputSizeUser, Update};

/// Transform a utf-8 string in a unicode (utf16) string as binary array.
/// The Utf16 code points are stored in big endian format with two trailing zero bytes.
pub fn str_to_unicode(s: &str) -> Vec<u8> {
    let mut unicode: Vec<u8> = s
        .encode_utf16()
        .flat_map(|c| c.to_be_bytes().to_vec())
        .collect();
    unicode.push(0);
    unicode.push(0);
    unicode
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
) -> Result<Vec<u8>>
where
    D: Digest + FixedOutputReset + BlockSizeUser,
{
    let mut hasher = D::new();
    let pass_uni = str_to_unicode(pass);
    let u = <D as OutputSizeUser>::output_size();
    let v = D::block_size();
    let slen = v * ((salt.len() + v - 1) / v);
    let plen = v * ((pass_uni.len() + v - 1) / v);
    let ilen = slen + plen;
    let mut i_tmp = vec![0u8; ilen];
    for i in 0..slen {
        i_tmp[i] = salt[i % salt.len()];
    }
    for i in slen..ilen {
        i_tmp[i] = pass_uni[(i - slen) % pass_uni.len()];
    }
    let d_tmp = match id {
        Pkcs12KeyType::EncryptionKey => vec![1u8; v],
        Pkcs12KeyType::Iv => vec![2u8; v],
        Pkcs12KeyType::Mac => vec![3u8; v],
    };
    let mut m = key_len;
    let mut n = 0;
    let mut out = vec![0u8; key_len];
    loop {
        <D as Update>::update(&mut hasher, &d_tmp);
        <D as Update>::update(&mut hasher, &i_tmp);
        let mut result = hasher.finalize_fixed_reset();
        for _ in 1..rounds {
            <D as Update>::update(&mut hasher, &result[0..u]);
            result = hasher.finalize_fixed_reset();
        }
        let min_mu = m.min(u);
        out[n..n + min_mu].copy_from_slice(&result[0..min_mu]);
        n += min_mu;
        m -= min_mu;
        if m <= 0 {
            break;
        }
        let mut b_tmp = vec![0u8; v];
        for j in 0..v {
            b_tmp[j] = result[j % u];
        }
        let mut j = 0;
        while j < ilen {
            let mut c = 1_u16;
            let mut k: i64 = v as i64 - 1;
            while k >= 0 {
                c += i_tmp[k as usize + j] as u16 + b_tmp[k as usize] as u16;
                i_tmp[j + k as usize] = (c & 0x00ff) as u8;
                c >>= 8;
                k -= 1;
            }
            j += v;
        }
    }
    Ok(out)
}
