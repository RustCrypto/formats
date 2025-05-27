//! Implementation of the PKCS#12 key derivation function as described in
//! [RFC 7292 Appendix B](https://datatracker.ietf.org/doc/html/rfc7292#appendix-B).
//!
//! ## ⚠️ Security Warning
//!
//! This KDF is considered poor quality by today's standards as noted in the aforementioned RFC:
//!
//! > Note that this method for password privacy mode is not recommended
//! > and is deprecated for new usage.  The procedures and algorithms
//! > defined in PKCS #5 v2.1 should be used instead.
//! > Specifically, PBES2 should be used as encryption scheme, with PBKDF2
//! > as the key derivation function.
//!
//! See the [`pkcs5`](https://docs.rs/pkcs5) crate for an implementation of PKCS #5, or the
//! [`argon2`](https://docs.rs/argon2) crate for a state-of-the-art password-based KDF.

use alloc::{vec, vec::Vec};
use der::asn1::BmpString;
use digest::{Digest, FixedOutputReset, OutputSizeUser, Update, block_api::BlockSizeUser};
use zeroize::{Zeroize, Zeroizing};

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
/// `pass` must be a utf8 string.
/// ```rust
/// let key = pkcs12::kdf::derive_key_utf8::<sha2::Sha256>("top-secret", &[0x1, 0x2, 0x3, 0x4],
///     pkcs12::kdf::Pkcs12KeyType::EncryptionKey, 1000, 32);
/// ```
pub fn derive_key_utf8<D>(
    password: &str,
    salt: &[u8],
    id: Pkcs12KeyType,
    rounds: i32,
    key_len: usize,
) -> der::Result<Vec<u8>>
where
    D: Digest + FixedOutputReset + BlockSizeUser,
{
    let password_bmp = BmpString::from_utf8(password)?;
    Ok(derive_key_bmp::<D>(password_bmp, salt, id, rounds, key_len))
}

/// Derive
pub fn derive_key_bmp<D>(
    password: BmpString,
    salt: &[u8],
    id: Pkcs12KeyType,
    rounds: i32,
    key_len: usize,
) -> Vec<u8>
where
    D: Digest + FixedOutputReset + BlockSizeUser,
{
    let mut password = Zeroizing::new(Vec::from(password.into_bytes()));

    // Password is NULL terminated
    password.extend([0u8; 2]);

    derive_key::<D>(&password, salt, id, rounds, key_len)
}

/// Derives `key` of type `id` from `pass` and `salt` with length `key_len` using `rounds`
/// iterations of the algorithm
/// `pass` must be a unicode (utf16) byte array in big endian order without order mark and with two
/// terminating zero bytes.
/// ```rust
/// let key = pkcs12::kdf::derive_key_utf8::<sha2::Sha256>("top-secret", &[0x1, 0x2, 0x3, 0x4],
///     pkcs12::kdf::Pkcs12KeyType::EncryptionKey, 1000, 32);
/// ```
pub fn derive_key<D>(
    pass: &[u8],
    salt: &[u8],
    id: Pkcs12KeyType,
    rounds: i32,
    key_len: usize,
) -> Vec<u8>
where
    D: Digest + FixedOutputReset + BlockSizeUser,
{
    let mut digest = D::new();
    let output_size = <D as OutputSizeUser>::output_size();
    let block_size = D::block_size();

    // In the following, the numbered comments relate directly to the algorithm
    // described in RFC 7292, Appendix B.2. Actual variable names may differ.
    // Comments of the RFC are in enclosed in []
    //
    // 1. Construct a string, D (the "diversifier"), by concatenating v/8
    //    copies of ID, where v is the block size in bits.
    let id_block = match id {
        Pkcs12KeyType::EncryptionKey => vec![1u8; block_size],
        Pkcs12KeyType::Iv => vec![2u8; block_size],
        Pkcs12KeyType::Mac => vec![3u8; block_size],
    };

    let slen = block_size * salt.len().div_ceil(block_size);
    let plen = block_size * pass.len().div_ceil(block_size);
    let ilen = slen + plen;
    let mut init_key = vec![0u8; ilen];
    // 2. Concatenate copies of the salt together to create a string S of
    //    length v(ceiling(s/v)) bits (the final copy of the salt may be
    //    truncated to create S).  Note that if the salt is the empty
    //    string, then so is S.
    for i in 0..slen {
        init_key[i] = salt[i % salt.len()];
    }

    // 3. Concatenate copies of the password together to create a string P
    //    of length v(ceiling(p/v)) bits (the final copy of the password
    //    may be truncated to create P).  Note that if the password is the
    //    empty string, then so is P.
    for i in 0..plen {
        init_key[slen + i] = pass[i % pass.len()];
    }

    // 4. Set I=S||P to be the concatenation of S and P.
    // [already done in `init_key`]

    let mut m = key_len;
    let mut n = 0;
    let mut out = vec![0u8; key_len];
    // 5. Set c=ceiling(n/u)
    // 6. For i=1, 2, ..., c, do the following:
    // [ Instead of following this approach, we use an infinite loop and
    //   use the break condition below, if we have produced n bytes for the key]
    loop {
        // 6. A. Set A2=H^r(D||I). (i.e., the r-th hash of D||1,
        //    H(H(H(... H(D||I))))
        <D as Update>::update(&mut digest, &id_block);
        <D as Update>::update(&mut digest, &init_key);
        let mut result = digest.finalize_fixed_reset();
        for _ in 1..rounds {
            <D as Update>::update(&mut digest, &result[0..output_size]);
            result = digest.finalize_fixed_reset();
        }

        // 7. Concateate A_1, A_2, ..., A_c together to form a pseudorandom
        //     bit string, A.
        // [ Instead of storing all Ais and concatenating later, we concatenate
        // them immediately ]
        let new_bytes_num = m.min(output_size);
        out[n..n + new_bytes_num].copy_from_slice(&result[0..new_bytes_num]);
        n += new_bytes_num;
        if m <= new_bytes_num {
            break;
        }
        m -= new_bytes_num;

        // 6. B. Concatenate copies of Ai to create a string B of length v
        //       bits (the final copy of Ai may be truncated to create B).
        // [ we achieve this on thy fly with the expression `result[k % output_size]` below]

        // 6. C. Treating I as a concatenation I_0, I_1, ..., I_(k-1) of v-bit
        //       blocks, where k=ceiling(s/v)+ceiling(p/v), modify I by
        //       setting I_j=(I_j+B+1) mod 2^v for each j.
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
    // 8. Use the first n bits of A as the output of this entire process.
    out
}
