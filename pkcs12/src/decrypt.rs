//! Decryption support for PKCS#12 shrouded key bags.
//!
//! Implements `pbeWithSHAAnd128BitRC2-CBC` (OID `1.2.840.113549.1.12.1.5`) and
//! `pbeWithSHAAnd40BitRC2-CBC` (OID `1.2.840.113549.1.12.1.6`), as defined in
//! [RFC 7292 Appendix C].
//!
//! ⚠️ **Security Warning**: both RC2 schemes are deprecated.  New code should use
//! PBES2 with PBKDF2 and AES-256-CBC instead.  This implementation exists solely
//! to support reading legacy PKCS#12 files.
//!
//! [RFC 7292 Appendix C]: https://www.rfc-editor.org/rfc/rfc7292#appendix-C

use alloc::vec::Vec;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use zeroize::Zeroizing;

use crate::{
    PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC, PKCS_12_PBE_WITH_SHAAND40_BIT_RC2_CBC,
    kdf::{Pkcs12KeyType, derive_key_utf8},
    pbe_params::{EncryptedPrivateKeyInfo, Pkcs12PbeParams},
};

/// RC2 block size in bytes; also the CBC IV length.
const RC2_BLOCK_SIZE: usize = 8;

/// RC2-128 key length: 16 bytes = 128 bits.
const RC2_128_KEY_LEN: usize = 16;

/// RC2-40 key length: 5 bytes = 40 bits.
const RC2_40_KEY_LEN: usize = 5;

/// Maximum accepted KDF iteration count.
///
/// RFC 7292 places no upper bound on the iteration count, but an
/// implementation-defined limit is required to prevent denial-of-service from
/// crafted .p12 files.  At ~100 000 SHA-1 compressions per second, this cap
/// limits a single decrypt call to roughly 10 seconds on slow hardware while
/// still exceeding any iteration count used in practice.
const MAX_ITERATIONS: i32 = 1_000_000;

type Rc2CbcDec = cbc::Decryptor<rc2::Rc2>;

impl EncryptedPrivateKeyInfo {
    /// Decrypt a `pkcs8ShroudedKeyBag` encrypted with
    /// `pbeWithSHAAnd128BitRC2-CBC` (OID `1.2.840.113549.1.12.1.5`)
    /// and return the plaintext PKCS#8 `PrivateKeyInfo` DER blob.
    ///
    /// `password` is the UTF-8 passphrase used when the file was created.
    /// It must contain only characters in the Unicode Basic Multilingual Plane
    /// (U+0000–U+FFFF); surrogate pairs and characters above U+FFFF are rejected.
    ///
    /// # Security
    ///
    /// This is a **low-level primitive**.  It operates on a single
    /// `EncryptedPrivateKeyInfo` bag and has no access to the `Pfx`-level
    /// MAC (HMAC-SHA1 over the `AuthenticatedSafe`).
    ///
    /// **Callers that read from untrusted files MUST verify the PFX MAC before
    /// calling this function.**  PKCS#7 unpadding catches a wrong password
    /// roughly 254 out of 255 times; the remaining ~0.4% of wrong-password
    /// attempts produce garbage output that passes unpadding but will fail
    /// downstream when the caller parses the result as PKCS#8.  Without MAC
    /// verification there is no protection against ciphertext tampering.
    ///
    /// # Errors
    ///
    /// Returns [`der::Error`] if:
    /// - the `encryption_algorithm` OID is not `pbeWithSHAAnd128BitRC2-CBC`,
    /// - algorithm parameters are absent or fail to decode as [`Pkcs12PbeParams`],
    /// - `iterations` is not in the range `1..=MAX_ITERATIONS` (1 000 000),
    /// - the salt is empty,
    /// - `password` contains a character outside the Basic Multilingual Plane,
    /// - the ciphertext length is zero or not a multiple of 8 bytes, or
    /// - decryption or PKCS#7 unpadding fails (wrong password or corrupted data).
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    pub fn decrypt_rc2_128_cbc(&self, password: &str) -> der::Result<Zeroizing<Vec<u8>>> {
        decrypt_rc2(
            self,
            password,
            &PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC,
            RC2_128_KEY_LEN,
        )
    }

    /// Decrypt a `pkcs8ShroudedKeyBag` encrypted with
    /// `pbeWithSHAAnd40BitRC2-CBC` (OID `1.2.840.113549.1.12.1.6`)
    /// and return the plaintext PKCS#8 `PrivateKeyInfo` DER blob.
    ///
    /// `password` is the UTF-8 passphrase used when the file was created.
    /// It must contain only characters in the Unicode Basic Multilingual Plane
    /// (U+0000–U+FFFF); surrogate pairs and characters above U+FFFF are rejected.
    ///
    /// # Security
    ///
    /// Same caveats as [`EncryptedPrivateKeyInfo::decrypt_rc2_128_cbc`].
    /// RC2-40 uses a 5-byte effective key and is cryptographically weak;
    /// do not use in new designs.
    ///
    /// # Errors
    ///
    /// Returns [`der::Error`] if:
    /// - the `encryption_algorithm` OID is not `pbeWithSHAAnd40BitRC2-CBC`,
    /// - algorithm parameters are absent or fail to decode as [`Pkcs12PbeParams`],
    /// - `iterations` is not in the range `1..=MAX_ITERATIONS` (1 000 000),
    /// - the salt is empty,
    /// - `password` contains a character outside the Basic Multilingual Plane,
    /// - the ciphertext length is zero or not a multiple of 8 bytes, or
    /// - decryption or PKCS#7 unpadding fails (wrong password or corrupted data).
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    pub fn decrypt_rc2_40_cbc(&self, password: &str) -> der::Result<Zeroizing<Vec<u8>>> {
        decrypt_rc2(
            self,
            password,
            &PKCS_12_PBE_WITH_SHAAND40_BIT_RC2_CBC,
            RC2_40_KEY_LEN,
        )
    }
}

/// Shared decryption implementation for both RC2 variants.
///
/// `expected_oid` and `key_len` select the specific RC2 variant.  All other
/// logic (parameter decoding, KDF, CBC decryption, PKCS#7 unpadding) is
/// identical for both OIDs.
fn decrypt_rc2(
    epki: &EncryptedPrivateKeyInfo,
    password: &str,
    expected_oid: &der::oid::ObjectIdentifier,
    key_len: usize,
) -> der::Result<Zeroizing<Vec<u8>>> {
    // Defensive: verify OID before touching any key material.
    if epki.encryption_algorithm.oid != *expected_oid {
        return Err(der::ErrorKind::OidUnknown {
            oid: epki.encryption_algorithm.oid,
        }
        .into());
    }

    // Decode the PBE parameters (salt + iteration count) from the
    // AlgorithmIdentifier parameters field.
    let params_any = epki
        .encryption_algorithm
        .parameters
        .as_ref()
        .ok_or(der::ErrorKind::Failed)?;
    let params = params_any.decode_as::<Pkcs12PbeParams>()?;

    // Defensive: iteration count must be strictly positive and below the
    // denial-of-service limit.
    if !(1..=MAX_ITERATIONS).contains(&params.iterations) {
        return Err(der::ErrorKind::Failed.into());
    }

    let salt = params.salt.as_bytes();

    // Defensive: a zero-length salt produces a trivially weak KDF input.
    if salt.is_empty() {
        return Err(der::ErrorKind::Failed.into());
    }

    // Derive the RC2 key (ID=1, key_len bytes) and CBC IV (ID=2, 8 bytes)
    // using the RFC 7292 §B.2 KDF with SHA-1.
    let key = Zeroizing::new(derive_key_utf8::<sha1::Sha1>(
        password,
        salt,
        Pkcs12KeyType::EncryptionKey,
        params.iterations,
        key_len,
    )?);

    let iv = Zeroizing::new(derive_key_utf8::<sha1::Sha1>(
        password,
        salt,
        Pkcs12KeyType::Iv,
        params.iterations,
        RC2_BLOCK_SIZE,
    )?);

    let ciphertext = epki.encrypted_data.as_bytes();

    // Defensive: ciphertext must be non-empty and a multiple of the
    // RC2 block size (8 bytes).
    if ciphertext.is_empty() || ciphertext.len() % RC2_BLOCK_SIZE != 0 {
        return Err(der::ErrorKind::Failed.into());
    }

    // Build the CBC decryptor.  new_from_slices uses KeyInit::new_from_slice
    // for the key, which accepts any key length from 1 to 128 bytes and sets
    // the effective key length to key_len * 8 bits — correct for both RC2-128
    // (16 bytes → EKB=128) and RC2-40 (5 bytes → EKB=40).
    let decryptor = Rc2CbcDec::new_from_slices(&key, &iv)
        .map_err(|_| der::Error::from(der::ErrorKind::Failed))?;

    // Decrypt in-place into a Zeroizing buffer.  We capture only the
    // plaintext *length* from decrypt_padded (dropping the borrow on buf),
    // then truncate buf to that length and return it directly.  This avoids
    // a second allocation and memcpy compared to calling plaintext.to_vec().
    // The Zeroizing drop still zeroes the full buffer capacity on exit.
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let pt_len = decryptor
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|_| der::Error::from(der::ErrorKind::Failed))?
        .len();

    // Defensive: a valid PKCS#8 PrivateKeyInfo cannot be empty.
    if pt_len == 0 {
        return Err(der::ErrorKind::Failed.into());
    }

    buf.truncate(pt_len);
    Ok(buf)
}
