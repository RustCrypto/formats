//! Decryption support for PKCS#12 shrouded key bags.
//!
//! Implements `pbeWithSHAAnd3-KeyTripleDES-CBC` (OID `1.2.840.113549.1.12.1.3`)
//! as defined in [RFC 7292 Appendix C].
//!
//! ⚠️ **Security Warning**: this scheme is deprecated. New code should use PBES2
//! with PBKDF2 and AES-256-CBC instead. This implementation exists solely to
//! support reading legacy PKCS#12 files.
//!
//! [RFC 7292 Appendix C]: https://www.rfc-editor.org/rfc/rfc7292#appendix-C

use alloc::vec::Vec;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use zeroize::Zeroizing;

use crate::{
    PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC,
    kdf::{Pkcs12KeyType, derive_key_utf8},
    pbe_params::{EncryptedPrivateKeyInfo, Pkcs12PbeParams},
};

/// 3-key Triple-DES key length: three 8-byte DES keys.
const DES3_KEY_LEN: usize = 24;

/// DES block size in bytes; also the CBC IV length.
const DES3_BLOCK_SIZE: usize = 8;

/// Maximum accepted KDF iteration count.
///
/// RFC 7292 places no upper bound on the iteration count, but an
/// implementation-defined limit is required to prevent denial-of-service from
/// crafted .p12 files.  At ~100 000 SHA-1 compressions per second, this cap
/// limits a single decrypt call to roughly 10 seconds on slow hardware while
/// still exceeding any iteration count used in practice.
const MAX_ITERATIONS: i32 = 1_000_000;

type TdesEde3CbcDec = cbc::Decryptor<des::TdesEde3>;

impl EncryptedPrivateKeyInfo {
    /// Decrypt a `pkcs8ShroudedKeyBag` encrypted with
    /// `pbeWithSHAAnd3-KeyTripleDES-CBC` (OID `1.2.840.113549.1.12.1.3`)
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
    /// - the `encryption_algorithm` OID is not `pbeWithSHAAnd3-KeyTripleDES-CBC`,
    /// - algorithm parameters are absent or fail to decode as [`Pkcs12PbeParams`],
    /// - `iterations` is not in the range `1..=MAX_ITERATIONS` (1 000 000),
    /// - the salt is empty,
    /// - `password` contains a character outside the Basic Multilingual Plane,
    /// - the ciphertext length is zero or not a multiple of 8 bytes, or
    /// - decryption or PKCS#7 unpadding fails (wrong password or corrupted data).
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    pub fn decrypt_3des_cbc(&self, password: &str) -> der::Result<Zeroizing<Vec<u8>>> {
        // Defensive: verify OID before touching any key material.
        if self.encryption_algorithm.oid != PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC {
            return Err(der::ErrorKind::OidUnknown {
                oid: self.encryption_algorithm.oid,
            }
            .into());
        }

        // Decode the PBE parameters (salt + iteration count) from the
        // AlgorithmIdentifier parameters field.  `decode_as` avoids an
        // intermediate DER serialisation: `der::Any` already holds the raw
        // TLV bytes and can decode them directly into any `Choice + DecodeValue`
        // type, which `Pkcs12PbeParams` satisfies via its `Sequence` derive.
        let params_any = self
            .encryption_algorithm
            .parameters
            .as_ref()
            .ok_or(der::ErrorKind::Failed)?;
        let params = params_any.decode_as::<Pkcs12PbeParams>()?;

        // Defensive: iteration count must be strictly positive and below the
        // implementation-defined denial-of-service limit (see MAX_ITERATIONS).
        // The field is i32 in the ASN.1 schema; zero or negative is malformed.
        if !(1..=MAX_ITERATIONS).contains(&params.iterations) {
            return Err(der::ErrorKind::Failed.into());
        }

        let salt = params.salt.as_bytes();

        // Defensive: a zero-length salt produces a trivially weak KDF input.
        if salt.is_empty() {
            return Err(der::ErrorKind::Failed.into());
        }

        // Derive the 3DES key (ID=1, 24 bytes) and CBC IV (ID=2, 8 bytes)
        // using the RFC 7292 §B.2 KDF with SHA-1.
        // Both are wrapped in Zeroizing so they are cleared on drop.
        let key = Zeroizing::new(derive_key_utf8::<sha1::Sha1>(
            password,
            salt,
            Pkcs12KeyType::EncryptionKey,
            params.iterations,
            DES3_KEY_LEN,
        )?);

        let iv = Zeroizing::new(derive_key_utf8::<sha1::Sha1>(
            password,
            salt,
            Pkcs12KeyType::Iv,
            params.iterations,
            DES3_BLOCK_SIZE,
        )?);

        let ciphertext = self.encrypted_data.as_bytes();

        // Defensive: ciphertext must be non-empty and a multiple of the
        // 3DES block size (8 bytes).  An empty or misaligned buffer cannot
        // be a valid PKCS#7-padded ciphertext.
        if ciphertext.is_empty() || ciphertext.len() % DES3_BLOCK_SIZE != 0 {
            return Err(der::ErrorKind::Failed.into());
        }

        // Build the CBC decryptor.  new_from_slices validates key (24 bytes)
        // and IV (8 bytes) lengths; any mismatch is a programming error but
        // we propagate it as a DER failure rather than panicking.
        let decryptor = TdesEde3CbcDec::new_from_slices(&key, &iv)
            .map_err(|_| der::Error::from(der::ErrorKind::Failed))?;

        // Decrypt in-place into a Zeroizing buffer so key material in the
        // plaintext is cleared if the caller drops the result.
        let mut buf = Zeroizing::new(ciphertext.to_vec());
        let plaintext = decryptor
            .decrypt_padded::<Pkcs7>(&mut buf)
            .map_err(|_| der::Error::from(der::ErrorKind::Failed))?;

        // Defensive: a valid PKCS#8 PrivateKeyInfo cannot be empty.
        if plaintext.is_empty() {
            return Err(der::ErrorKind::Failed.into());
        }

        Ok(Zeroizing::new(plaintext.to_vec()))
    }
}
