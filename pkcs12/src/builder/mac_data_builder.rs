//! Structure to help with generating [`MacData`] objects

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "legacy")]
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifier;
use zeroize::Zeroizing;

use crate::{
    DigestInfo, MacData,
    kdf::{Pkcs12KeyType, derive_key_utf8},
};
use der::{Any, AnyRef, Decode, asn1::OctetString};
use log::{error, warn};

use super::error::{Error, Result};

use super::supported_algs::MacAlgorithm;

/// Helper for building password-based [`MacData`] objects for inclusion in a [PKCS #12 object](crate::pfx::Pfx)
pub struct MacDataBuilder {
    digest_algorithm: MacAlgorithm,
    salt: Option<Vec<u8>>,
    iterations: Option<u32>,
}
impl MacDataBuilder {
    /// Creates a new MacDataBuilder instance with no salt, suitable for use with build_with_rng as-is
    /// or for further customization prior to invoking build. By default, iterations will be set to 600,000.
    pub fn new(digest_algorithm: MacAlgorithm) -> MacDataBuilder {
        MacDataBuilder {
            digest_algorithm,
            salt: None,
            iterations: None,
        }
    }

    /// Creates a new MacDataBuilder instance with the provided salt suitable for further
    /// customization prior to invoking build. By default, iterations will be set to 600,000.
    pub fn new_with_salt(digest_algorithm: MacAlgorithm, salt: Vec<u8>) -> MacDataBuilder {
        if salt.len() < 16 {
            warn!(
                "The salt value passed to new_with_salt is shorter than the recommended 16 bytes."
            );
        }
        MacDataBuilder {
            digest_algorithm,
            salt: Some(salt),
            iterations: None,
        }
    }

    /// Specify a salt value for use on the subsequent [`build`](MacDataBuilder::build) invocation.
    pub fn salt(&mut self, salt: Option<Vec<u8>>) -> &mut Self {
        if let Some(salt) = &salt {
            if salt.len() < 16 {
                warn!("The provided salt value is shorter than the recommended 16 bytes.");
            }
        }
        self.salt = salt;
        self
    }

    /// Returns true if a `salt` value has been specified and false if not.
    pub fn has_salt(&self) -> bool {
        self.salt.is_some()
    }

    /// Specify an iteration count for use on the subsequent [`build`](MacDataBuilder::build)
    /// invocation. If not set, a default of 600,000 iterations is used.
    pub fn iterations(&mut self, iterations: Option<u32>) -> Result<&mut Self> {
        if let Some(iterations) = iterations {
            if iterations > i32::MAX as u32 {
                return Err(Error::Pkcs12Builder(format!(
                    "Invalid number of iterations provided ({iterations})"
                )));
            }
        }
        self.iterations = iterations;
        Ok(self)
    }

    /// Casts the u32 to an i32 if possible, else returns 600000 as a default.
    fn get_iterations(&self) -> i32 {
        if let Some(iterations) = self.iterations {
            if iterations <= i32::MAX as u32 {
                return iterations as i32;
            } else {
                error!("Invalid number of iterations provided ({iterations})");
            }
        }
        600000
    }

    /// Generate MAC key given a password and a salt. The returned key is zeroized on drop.
    fn generate_mac_key(&self, password: &str, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let iterations = self.get_iterations();

        match self.digest_algorithm {
            MacAlgorithm::HmacSha256 => Ok(Zeroizing::new(derive_key_utf8::<Sha256>(
                password,
                salt,
                Pkcs12KeyType::Mac,
                iterations,
                self.digest_algorithm.output_size(),
            )?)),
            MacAlgorithm::HmacSha384 => Ok(Zeroizing::new(derive_key_utf8::<Sha384>(
                password,
                salt,
                Pkcs12KeyType::Mac,
                iterations,
                self.digest_algorithm.output_size(),
            )?)),
            MacAlgorithm::HmacSha512 => Ok(Zeroizing::new(derive_key_utf8::<Sha512>(
                password,
                salt,
                Pkcs12KeyType::Mac,
                iterations,
                self.digest_algorithm.output_size(),
            )?)),
            #[cfg(feature = "legacy")]
            MacAlgorithm::HmacSha1 => Ok(Zeroizing::new(derive_key_utf8::<Sha1>(
                password,
                salt,
                Pkcs12KeyType::Mac,
                iterations,
                self.digest_algorithm.output_size(),
            )?)),
        }
    }

    /// Generate a MAC given a MAC key and content
    fn generate_mac(&self, mac_key: &[u8], content: &[u8]) -> Result<Vec<u8>> {
        Ok(self.digest_algorithm.compute_hmac(mac_key, content)?)
    }

    /// Builds a MacData instance using a previously specified salt value and a previously specified
    /// (or default) iterations value. If no iterations value has been specified, a default of 600,000
    /// is used.
    pub fn build(&self, password: &str, content: &[u8]) -> Result<MacData> {
        let salt = match &self.salt {
            Some(salt) => salt,
            None => {
                return Err(Error::Pkcs12Builder(String::from(
                    "No salt provided for MacData",
                )));
            }
        };

        let mac_key = self.generate_mac_key(password, salt)?;
        let result = self.generate_mac(&mac_key, content)?;
        let mac_os = OctetString::new(&result[..])?;
        let mac_salt = OctetString::new(&salt[..])?;
        let params_bytes = self.digest_algorithm.parameters();
        let params_ref = Some(Any::from(AnyRef::from_der(&params_bytes)?));

        Ok(MacData {
            mac: DigestInfo {
                algorithm: AlgorithmIdentifier {
                    oid: self.digest_algorithm.oid(),
                    parameters: params_ref,
                },
                digest: mac_os,
            },
            mac_salt,
            iterations: self.get_iterations(),
        })
    }
}
