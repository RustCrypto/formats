//! Writer trait and associated implementations.

use crate::Result;
use pem_rfc7468 as pem;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "fingerprint")]
use sha2::{Digest, Sha256};

/// Get the estimated length of data when encoded as Base64.
///
/// This is an upper bound where the actual length might be slightly shorter.
#[cfg(feature = "alloc")]
#[allow(clippy::integer_arithmetic)]
pub(crate) fn base64_len(input_len: usize) -> usize {
    // TODO(tarcieri): checked arithmetic
    (((input_len * 4) / 3) + 3) & !3
}

/// Constant-time Base64 writer implementation.
pub(crate) type Base64Writer<'o> = base64ct::Encoder<'o, base64ct::Base64>;

/// Writer trait which encodes the SSH binary format to various output
/// encodings.
pub(crate) trait Writer: Sized {
    /// Write the given bytes to the writer.
    fn write(&mut self, bytes: &[u8]) -> Result<()>;
}

impl Writer for Base64Writer<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        Ok(self.encode(bytes)?)
    }
}

impl Writer for pem::Encoder<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        Ok(self.encode(bytes)?)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl Writer for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

#[cfg(feature = "fingerprint")]
impl Writer for Sha256 {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.update(bytes);
        Ok(())
    }
}
