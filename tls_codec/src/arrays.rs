//! Implement the TLS codec for some byte arrays.

use crate::{Deserialize, DeserializeBytes, Error, Serialize, Size};

#[cfg(feature = "std")]
use std::io::{Read, Write};

impl<const LEN: usize> Serialize for [u8; LEN] {
    #[cfg(feature = "std")]
    #[inline]
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let written = writer.write(self)?;
        if written == LEN {
            Ok(written)
        } else {
            Err(Error::InvalidWriteLength(format!(
                "Expected to write {LEN} bytes but only {written} were written."
            )))
        }
    }
}

impl<const LEN: usize> Deserialize for [u8; LEN] {
    #[cfg(feature = "std")]
    #[inline]
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        let mut out = [0u8; LEN];
        bytes.read_exact(&mut out)?;
        Ok(out)
    }
}

impl<const LEN: usize> DeserializeBytes for [u8; LEN] {
    #[inline]
    fn tls_deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let out = bytes
            .get(..LEN)
            .ok_or(Error::EndOfStream)?
            .try_into()
            .map_err(|_| Error::EndOfStream)?;
        Ok((out, &bytes[LEN..]))
    }
}

impl<const LEN: usize> Size for [u8; LEN] {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        LEN
    }
}
