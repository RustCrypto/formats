//! Implement the TLS codec for some byte arrays.

use super::{Deserialize, Error, Serialize, Size};
use std::io::{Read, Write};

impl<const LEN: usize> Serialize for [u8; LEN] {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let written = writer.write(self)?;
        if written == LEN {
            Ok(written)
        } else {
            Err(Error::InvalidWriteLength(format!(
                "Expected to write {} bytes but only {} were written.",
                LEN, written
            )))
        }
    }
}

impl<const LEN: usize> Deserialize for [u8; LEN] {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        let mut out = [0u8; LEN];
        bytes.read_exact(&mut out)?;
        Ok(out)
    }
}

impl<const LEN: usize> Size for [u8; LEN] {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        LEN
    }
}
