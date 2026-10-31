//! Implement the TLS codec for some byte arrays.

use alloc::vec::Vec;

use crate::{Deserialize, DeserializeBytes, Error, Serialize, SerializeBytes, Size};

#[cfg(feature = "std")]
use std::io::{Read, Write};

impl<const LEN: usize> Serialize for [u8; LEN] {
    #[cfg(feature = "std")]
    #[inline]
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_all(self)?;
        Ok(LEN)
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

#[cfg_attr(hax, hax_lib::attributes)]
impl<const LEN: usize> DeserializeBytes for [u8; LEN] {
    #[cfg_attr(hax, hax_lib::ensures(|res| if bytes.len() < LEN {
        res == Err(Error::EndOfStream)
    } else {
        res.is_ok_and(|(value, remainder)|
            value[..] == bytes[..LEN]
                && remainder.len() == bytes.len() - LEN
                && remainder.len() <= bytes.len()
                && (!cfg!(feature = "mls")
                    || remainder.len() + value.tls_serialized_len() == bytes.len()))
    }))]
    #[inline]
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let out = bytes
            .get(..LEN)
            .ok_or(Error::EndOfStream)?
            .try_into()
            .map_err(|_| Error::EndOfStream)?;
        Ok((out, &bytes[LEN..]))
    }
}

impl<const LEN: usize> SerializeBytes for [u8; LEN] {
    fn tls_serialize_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.to_vec())
    }
}

impl<const LEN: usize> Size for [u8; LEN] {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        LEN
    }
}
