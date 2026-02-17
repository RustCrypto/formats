use crate::{Deserialize, DeserializeBytes, Error, Serialize, Size};

/// Variable-length encoded unsigned integer as defined in [RFC 9000].
///
/// [RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000#name-variable-length-integer-enc
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct TlsVarInt(u64);

impl TlsVarInt {
    /// The largest value that can be represented by this type.
    pub const MAX: u64 = (1 << 62) - 1;
    const MAX_LOG: usize = 3;

    /// Wraps an unsinged integer as variable-length int.
    ///
    /// Returns `None` if the value is larger than [`Self::MAX`].
    pub const fn new(value: u64) -> Option<Self> {
        if Self::MAX < value {
            None
        } else {
            Some(Self(value))
        }
    }

    pub(crate) fn try_new(value: u64) -> Result<Self, Error> {
        Self::new(value).ok_or(Error::InvalidVectorLength)
    }

    /// Returns the value of this variable-length int.
    pub const fn value(&self) -> u64 {
        self.0
    }

    /// Returns the number of bytes required to encode this variable-length
    /// int.
    pub(crate) const fn bytes_len(&self) -> usize {
        let value = self.0;
        if !cfg!(fuzzing) {
            debug_assert!(value <= Self::MAX);
        }
        if value <= 0x3f {
            1
        } else if value <= 0x3fff {
            2
        } else if value <= 0x3fff_ffff {
            4
        } else {
            8
        }
    }

    /// Writes the bytes of this variable-length at the beginning of the
    /// buffer.
    ///
    /// The buffer must be at least of the length returned by
    /// [`Self::bytes_len`].
    pub(crate) fn write_bytes(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let len = self.bytes_len();
        if !cfg!(fuzzing) {
            debug_assert!(len <= 8, "Invalid varint len {len}");
        }
        if len > 8 {
            return Err(Error::LibraryError);
        }

        if buf.len() < len {
            return Err(Error::InvalidVectorLength);
        }
        let bytes = &mut buf[..len];

        match len {
            1 => bytes[0] = 0x00,
            2 => bytes[0] = 0x40,
            4 => bytes[0] = 0x80,
            8 => bytes[0] = 0xc0,
            _ => {
                if !cfg!(fuzzing) {
                    debug_assert!(false, "Invalid varint len {len}");
                }
                return Err(Error::InvalidVectorLength);
            }
        }
        let mut value = self.0;
        for b in bytes.iter_mut().rev() {
            *b |= (value & 0xFF) as u8;
            value >>= 8;
        }

        Ok(len)
    }
}

impl TryFrom<u64> for TlsVarInt {
    type Error = Error;

    #[inline]
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<TlsVarInt> for u64 {
    #[inline]
    fn from(value: TlsVarInt) -> Self {
        value.0
    }
}

#[inline(always)]
fn check_min_len(value: u64, len: usize) -> Result<(), Error> {
    if cfg!(feature = "mls") {
        // ensure that `len` is minimal for the given `value`
        let min_len = TlsVarInt::try_new(value)?.bytes_len();
        if min_len != len {
            return Err(Error::InvalidVectorLength);
        }
    };
    Ok(())
}

impl Deserialize for TlsVarInt {
    #[cfg(feature = "std")]
    #[inline]
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, Error> {
        let mut len_byte = [0u8; 1];
        if bytes.read(&mut len_byte)? == 0 {
            return Err(Error::EndOfStream);
        };
        let len_byte = len_byte[0];

        let (value, len) = calculate_value(len_byte)?;
        let mut value: u64 = value.try_into().map_err(|_| Error::InvalidInput)?;

        for _ in 1..len {
            let mut next = [0u8; 1];
            bytes.read_exact(&mut next)?;
            value = (value << 8) + u64::from(next[0]);
        }

        check_min_len(value, len)?;

        Ok(TlsVarInt(value))
    }
}

impl DeserializeBytes for TlsVarInt {
    #[inline]
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let (len_byte, mut remainder) = u8::tls_deserialize_bytes(bytes)?;

        let (value, len) = calculate_value(len_byte)?;
        let mut value: u64 = value.try_into().map_err(|_| Error::InvalidInput)?;

        for _ in 1..len {
            let (next, next_remainder) = u8::tls_deserialize_bytes(remainder)?;
            remainder = next_remainder;
            value = (value << 8) + u64::from(next);
        }

        check_min_len(value, len)?;

        Ok((TlsVarInt(value), remainder))
    }
}

impl Serialize for TlsVarInt {
    #[cfg(feature = "std")]
    #[inline]
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut bytes = [0u8; 8];
        let len = self.write_bytes(&mut bytes)?;
        writer.write_all(&bytes[..len])?;
        Ok(len)
    }
}

impl Size for TlsVarInt {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.bytes_len()
    }
}

/// Calculates the value and the length from the first byte.
#[inline(always)]
pub(crate) fn calculate_value(byte: u8) -> Result<(usize, usize), Error> {
    let value: usize = (byte & 0x3F).into();
    let len_log = (byte >> 6).into();
    if !cfg!(fuzzing) {
        debug_assert!(len_log <= TlsVarInt::MAX_LOG);
    }
    if len_log > TlsVarInt::MAX_LOG {
        return Err(Error::InvalidVectorLength);
    }
    let len = match len_log {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };
    Ok((value, len))
}

#[cfg(test)]
mod tests {

    use super::*;

    // (value, var length, encoded bytes)
    const TESTS: [(u64, usize, &[u8]); 5] = [
        (37, 1, &[0x25]),
        (15_293, 2, &[0x7b, 0xbd]),
        (494_878_333, 4, &[0x9d, 0x7f, 0x3e, 0x7d]),
        (
            151_288_809_941_952_652,
            8,
            &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
        ),
        (
            TlsVarInt::MAX,
            8,
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
    ];

    #[test]
    fn tls_serialized_len() {
        for (value, len, _) in TESTS {
            assert_eq!(
                TlsVarInt::try_from(value)
                    .expect("value too large")
                    .tls_serialized_len(),
                len
            );
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn tls_serialize() {
        use crate::alloc::vec::Vec;

        for (value, len, bytes) in TESTS {
            let mut buf = Vec::new();
            let written = TlsVarInt::try_from(value)
                .expect("value too large")
                .tls_serialize(&mut buf)
                .expect("tls serialize failed");
            assert_eq!(written, len, "{value}");
            assert_eq!(buf.len(), len, "{value}");
            assert_eq!(&buf[..], bytes, "{value}");
        }
    }

    #[test]
    fn tls_deserialize_bytes() {
        for (value, len, bytes) in TESTS {
            assert_eq!(len, bytes.len());
            let (out, remainder) =
                TlsVarInt::tls_deserialize_bytes(bytes).expect("tls deserialize bytes failed");
            assert_eq!(remainder.len(), 0);
            assert_eq!(out, TlsVarInt::try_from(value).expect("value too large"));
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn tls_deserialize() {
        use std::io::Cursor;

        for (value, len, bytes) in TESTS {
            assert_eq!(len, bytes.len());
            let out = TlsVarInt::tls_deserialize(&mut Cursor::new(bytes))
                .expect("tls deserialize failed");
            assert_eq!(out, TlsVarInt::try_from(value).expect("value too large"));
        }
    }

    #[test]
    // Note: MLS requires minimum-size encoding
    // <https://www.rfc-editor.org/rfc/rfc9420.html#name-variable-size-vector-length>
    #[cfg_attr(feature = "mls", should_panic)]
    fn non_minimum_size_deserialize_bytes() {
        let (out, remaining) =
            TlsVarInt::tls_deserialize_bytes(&[0x40, 0x25]).expect("tls deserialize bytes failed");
        assert_eq!(remaining.len(), 0);
        assert_eq!(out, TlsVarInt(37));
    }

    #[cfg(feature = "std")]
    #[test]
    // Note: MLS requires minimum-size encoding
    // <https://www.rfc-editor.org/rfc/rfc9420.html#name-variable-size-vector-length>
    #[cfg_attr(feature = "mls", should_panic)]
    fn non_minimum_size_tls_deserialize() {
        use std::io::Cursor;

        let out = TlsVarInt::tls_deserialize(&mut Cursor::new(&[0x40, 0x25]))
            .expect("tls deserialize failed");
        assert_eq!(out, TlsVarInt(37));
    }
}
