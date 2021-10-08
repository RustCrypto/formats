//! Codec implementations for unsigned integer primitives.

use super::{Deserialize, Error, Serialize, Size};

use std::io::{Read, Write};

impl<T: Size> Size for Option<T> {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        1 + match self {
            Some(v) => v.tls_serialized_len(),
            None => 0,
        }
    }
}

impl<T: Serialize> Serialize for Option<T> {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        match self {
            Some(e) => {
                let written = writer.write(&[1])?;
                debug_assert_eq!(written, 1);
                e.tls_serialize(writer).map(|l| l + 1)
            }
            None => {
                writer.write_all(&[0])?;
                Ok(1)
            }
        }
    }
}

impl<T: Deserialize> Deserialize for Option<T> {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        let mut some_or_none = [0u8; 1];
        bytes.read_exact(&mut some_or_none)?;
        match some_or_none[0] {
            0 => {
                Ok(None)
            },
            1 => {
                let element = T::tls_deserialize(bytes)?;
                Ok(Some(element))
            },
            _ => Err(Error::DecodingError(format!("Trying to decode Option<T> with {} for option. It must be 0 for None and 1 for Some.", some_or_none[0])))
        }
    }
}

macro_rules! impl_unsigned {
    ($t:ty, $bytes:literal) => {
        impl Deserialize for $t {
            fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
                let mut x = (0 as $t).to_be_bytes();
                bytes.read_exact(&mut x)?;
                Ok(<$t>::from_be_bytes(x))
            }
        }

        impl Serialize for $t {
            fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
                let written = writer.write(&self.to_be_bytes())?;
                Ok(written)
            }
        }

        impl Size for $t {
            #[inline]
            fn tls_serialized_len(&self) -> usize {
                $bytes
            }
        }
    };
}

impl_unsigned!(u8, 1);
impl_unsigned!(u16, 2);
impl_unsigned!(u32, 4);
impl_unsigned!(u64, 8);

impl From<std::array::TryFromSliceError> for Error {
    fn from(_: std::array::TryFromSliceError) -> Self {
        Self::InvalidInput
    }
}

// Implement (de)serialization for tuple.
impl<T, U> Deserialize for (T, U)
where
    T: Deserialize,
    U: Deserialize,
{
    #[inline(always)]
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        Ok((T::tls_deserialize(bytes)?, U::tls_deserialize(bytes)?))
    }
}

impl<T, U> Serialize for (T, U)
where
    T: Serialize,
    U: Serialize,
{
    #[inline(always)]
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let written = self.0.tls_serialize(writer)?;
        self.1.tls_serialize(writer).map(|l| l + written)
    }
}

impl<T, U> Size for (T, U)
where
    T: Size,
    U: Size,
{
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        self.0.tls_serialized_len() + self.1.tls_serialized_len()
    }
}

impl<T, U, V> Deserialize for (T, U, V)
where
    T: Deserialize,
    U: Deserialize,
    V: Deserialize,
{
    #[inline(always)]
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        Ok((
            T::tls_deserialize(bytes)?,
            U::tls_deserialize(bytes)?,
            V::tls_deserialize(bytes)?,
        ))
    }
}

impl<T, U, V> Serialize for (T, U, V)
where
    T: Serialize,
    U: Serialize,
    V: Serialize,
{
    #[inline(always)]
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut written = self.0.tls_serialize(writer)?;
        written += self.1.tls_serialize(writer)?;
        self.2.tls_serialize(writer).map(|l| l + written)
    }
}

impl<T, U, V> Size for (T, U, V)
where
    T: Size,
    U: Size,
    V: Size,
{
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        self.0.tls_serialized_len() + self.1.tls_serialized_len() + self.2.tls_serialized_len()
    }
}
