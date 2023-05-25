//! Codec implementations for unsigned integer primitives.

use crate::DeserializeRemainder;

use super::{Deserialize, Error, Serialize, Size};

use core::marker::PhantomData;
#[cfg(feature = "std")]
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

impl<T: Size> Size for &Option<T> {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        (*self).tls_serialized_len()
    }
}

impl<T: Serialize> Serialize for Option<T> {
    #[cfg(feature = "std")]
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

impl<T: Serialize> Serialize for &Option<T> {
    #[cfg(feature = "std")]
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        (*self).tls_serialize(writer)
    }
}

impl<T: Deserialize> Deserialize for Option<T> {
    #[cfg(feature = "std")]
    #[inline]
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

impl<T: DeserializeRemainder> DeserializeRemainder for Option<T> {
    #[inline]
    fn tls_deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let some_or_none = bytes.first().ok_or(Error::EndOfStream)?;
        match some_or_none {
            0 => {
                Ok((None, &bytes[1..]))
            },
            1 => {
                let (element, remainder) = T::tls_deserialize(bytes)?;
                Ok((Some(element), remainder))
            },
            _ => Err(Error::DecodingError(format!("Trying to decode Option<T> with {} for option. It must be 0 for None and 1 for Some.", some_or_none)))
        }
    }
}

macro_rules! impl_unsigned {
    ($t:ty, $bytes:literal) => {
        impl Deserialize for $t {
            #[cfg(feature = "std")]
            #[inline]
            fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
                let mut x = (0 as $t).to_be_bytes();
                bytes.read_exact(&mut x)?;
                Ok(<$t>::from_be_bytes(x))
            }
        }

        impl DeserializeRemainder for $t {
            #[inline]
            fn tls_deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
                // TODO: There's probably a better way of doing this.
                let x = (0 as $t).to_be_bytes();
                let out = bytes[..x.len()]
                    .try_into()
                    .map_err(|_| Error::EndOfStream)?;
                Ok((<$t>::from_be_bytes(out), &bytes[x.len()..]))
            }
        }

        impl Serialize for $t {
            #[cfg(feature = "std")]
            #[inline]
            fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
                let written = writer.write(&self.to_be_bytes())?;
                debug_assert_eq!(written, $bytes);
                Ok(written)
            }
        }

        impl Serialize for &$t {
            #[cfg(feature = "std")]
            #[inline]
            fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
                (*self).tls_serialize(writer)
            }
        }

        impl Size for $t {
            #[inline]
            fn tls_serialized_len(&self) -> usize {
                $bytes
            }
        }

        impl Size for &$t {
            #[inline]
            fn tls_serialized_len(&self) -> usize {
                (*self).tls_serialized_len()
            }
        }
    };
}

impl_unsigned!(u8, 1);
impl_unsigned!(u16, 2);
impl_unsigned!(u32, 4);
impl_unsigned!(u64, 8);

impl From<core::array::TryFromSliceError> for Error {
    fn from(_: core::array::TryFromSliceError) -> Self {
        Self::InvalidInput
    }
}

// Implement (de)serialization for tuple.
impl<T, U> Deserialize for (T, U)
where
    T: Deserialize,
    U: Deserialize,
{
    #[cfg(feature = "std")]
    #[inline(always)]
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        Ok((T::tls_deserialize(bytes)?, U::tls_deserialize(bytes)?))
    }
}

// Implement (de)serialization for tuple.
impl<T, U> DeserializeRemainder for (T, U)
where
    T: DeserializeRemainder,
    U: DeserializeRemainder,
{
    #[inline(always)]
    fn tls_deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (first_element, remainder) = T::tls_deserialize(bytes)?;
        let (second_element, remainder) = U::tls_deserialize(remainder)?;
        Ok(((first_element, second_element), remainder))
    }
}

impl<T, U> Serialize for (T, U)
where
    T: Serialize,
    U: Serialize,
{
    #[cfg(feature = "std")]
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
    #[cfg(feature = "std")]
    #[inline(always)]
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        Ok((
            T::tls_deserialize(bytes)?,
            U::tls_deserialize(bytes)?,
            V::tls_deserialize(bytes)?,
        ))
    }
}

impl<T, U, V> DeserializeRemainder for (T, U, V)
where
    T: DeserializeRemainder,
    U: DeserializeRemainder,
    V: DeserializeRemainder,
{
    #[inline(always)]
    fn tls_deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (first_element, remainder) = T::tls_deserialize(bytes)?;
        let (second_element, remainder) = U::tls_deserialize(remainder)?;
        let (third_element, remainder) = V::tls_deserialize(remainder)?;
        Ok(((first_element, second_element, third_element), remainder))
    }
}

impl<T, U, V> Serialize for (T, U, V)
where
    T: Serialize,
    U: Serialize,
    V: Serialize,
{
    #[cfg(feature = "std")]
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

impl Size for () {
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        0
    }
}

impl Deserialize for () {
    #[cfg(feature = "std")]
    #[inline(always)]
    fn tls_deserialize<R: Read>(_: &mut R) -> Result<(), Error> {
        Ok(())
    }
}

impl DeserializeRemainder for () {
    #[inline(always)]
    fn tls_deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        Ok(((), bytes))
    }
}

impl Serialize for () {
    #[cfg(feature = "std")]
    fn tls_serialize<W: Write>(&self, _: &mut W) -> Result<usize, Error> {
        Ok(0)
    }
}

impl<T> Size for PhantomData<T> {
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        0
    }
}

impl<T> Deserialize for PhantomData<T> {
    #[cfg(feature = "std")]
    #[inline(always)]
    fn tls_deserialize<R: Read>(_: &mut R) -> Result<Self, Error> {
        Ok(PhantomData)
    }
}

impl<T> DeserializeRemainder for PhantomData<T> {
    #[cfg(feature = "std")]
    #[inline(always)]
    fn tls_deserialize(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        Ok((PhantomData, bytes))
    }
}

impl<T> Serialize for PhantomData<T> {
    #[cfg(feature = "std")]
    #[inline(always)]
    fn tls_serialize<W: Write>(&self, _: &mut W) -> Result<usize, Error> {
        Ok(0)
    }
}
