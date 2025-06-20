//! BER encoding reader.

use crate::{EncodingRules, Error, ErrorKind, Length, Reader, Result, SliceReader};
use core::marker::PhantomData;

/// Reader for Basic Encoding Rules with support for indefinite length encoding.
///
/// Wraps an inner [`Reader`] type `R` to support decoding from BER-encoded bytes or PEM.
#[derive(Clone)]
pub struct BerReader<'r, R: Reader<'r>> {
    /// Inner reader type
    inner: R,

    /// Input length (in bytes after possible indefinite length decoding).
    input_len: Length,

    /// Position in the input buffer (in bytes after possible indefinite length decoding).
    position: Length,

    // Phantom lifetime
    phantom: PhantomData<&'r ()>,
}

impl<'r, R> BerReader<'r, R>
where
    R: Reader<'r>,
{
    /// Create a new [`BerReader`] which wraps the given inner reader type.
    pub fn new(inner: R) -> BerReader<'r, R> {
        // TODO(tarcieri): handle indefinite length decoding if necessary
        let input_len = inner.input_len();

        BerReader {
            inner,
            input_len,
            position: Length::ZERO,
            phantom: PhantomData,
        }
    }
}

impl<'r> BerReader<'r, SliceReader<'r>> {
    /// Create a new [`BerReader`] which decodes from the provided byte slice.
    pub fn from_bytes(slice: &'r [u8]) -> Result<BerReader<'r, SliceReader<'r>>> {
        let inner = SliceReader::new(slice)?;
        Ok(Self::new(inner))
    }
}

impl<'r, R> Reader<'r> for BerReader<'r, R>
where
    R: Reader<'r>,
{
    const ENCODING_RULES: EncodingRules = EncodingRules::Ber;

    fn input_len(&self) -> Length {
        // TODO(tarcieri): handle indefinite length data if necessary
        self.inner.input_len()
    }

    fn peek_into(&self, buf: &mut [u8]) -> Result<()> {
        // TODO(tarcieri): decode indefinite length data if needed
        self.inner.peek_into(buf)
    }

    fn position(&self) -> Length {
        // TODO(tarcieri): handle indefinite length data if necessary
        self.inner.position()
    }

    fn read_nested<T, F, E>(&mut self, len: Length, f: F) -> core::result::Result<T, E>
    where
        E: From<Error>,
        F: FnOnce(&mut Self) -> core::result::Result<T, E>,
    {
        let nested_input_len = (self.position + len)?;
        if nested_input_len > self.input_len {
            return Err(Error::incomplete(self.input_len).into());
        }

        let orig_input_len = self.input_len;
        self.input_len = nested_input_len;
        let ret = f(self);
        self.input_len = orig_input_len;
        ret
    }

    fn read_slice(&mut self, _len: Length) -> Result<&'r [u8]> {
        // Can't borrow from BER because it may require indefinite length decoding
        Err(ErrorKind::Reader.into())
    }
}
