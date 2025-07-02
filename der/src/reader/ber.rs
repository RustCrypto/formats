//! BER encoding reader.

use super::position::Position;
use crate::{EncodingRules, Error, ErrorKind, Length, Reader, Result, SliceReader};
use core::marker::PhantomData;

/// Reader for Basic Encoding Rules with support for indefinite length encoding.
///
/// Wraps an inner [`Reader`] type `R` to support decoding from BER-encoded bytes or PEM.
#[derive(Clone)]
pub struct BerReader<'r, R: Reader<'r>> {
    /// Inner reader type
    inner: R,

    /// Position tracker.
    position: Position,

    // Phantom lifetime
    phantom: PhantomData<&'r ()>,
}

impl<'r, R> BerReader<'r, R>
where
    R: Reader<'r>,
{
    /// Create a new [`BerReader`] which wraps the given inner reader type.
    pub fn new(inner: R) -> BerReader<'r, R> {
        let position = Position::new(inner.input_len());

        BerReader {
            inner,
            position,
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
        self.position.current()
    }

    fn read_into<'o>(&mut self, buf: &'o mut [u8]) -> Result<&'o [u8]> {
        // TODO(tarcieri): handle indefinite length data if necessary
        self.position.advance(Length::try_from(buf.len())?)?;
        self.inner.read_into(buf)
    }

    fn read_nested<T, F, E>(&mut self, len: Length, f: F) -> core::result::Result<T, E>
    where
        E: From<Error>,
        F: FnOnce(&mut Self) -> core::result::Result<T, E>,
    {
        let resumption = self.position.split_nested(len)?;
        let ret = f(self);
        self.position.resume_nested(resumption);
        ret
    }

    fn read_slice(&mut self, _len: Length) -> Result<&'r [u8]> {
        // Can't borrow from BER because it may require indefinite length decoding
        Err(ErrorKind::Reader.into())
    }
}
