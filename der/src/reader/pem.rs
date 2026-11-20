//! Streaming PEM reader.

use super::{Reader, position::Position};
use crate::{EncodingRules, Error, ErrorKind, Length, Result};
use core::fmt;
use pem_rfc7468::Decoder;

/// `Reader` type which decodes PEM on-the-fly.
#[derive(Clone)]
pub struct PemReader<'i> {
    /// Inner PEM decoder.
    decoder: Decoder<'i>,

    /// Encoding rules to apply when decoding the input.
    encoding_rules: EncodingRules,

    /// Position tracker.
    position: Position,
}

impl<'i> PemReader<'i> {
    /// Create a new PEM reader which decodes data on-the-fly.
    ///
    /// Uses the default 64-character line wrapping.
    ///
    /// # Errors
    /// If a decoding error occurred.
    pub fn new(pem: &'i [u8]) -> Result<Self> {
        let decoder = Decoder::new(pem)?;
        let input_len = Length::try_from(decoder.remaining_len())?;

        Ok(Self {
            decoder,
            encoding_rules: EncodingRules::default(),
            position: Position::new(input_len),
        })
    }

    /// Get the PEM label which will be used in the encapsulation boundaries
    /// for this document.
    #[must_use]
    pub fn type_label(&self) -> &'i str {
        self.decoder.type_label()
    }
}

impl<'i> Reader<'static> for PemReader<'i> {
    const CAN_READ_SLICE: bool = false;

    fn encoding_rules(&self) -> EncodingRules {
        self.encoding_rules
    }

    fn input_len(&self) -> Length {
        self.position.input_len()
    }

    fn position(&self) -> Length {
        self.position.current()
    }

    fn read_nested<T, F, E>(&mut self, len: Length, f: F) -> core::result::Result<T, E>
    where
        F: FnOnce(&mut Self) -> core::result::Result<T, E>,
        E: From<Error>,
    {
        let resumption = self.position.split_nested(len)?;
        let ret = f(self);
        let finished = self.is_finished();
        let decoded = self.position.current();
        let remaining = self.remaining_len();

        self.position.resume_nested(resumption);

        if ret.is_ok() && !finished {
            return Err(self
                .error(ErrorKind::TrailingData { decoded, remaining })
                .into());
        }

        ret
    }

    fn read_slice(&mut self, _len: Length) -> Result<&'static [u8]> {
        // Can't borrow from PEM because it requires decoding
        Err(self.error(ErrorKind::Reader))
    }

    fn read_into<'o>(&mut self, buf: &'o mut [u8]) -> Result<&'o [u8]> {
        self.position.advance(Length::try_from(buf.len())?)?;
        self.decoder.decode(buf)?;
        Ok(buf)
    }
}

impl fmt::Debug for PemReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PemReader")
            .field("position", &self.position)
            .field("encoding_rules", &self.encoding_rules)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::PemReader;
    use crate::{
        Error, ErrorKind, Length, Reader,
        pem::{self, LineEnding},
    };
    use hex_literal::hex;

    #[test]
    fn nested_trailing_data() {
        let pem = pem::encode_string("TEST", LineEnding::LF, &hex!("0102")).unwrap();
        let mut reader = PemReader::new(pem.as_bytes()).unwrap();

        let err: Error = reader
            .read_nested(2u8.into(), |reader| {
                reader.read_byte()?;
                Ok(())
            })
            .expect_err("read_nested should return Err when the callback did not consume the complete contents of the nested value");

        assert_eq!(Length::ONE, err.position().unwrap());
        assert_eq!(
            ErrorKind::TrailingData {
                decoded: 1u8.into(),
                remaining: 1u8.into(),
            },
            err.kind()
        );
    }
}
