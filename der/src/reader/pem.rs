//! Streaming PEM reader.

use super::Reader;
use crate::{Decode, EncodingRules, ErrorKind, Header, Length, Result};
use pem_rfc7468::Decoder;

/// `Reader` type which decodes PEM on-the-fly.
#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
#[derive(Clone)]
pub struct PemReader<'i> {
    /// Inner PEM decoder.
    decoder: Decoder<'i>,

    /// Encoding rules to apply when decoding the input.
    encoding_rules: EncodingRules,

    /// Input length (in bytes after Base64 decoding).
    input_len: Length,

    /// Position in the input buffer (in bytes after Base64 decoding).
    position: Length,
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl<'i> PemReader<'i> {
    /// Create a new PEM reader which decodes data on-the-fly.
    ///
    /// Uses the default 64-character line wrapping.
    pub fn new(pem: &'i [u8]) -> Result<Self> {
        let decoder = Decoder::new(pem)?;
        let input_len = Length::try_from(decoder.remaining_len())?;

        Ok(Self {
            decoder,
            encoding_rules: EncodingRules::default(),
            input_len,
            position: Length::ZERO,
        })
    }

    /// Get the PEM label which will be used in the encapsulation boundaries
    /// for this document.
    pub fn type_label(&self) -> &'i str {
        self.decoder.type_label()
    }

    /// Peek at the decoded PEM without updating the internal state, writing into the provided
    /// output buffer.
    ///
    /// Attempts to fill the entire buffer, returning an error if there is not enough data.
    pub fn peek_into(&self, buf: &mut [u8]) -> Result<()> {
        self.decoder.clone().decode(buf)?;
        Ok(())
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl<'i> Reader<'i> for PemReader<'i> {
    fn encoding_rules(&self) -> EncodingRules {
        self.encoding_rules
    }

    fn input_len(&self) -> Length {
        self.input_len
    }

    fn peek_byte(&self) -> Option<u8> {
        let mut byte = [0];
        self.peek_into(&mut byte).ok().map(|_| byte[0])
    }

    fn peek_header(&self) -> Result<Header> {
        Header::decode(&mut self.clone())
    }

    fn position(&self) -> Length {
        self.position
    }

    fn read_slice(&mut self, _len: Length) -> Result<&'i [u8]> {
        // Can't borrow from PEM because it requires decoding
        Err(ErrorKind::Reader.into())
    }

    fn read_into<'o>(&mut self, buf: &'o mut [u8]) -> Result<&'o [u8]> {
        let bytes = self.decoder.decode(buf)?;
        self.position = (self.position + bytes.len())?;

        debug_assert_eq!(
            self.position,
            (self.input_len - Length::try_from(self.decoder.remaining_len())?)?
        );

        Ok(bytes)
    }
}
