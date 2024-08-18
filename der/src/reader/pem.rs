//! Streaming PEM reader.

use super::Reader;
use crate::{Decode, EncodingRules, Error, ErrorKind, Header, Length};
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
    pub fn new(pem: &'i [u8]) -> crate::Result<Self> {
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
    pub fn peek_into(&self, buf: &mut [u8]) -> crate::Result<()> {
        self.clone().read_into(buf)?;
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

    fn peek_header(&self) -> crate::Result<Header> {
        Header::decode(&mut self.clone())
    }

    fn position(&self) -> Length {
        self.position
    }

    fn read_nested<T, F, E>(&mut self, len: Length, f: F) -> Result<T, E>
    where
        F: FnOnce(&mut Self) -> Result<T, E>,
        E: From<Error>,
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

    fn read_slice(&mut self, _len: Length) -> crate::Result<&'i [u8]> {
        // Can't borrow from PEM because it requires decoding
        Err(ErrorKind::Reader.into())
    }

    fn read_into<'o>(&mut self, buf: &'o mut [u8]) -> crate::Result<&'o [u8]> {
        let new_position = (self.position + buf.len())?;
        if new_position > self.input_len {
            return Err(ErrorKind::Incomplete {
                expected_len: new_position,
                actual_len: self.input_len,
            }
            .at(self.position));
        }

        self.decoder.decode(buf)?;
        self.position = new_position;
        Ok(buf)
    }
}
