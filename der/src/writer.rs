//! Writer trait.

use crate::Result;

#[cfg(feature = "pem")]
use crate::pem;

#[cfg(feature = "std")]
use std::io;

/// Writer trait which outputs encoded DER.
pub trait Writer {
    /// Write the given DER-encoded bytes as output.
    fn write(&mut self, slice: &[u8]) -> Result<()>;

    /// Write a single byte.
    fn write_byte(&mut self, byte: u8) -> Result<()> {
        self.write(&[byte])
    }
}

/// `Writer` type which outputs PEM-encoded data.
#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
pub struct PemWriter<'w>(pem::Encoder<'static, 'w>);

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl<'w> PemWriter<'w> {
    /// Create a new PEM writer which outputs into the provided buffer.
    ///
    /// Uses the default 64-character line wrapping.
    pub fn new(
        type_label: &'static str,
        line_ending: pem::LineEnding,
        out: &'w mut [u8],
    ) -> Result<Self> {
        Ok(Self(pem::Encoder::new(type_label, line_ending, out)?))
    }

    /// Get the PEM label which will be used in the encapsulation boundaries
    /// for this document.
    pub fn type_label(&self) -> &'static str {
        self.0.type_label()
    }

    /// Finish encoding PEM, writing the post-encapsulation boundary.
    ///
    /// On success, returns the total number of bytes written to the output buffer.
    pub fn finish(self) -> Result<usize> {
        Ok(self.0.finish()?)
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl Writer for PemWriter<'_> {
    fn write(&mut self, slice: &[u8]) -> Result<()> {
        self.0.encode(slice)?;
        Ok(())
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<W: io::Write> Writer for W {
    fn write(&mut self, slice: &[u8]) -> Result<()> {
        <Self as io::Write>::write(self, slice)?;
        Ok(())
    }
}
