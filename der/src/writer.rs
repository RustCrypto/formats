//! Writer trait.

use crate::Result;

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

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<W: io::Write> Writer for W {
    fn write(&mut self, slice: &[u8]) -> Result<()> {
        <Self as io::Write>::write(self, slice)?;
        Ok(())
    }
}
