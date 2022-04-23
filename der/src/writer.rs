//! Writer trait.

use crate::Result;

/// Writer trait which outputs encoded DER.
pub trait Writer: Sized {
    /// Write the given DER-encoded bytes as output.
    fn write(&mut self, slice: &[u8]) -> Result<()>;

    /// Write a single byte.
    fn write_byte(&mut self, byte: u8) -> Result<()> {
        self.write(&[byte])
    }
}
