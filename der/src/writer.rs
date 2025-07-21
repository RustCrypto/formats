//! Writer trait.

#[cfg(feature = "clarify")]
pub mod clarify;
#[cfg(feature = "pem")]
pub(crate) mod pem;
pub(crate) mod slice;

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

    #[cfg(feature = "clarify")]
    /// Should return Some(clarifier) for clarify writers
    fn clarifier(&mut self) -> Option<&mut impl clarify::Clarifier> {
        Option::<&mut clarify::CommentClarifier<()>>::None
    }
}

#[cfg(feature = "std")]
impl<W: io::Write> Writer for W {
    fn write(&mut self, slice: &[u8]) -> Result<()> {
        <Self as io::Write>::write(self, slice)?;
        Ok(())
    }
}
