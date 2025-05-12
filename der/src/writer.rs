//! Writer trait.

#[cfg(feature = "clarify")]
pub(crate) mod clarify;
#[cfg(feature = "pem")]
pub(crate) mod pem;
pub(crate) mod slice;

use crate::Result;

#[cfg(feature = "std")]
use std::io;

#[cfg(feature = "clarify")]
use crate::Tag;

/// Writer trait which outputs encoded DER.
pub trait Writer {
    /// Write the given DER-encoded bytes as output.
    fn write(&mut self, slice: &[u8]) -> Result<()>;

    /// Write a single byte.
    fn write_byte(&mut self, byte: u8) -> Result<()> {
        self.write(&[byte])
    }

    #[cfg(feature = "clarify")]
    /// Should return true for clarify writers
    fn is_clarify(&self) -> bool {
        false
    }

    #[cfg(feature = "clarify")]
    /// Called when starting next TLV value
    fn clarify_start_value_type<T>(&mut self) {
        // can be overrided
    }

    #[cfg(feature = "clarify")]
    /// Called when ending next TLV value
    fn clarify_end_value_type<T>(&mut self) {
        // can be overrided
    }

    #[cfg(feature = "clarify")]
    /// Called when starting next TLV tag
    fn clarify_start_tag(&mut self, _tag: &Tag) {
        // can be overrided
    }

    #[cfg(feature = "clarify")]
    /// Called when ending next TLV tag
    fn clarify_end_tag(&mut self, _tag: &Tag) {
        // can be overrided
    }

    #[cfg(feature = "clarify")]
    /// Called when writing field with name
    fn clarify_field_name(&mut self, _field_name: &str) {
        // can be overrided
    }

    #[cfg(feature = "clarify")]
    // Called when writing choice, e.g. enum name: "DnsName"
    fn clarify_choice(&mut self, _choice_name: &[u8]) {
        // can be overrided
    }
}

#[cfg(feature = "std")]
impl<W: io::Write> Writer for W {
    fn write(&mut self, slice: &[u8]) -> Result<()> {
        <Self as io::Write>::write(self, slice)?;
        Ok(())
    }
}
