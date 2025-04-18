//! Adapter for Digest objects to write bytes to

use digest::Digest;

use super::Writer;
use crate::Result;

/// Adapter object to write to a digest backend
pub struct DigestWriter<'d, D>(pub &'d mut D);

impl<D> Writer for DigestWriter<'_, D>
where
    D: Digest,
{
    fn write(&mut self, slice: &[u8]) -> Result<()> {
        self.0.update(slice);
        Ok(())
    }
}
