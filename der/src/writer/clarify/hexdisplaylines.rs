use core::fmt::Write;
use std::fmt;

/// (bytes, indent, nl_ident)
pub struct HexDisplayLines<'a, 'i> {
    pub bytes: &'a [u8],
    pub indent: &'i str,
    pub space: bool,
}

impl fmt::Display for HexDisplayLines<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for chunk in self.bytes.chunks(16) {
            if !first {
                write!(f, "\n{}", self.indent)?;
                if self.space {
                    f.write_char(' ').ok();
                }
            } else {
                first = false;
            }
            for byte in chunk {
                write!(f, "{byte:02X} ")?;
            }
        }
        Ok(())
    }
}
