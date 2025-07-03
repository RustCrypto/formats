use std::fmt;

/// (bytes, indent)
pub struct HexDisplayLines<'a, 'i>(pub &'a [u8], pub &'i str);

impl fmt::Display for HexDisplayLines<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for chunk in self.0.chunks(16) {
            if !first {
                write!(f, "\n{}", self.1)?;
            } else {
                first = false;
            }

            for byte in chunk {
                write!(f, "{:02X} ", byte)?;
            }
        }
        Ok(())
    }
}
