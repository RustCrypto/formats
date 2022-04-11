//! OpenSSH certificate options used by critical options and extensions.

use crate::{
    checked::CheckedSum, decode::Decode, encode::Encode, reader::Reader, writer::Writer, Error,
    Result,
};
use alloc::{string::String, vec::Vec};
use core::cmp::Ordering;

/// Key/value map type used for certificate's critical options and extensions.
pub type OptionsMap = alloc::collections::BTreeMap<String, String>;

impl Decode for OptionsMap {
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        reader.read_nested(|reader| {
            let mut entries = Vec::<(String, String)>::new();

            while !reader.is_finished() {
                let name = String::decode(reader)?;
                let data = String::decode(reader)?;

                // Options must be lexically ordered by "name" if they appear in
                // the sequence. Each named option may only appear once in a
                // certificate.
                if let Some((prev_name, _)) = entries.last() {
                    if prev_name.cmp(&name) != Ordering::Less {
                        return Err(Error::FormatEncoding);
                    }
                }

                entries.push((name, data));
            }

            Ok(OptionsMap::from_iter(entries))
        })
    }
}

impl Encode for OptionsMap {
    fn encoded_len(&self) -> Result<usize> {
        self.iter().try_fold(4, |acc, (name, data)| {
            [acc, 4, name.len(), 4, data.len()].checked_sum()
        })
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.encoded_len()?
            .checked_sub(4)
            .ok_or(Error::Length)?
            .encode(writer)?;

        for (name, data) in self {
            name.encode(writer)?;
            data.encode(writer)?;
        }

        Ok(())
    }
}
