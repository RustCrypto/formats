//! OID encoder with `const` support.

use crate::{
    arcs::{ARC_MAX_FIRST, ARC_MAX_SECOND},
    Arc, Buffer, Error, ObjectIdentifier, Result,
};

/// BER/DER encoder.
#[derive(Debug)]
pub(crate) struct Encoder<const MAX_SIZE: usize> {
    /// Current state.
    state: State,

    /// Bytes of the OID being BER-encoded in-progress.
    bytes: [u8; MAX_SIZE],

    /// Current position within the byte buffer.
    cursor: usize,
}

/// Current state of the encoder.
#[derive(Debug)]
enum State {
    /// Initial state - no arcs yet encoded.
    Initial,

    /// First arc parsed.
    FirstArc(Arc),

    /// Encoding base 128 body of the OID.
    Body,
}

impl<const MAX_SIZE: usize> Encoder<MAX_SIZE> {
    /// Create a new encoder initialized to an empty default state.
    pub(crate) const fn new() -> Self {
        Self {
            state: State::Initial,
            bytes: [0u8; MAX_SIZE],
            cursor: 0,
        }
    }

    /// Extend an existing OID.
    pub(crate) const fn extend(oid: ObjectIdentifier<MAX_SIZE>) -> Self {
        Self {
            state: State::Body,
            bytes: oid.ber.bytes,
            cursor: oid.ber.length as usize,
        }
    }

    /// Encode an [`Arc`] as base 128 into the internal buffer.
    #[allow(clippy::panic_in_result_fn)]
    pub(crate) const fn arc(mut self, arc: Arc) -> Result<Self> {
        match self.state {
            State::Initial => {
                if arc > ARC_MAX_FIRST {
                    return Err(Error::ArcInvalid { arc });
                }

                self.state = State::FirstArc(arc);
                Ok(self)
            }
            State::FirstArc(first_arc) => {
                if arc > ARC_MAX_SECOND {
                    return Err(Error::ArcInvalid { arc });
                }

                self.state = State::Body;
                self.bytes[0] = match (ARC_MAX_SECOND + 1).checked_mul(first_arc) {
                    // TODO(tarcieri): use `and_then` when const traits are stable
                    Some(n) => match n.checked_add(arc) {
                        Some(byte) => byte as u8,
                        None => {
                            // TODO(tarcieri): use `unreachable!`
                            panic!("overflow prevented by ARC_MAX_SECOND check")
                        }
                    },
                    // TODO(tarcieri): use `unreachable!`
                    None => panic!("overflow prevented by ARC_MAX_SECOND check"),
                };
                self.cursor = 1;
                Ok(self)
            }
            State::Body => {
                let nbytes = base128_len(arc);
                self.encode_base128(arc, nbytes)
            }
        }
    }

    /// Finish encoding an OID.
    pub(crate) const fn finish(self) -> Result<ObjectIdentifier<MAX_SIZE>> {
        if self.cursor == 0 {
            return Err(Error::Empty);
        }

        let ber = Buffer {
            bytes: self.bytes,
            length: self.cursor as u8,
        };

        Ok(ObjectIdentifier { ber })
    }

    /// Encode a single byte of a Base 128 value.
    const fn encode_base128(mut self, n: u32, remaining_len: usize) -> Result<Self> {
        if self.cursor >= MAX_SIZE {
            return Err(Error::Length);
        }

        let mask = if remaining_len > 0 { 0b10000000 } else { 0 };
        let (hi, lo) = split_hi_bits(n);
        self.bytes[self.cursor] = hi | mask;
        self.cursor = checked_add!(self.cursor, 1);

        match remaining_len.checked_sub(1) {
            Some(len) => self.encode_base128(lo, len),
            None => Ok(self),
        }
    }
}

/// Compute the length - 1 of an arc when encoded in base 128.
const fn base128_len(arc: Arc) -> usize {
    match arc {
        0..=0x7f => 0,
        0x80..=0x3fff => 1,
        0x4000..=0x1fffff => 2,
        0x200000..=0x1fffffff => 3,
        _ => 4,
    }
}

/// Split the highest 7-bits of an [`Arc`] from the rest of an arc.
///
/// Returns: `(hi, lo)`
#[inline]
const fn split_hi_bits(arc: Arc) -> (u8, Arc) {
    if arc < 0x80 {
        return (arc as u8, 0);
    }

    let hi_bit = match 32u32.checked_sub(arc.leading_zeros()) {
        Some(bit) => bit,
        None => unreachable!(),
    };

    let hi_bit_mod7 = hi_bit % 7;
    let upper_bit_offset = if hi_bit > 0 && hi_bit_mod7 == 0 {
        7
    } else {
        hi_bit_mod7
    };

    let upper_bit_pos = match hi_bit.checked_sub(upper_bit_offset) {
        Some(bit) => bit,
        None => unreachable!(),
    };

    let upper_bits = arc >> upper_bit_pos;
    let lower_bits = arc ^ (upper_bits << upper_bit_pos);
    (upper_bits as u8, lower_bits)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::Encoder;
    use hex_literal::hex;

    /// OID `1.2.840.10045.2.1` encoded as ASN.1 BER/DER
    const EXAMPLE_OID_BER: &[u8] = &hex!("2A8648CE3D0201");

    #[test]
    fn split_hi_bits_with_gaps() {
        assert_eq!(super::split_hi_bits(0x3a00002), (0x1d, 0x2));
        assert_eq!(super::split_hi_bits(0x3a08000), (0x1d, 0x8000));
    }

    #[test]
    fn encode() {
        let encoder = Encoder::<7>::new();
        let encoder = encoder.arc(1).unwrap();
        let encoder = encoder.arc(2).unwrap();
        let encoder = encoder.arc(840).unwrap();
        let encoder = encoder.arc(10045).unwrap();
        let encoder = encoder.arc(2).unwrap();
        let encoder = encoder.arc(1).unwrap();
        assert_eq!(&encoder.bytes[..encoder.cursor], EXAMPLE_OID_BER);
    }
}
