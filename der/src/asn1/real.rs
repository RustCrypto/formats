//! ASN.1 `NULL` support.

use crate::{
    asn1::Any, ByteSlice, DecodeValue, Decoder, Encodable, EncodeValue, Encoder, Error, ErrorKind,
    FixedTag, Length, OrdIsValueOrd, Result, Tag,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum SubnormalKind {
    PlusInfinity,
    MinusInfinity,
    NotANumber,
}

// ASN.1 `REAL` type.
// #[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
// pub enum Real {
//     Normal {
//         mantissa: i32,
//         base: u8,
//         exponent: i32,
//     },
//     Subnormal(SubnormalKind),
// }

// ASN.1 `REAL` type.
// TODO: define as Real<$t>($t) and impl for f32 and f64
// #[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
// pub struct Real(f64);

impl DecodeValue<'_> for f64 {
    fn decode_value(decoder: &mut Decoder<'_>, length: Length) -> Result<Self> {
        let bytes = ByteSlice::decode_value(decoder, length)?.as_bytes();

        // Implementation of section 8.5.6
        // the nth bit function is zero indexed
        if is_nth_bit_one::<7>(bytes) {
            // Binary encoding from section 8.5.7 applies
            let sign: u64 = if is_nth_bit_one::<6>(bytes) { 1 } else { 0 };
            // Section 8.5.7.2: Check the base -- the DER specs say that only base 2 should be supported in DER, but here we allow decoding of BER, just not encoding of BER
            match mnth_bits_to_u8::<5, 4>(bytes) {
                0 => (),
                1 => unimplemented!("DER only supports REAL type in base 2 (provided a base 8 REAL)"),
                2 => unimplemented!("DER only supports REAL type in base 2 (provided a base 16 REAL)"),
                3 => unimplemented!("Reserved for further editions of this Recommendation | International Standard."),
                _ => unreachable!()
            };

            // Section 8.5.7.3: grab the scaling factor
            let scaling_factor = mnth_bits_to_u8::<3, 2>(bytes);

            // Section 8.5.7.4:
            // 1. grab the number of octets used to express the exponent;
            // 2. read the exponent as an i32
            let remaining_bytes;
            let exponent: i32 = match mnth_bits_to_u8::<1, 0>(bytes) {
                0 => {
                    remaining_bytes = bytes.len() - 2;
                    i8::from_be_bytes([bytes[1]]).into()
                }
                1 => {
                    remaining_bytes = bytes.len() - 3;
                    i16::from_be_bytes([bytes[1], bytes[2]]).into()
                }
                2 => {
                    remaining_bytes = bytes.len() - 4;
                    i32::from_be_bytes([bytes[1], bytes[2], bytes[3], 0x0]).into()
                }
                3 => {
                    // This is where the next octet encodes this value
                    let exp_len = usize::from(u8::from_be_bytes([bytes[1]]));
                    if exp_len > 4 {
                        unimplemented!("Exponent is encoded in more than 4 bits, but that cannot be represented in Rust (i32 is 4 bits long)");
                    }
                    remaining_bytes = bytes.len() - exp_len;
                    i32::from_be_bytes(bytes[2..2 + exp_len].try_into().unwrap())
                }
                _ => unreachable!(),
            };
            if exponent > 1023 || exponent < -1022 {
                unimplemented!("Exponent too large to be represented as a IEEE 754");
            }
            // Section 8.5.7.5: Read the remaining bytes for the mantissa
            // XXX: Is this correct? I'm afraid this will not correctly pad things
            let n = u64::from_be_bytes(bytes[remaining_bytes..].try_into().unwrap());
            // Multiply byt 2^F corresponds to just a left shift
            let mantissa = n << scaling_factor;
            let m_bytes = mantissa.to_be_bytes();
            if m_bytes[0] > 0x0 || m_bytes[1] > 0x0f {
                // Only 52 bits can be stored
                unimplemented!("Mantissa too large to be represented as IEEE 754");
            }
            let exponent_bits: u64 = (exponent + 1032).try_into().unwrap();
            // Create the f64
            let bits = sign << 63 | exponent_bits << 52 | mantissa;
            return Ok(f64::from_bits(bits));
        } else if is_nth_bit_one::<6>(bytes) {
            // This either a special value, or it's the value minus zero is encoded, section 8.5.9 applies
            return match mnth_bits_to_u8::<1, 0>(bytes) {
                0 => Ok(f64::INFINITY),
                1 => Ok(f64::NEG_INFINITY),
                2 => Ok(f64::NAN),
                3 => Ok(-0.0_f64),
                _ => unreachable!(),
            };
        } else {
            // Decimal encoding from section 8.5.8 applies (both bit 8 and 7 are one)
            match mnth_bits_to_u8::<1, 0>(bytes) {
                0 => unimplemented!("Malformed decimal real"),
                1 => unimplemented!("DER only supports REAL type in NR3 encoded (NR1 provided)"),
                2 => unimplemented!("DER only supports REAL type in NR3 encoded (NR2 provided)"),
                3 => (),
                _ => unreachable!(),
            };
        }

        if length.is_zero() {
            todo!()
            // Ok(f64)
        } else {
            Err(decoder.error(ErrorKind::Length { tag: Self::TAG }))
        }
    }
}

impl EncodeValue for f64 {
    fn value_len(&self) -> Result<Length> {
        Ok(Length::ZERO)
    }

    fn encode_value(&self, _encoder: &mut Encoder<'_>) -> Result<()> {
        Ok(())
    }
}

impl FixedTag for f64 {
    const TAG: Tag = Tag::Real;
}

// impl OrdIsValueOrd for Real {}

impl<'a> From<f64> for Any<'a> {
    fn from(_: f64) -> Any<'a> {
        Any::from_tag_and_value(Tag::Real, ByteSlice::default())
    }
}

impl TryFrom<Any<'_>> for f64 {
    type Error = Error;

    fn try_from(any: Any<'_>) -> Result<f64> {
        any.decode_into()
    }
}

// impl TryFrom<Any<'_>> for () {
//     type Error = Error;

//     fn try_from(any: Any<'_>) -> Result<()> {
//         Real::try_from(any).map(|_| ())
//     }
// }

// impl<'a> From<()> for Any<'a> {
//     fn from(_: ()) -> Any<'a> {
//         Real.into()
//     }
// }

// impl DecodeValue<'_> for () {
//     fn decode_value(decoder: &mut Decoder<'_>, length: Length) -> Result<Self> {
//         Real::decode_value(decoder, length)?;
//         Ok(())
//     }
// }

// impl Encodable for () {
//     fn encoded_len(&self) -> Result<Length> {
//         Real.encoded_len()
//     }

//     fn encode(&self, encoder: &mut Encoder<'_>) -> Result<()> {
//         Real.encode(encoder)
//     }
// }

// impl FixedTag for () {
//     const TAG: Tag = Tag::Real;
// }

/// Is the N-th bit 1 in the first octet?
fn is_nth_bit_one<const N: usize>(bytes: &[u8]) -> bool {
    let mask = match N {
        0 => 0b00000001,
        1 => 0b00000010,
        2 => 0b00000100,
        3 => 0b00001000,
        4 => 0b00010000,
        5 => 0b00100000,
        6 => 0b01000000,
        7 => 0b10000000,
        _ => return false,
    };
    bytes.get(0).map(|byte| byte & mask != 0).unwrap_or(false)
}

/// Convert bits M, N into a u8, in the first octet only
fn mnth_bits_to_u8<const M: usize, const N: usize>(bytes: &[u8]) -> u8 {
    let bit_m = is_nth_bit_one::<M>(bytes);
    let bit_n = is_nth_bit_one::<N>(bytes);
    let data = if bit_m && bit_n {
        0b11
    } else if !bit_m && !bit_n {
        0b00
    } else if bit_n {
        0b01
    } else {
        0b10
    };
    u8::from_be_bytes([data])
}

#[cfg(test)]
mod tests {
    use crate::{Decodable, Encodable};

    #[test]
    fn decode() {
        f64::from_der(&[0x05, 0x00]).unwrap();
    }

    #[test]
    fn encode() {
        let mut buffer = [0u8; 2];
        assert_eq!(&[0x05, 0x00], 0.1_f64.encode_to_slice(&mut buffer).unwrap());
        assert_eq!(&[0x05, 0x00], ().encode_to_slice(&mut buffer).unwrap());
    }

    #[test]
    fn reject_non_canonical() {
        assert!(f64::from_der(&[0x05, 0x81, 0x00]).is_err());
    }
}
