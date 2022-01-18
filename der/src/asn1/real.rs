//! ASN.1 `NULL` support.

use crate::{
    asn1::Any, ByteSlice, DecodeValue, Decoder, Encodable, EncodeValue, Encoder, Error, ErrorKind,
    FixedTag, Length, Result, Tag,
};

impl DecodeValue<'_> for f64 {
    fn decode_value(decoder: &mut Decoder<'_>, length: Length) -> Result<Self> {
        let bytes = ByteSlice::decode_value(decoder, length)?.as_bytes();

        // Implementation of section 8.5.6
        // the nth bit function is zero indexed
        if is_nth_bit_one::<7>(bytes) {
            // Binary encoding from section 8.5.7 applies
            let sign: u64 = if is_nth_bit_one::<6>(bytes) { 1 } else { 0 };
            // Section 8.5.7.2: Check the base -- the DER specs say that only base 2 should be supported in DER, but here we allow decoding of BER, just not encoding of BER
            let base = mnth_bits_to_u8::<5, 4>(bytes);
            if base != 0 {
                return Err(Error::new(ErrorKind::RealBaseInvalid(base), Length::ZERO));
            }

            // Section 8.5.7.3: grab the scaling factor
            let scaling_factor = mnth_bits_to_u8::<3, 2>(bytes);

            // Section 8.5.7.4:
            // 1. grab the number of octets used to express the exponent;
            // 2. read the exponent as an i32
            let remaining_bytes;
            let exponent: i16 = match mnth_bits_to_u8::<1, 0>(bytes) {
                0 => {
                    remaining_bytes = bytes.len() - 2;
                    i16::from_be_bytes([0x0, bytes[1]]).into()
                }
                1 => {
                    remaining_bytes = bytes.len() - 3;
                    i16::from_be_bytes([bytes[1], bytes[2]])
                }
                _ => return Err(Error::new(ErrorKind::RealExponentTooLong, Length::ZERO)),
            };
            // Section 8.5.7.5: Read the remaining bytes for the mantissa
            // XXX: Is this correct? I'm afraid this will not correctly pad things
            let n = u64::from_be_bytes(bytes[remaining_bytes..].try_into().unwrap());
            // Multiply byt 2^F corresponds to just a left shift
            let mantissa = n << scaling_factor;
            // Create the f64
            return Ok(integer_encode_f64(mantissa, exponent, sign));
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
            #[cfg(feature = "std")]
            {
                // Decimal encoding from section 8.5.8 applies (both bit 8 and 7 are one)
                let iso_kind = mnth_bits_to_u8::<1, 0>(bytes);
                if iso_kind != 3 {
                    return Err(Error::new(
                        ErrorKind::RealISO6093EncodingNotSupported,
                        Length::ZERO,
                    ));
                }
                use std::str;
                let astr = str::from_utf8(&bytes[3..]).unwrap();
                let af64 = astr.parse::<f64>().unwrap();
            }
            #[cfg(not(feature = "std"))]
            {
                return Err(Error::new(
                    ErrorKind::RealISO6093EncodingNotSupported,
                    Length::ZERO,
                ));
            }
        }
    }
}

impl EncodeValue for f64 {
    fn value_len(&self) -> Result<Length> {
        if self.is_nan() || self.is_infinite() {
            Ok(Length::ONE)
        } else {
            let mut len = 0;
            // Perform encoding
            let (mantissa, exponent, _sign) = integer_decode_f64(*self);
            if exponent.is_positive() && exponent < 255 {
                // Then the exponent is encoded only on one byte
                len += 1;
            } else {
                len += 2;
            }

            let mantissa_len = mantissa.encoded_len()?;

            Length::new(len) + mantissa_len
        }
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

/// Decode an f64 as its mantissa, exponent (shifted by 1023!), and sign data, all in u64
/// From num_traits, src/floats.rs
/// https://github.com/rust-num/num-traits/blob/96a89e63258762d51f80ec141fcdf88d481d8dde/src/float.rs#L2008
fn integer_decode_f64(f: f64) -> (u64, i16, u64) {
    let bits = f.to_bits();
    let sign: u64 = if bits >> 63 == 0 { 0 } else { 1 };
    let mut exponent = ((bits >> 52) & 0x7ff) as i16;
    let mantissa = if exponent == 0 {
        (bits & 0xfffffffffffff) << 1
    } else {
        (bits & 0xfffffffffffff) | 0x10000000000000
    };
    // Exponent bias + mantissa shift
    exponent -= 1023 + 52;
    (mantissa, exponent, u64::from(sign))
}

fn integer_encode_f64(mantissa: u64, exponent: i16, sign: u64) -> f64 {
    let exponent = (exponent + 1023 + 52) as u64;
    let vbits = sign << 63 | exponent << 52 | mantissa;
    f64::from_bits(vbits)
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
