//! ASN.1 `NULL` support.

use crate::{
    asn1::Any, str_slice::StrSlice, ByteSlice, DecodeValue, Decoder, Encodable, EncodeValue,
    Encoder, Error, ErrorKind, FixedTag, Length, Result, Tag,
};

impl DecodeValue<'_> for f64 {
    fn decode_value(decoder: &mut Decoder<'_>, length: Length) -> Result<Self> {
        let bytes = ByteSlice::decode_value(decoder, length)?.as_bytes();

        if length == Length::ONE && bytes[0] == 0x0 {
            Ok(0.0)
        } else if is_nth_bit_one::<7>(bytes) {
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
            let exponent = match mnth_bits_to_u8::<1, 0>(bytes) {
                0 => {
                    remaining_bytes = bytes.len() - 2;
                    // i16::from_be_bytes([0x0, bytes[1]]).into()
                    u64::decode_value(decoder, Length::new(1))?
                }
                1 => {
                    remaining_bytes = bytes.len() - 3;
                    // i16::from_be_bytes([bytes[1], bytes[2]])
                    u64::decode_value(decoder, Length::new(2))?
                }
                _ => return Err(Error::new(ErrorKind::RealExponentTooLong, Length::ZERO)),
            };
            // Section 8.5.7.5: Read the remaining bytes for the mantissa
            // XXX: Is this correct? I'm afraid this will not correctly pad things
            let remaining_len = (length - Length::new(remaining_bytes.try_into().unwrap()))?;
            let n = u64::decode_value(decoder, remaining_len)?;
            // let n = u64::from_be_bytes(bytes[remaining_bytes..].try_into().unwrap());
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
            let astr = StrSlice::from_bytes(&bytes[3..])?;
            match astr.inner.parse::<f64>() {
                Ok(val) => Ok(val),
                Err(_) => Err(Error::new(ErrorKind::RealISO6093Error, Length::ZERO)),
            }
        }
    }
}

use crate::asn1::integer::uint::encode_bytes;

impl EncodeValue for f64 {
    fn value_len(&self) -> Result<Length> {
        if self.is_nan()
            || self.is_infinite()
            || (self.is_sign_negative() && -self < f64::EPSILON)
            || (self.is_sign_positive() && (*self) < f64::EPSILON)
        {
            Ok(Length::ONE)
        } else {
            // Perform encoding
            let (mantissa, exponent, _sign) = integer_decode_f64(*self);
            // if exponent.is_positive() && exponent < 255 {
            //     // Then the exponent is encoded only on one byte
            //     len += 1;
            // } else {
            //     len += 2;
            // }

            let exponent_len = exponent.encoded_len()?;

            let mantissa_len = mantissa.encoded_len()?;

            exponent_len + mantissa_len
        }
    }

    fn encode_value(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        // Check if special value
        // Encode zero first, if it's zero
        // Special value from section 8.5.9 if non zero
        if self.is_nan()
            || self.is_infinite()
            || (self.is_sign_negative() && -self < f64::EPSILON)
            || (self.is_sign_positive() && (*self) < f64::EPSILON)
        {
            if self.is_sign_positive() && (*self) < f64::EPSILON {
                // Zero
                encoder.bytes(&[0b0000_0000])?;
            } else if self.is_nan() {
                // Not a number
                encoder.bytes(&[0b0100_0010])?;
            } else if self.is_infinite() {
                if self.is_sign_negative() {
                    // Negative infinity
                    encoder.bytes(&[0b0100_0001])?;
                } else {
                    // Plus infinity
                    encoder.bytes(&[0b0100_0000])?;
                }
            } else {
                // Minus zero
                encoder.bytes(&[0b0100_0011])?;
            }
        } else {
            // Always use binary encoding
            let mut first_byte = 0b1000_0000;
            if self.is_sign_negative() {
                first_byte |= 0b0100_0000;
            }

            let (mantissa, exponent, _sign) = integer_decode_f64(*self);
            // Encode the exponent as two's complement on 16 bits
            let exponent_bytes = (exponent as i16).to_be_bytes();
            // If the exponent is encoded only on two bytes, add that info
            if exponent_bytes[0] > 0x0 {
                first_byte |= 0b0000_0001;
            }

            encoder.bytes(&[first_byte])?;

            // Encode both bytes or just the last one, handled by encode_bytes directly
            encode_bytes(encoder, &exponent_bytes)?;
            // if exponent_bytes[0] > 0x0 {
            //     encode_bytes(encoder, &exponent_bytes)?;
            //     // encoder.bytes(&exponent_bytes)?;
            // } else {
            //     encode_bytes(encoder, &exponent_bytes)?;
            //     // encoder.bytes(&exponent_bytes[1..2])?;
            // }

            // Now, encode the mantissa as unsigned binary number
            // mantissa.encode(encoder)?;
            encode_bytes(encoder, &mantissa.to_be_bytes())?;
            // encoder.bytes(&mantissa.to_be_bytes())?;
        }
        Ok(())
    }
}

impl FixedTag for f64 {
    const TAG: Tag = Tag::Real;
}

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
/// NOTE: this function is zero indexed
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

/// Decode an f64 as its sign, exponent, and mantissa in u64 and in that order, using bit shifts and masks
fn integer_decode_f64(f: f64) -> (u64, u64, u64) {
    let bits = f.to_bits();
    let sign = bits >> 63;
    let exponent = bits >> 52 & 0x7ff;
    let mantissa = bits & 0xfffffffffffff;
    (sign, exponent, mantissa)
}

/// Encode an f64 from its sign, exponent, and mantissa using bit shifts
fn integer_encode_f64(sign: u64, exponent: u64, mantissa: u64) -> f64 {
    let bits = sign << 63 | exponent << 52 | mantissa;
    f64::from_bits(bits)
}

#[cfg(test)]
mod tests {
    use crate::{Decodable, Encodable};

    #[test]
    fn decode_subnormal() {
        assert!(f64::from_der(&[0x09, 0x01, 0b0100_0010]).unwrap().is_nan());
        let plus_infty = f64::from_der(&[0x09, 0x01, 0b0100_0000]).unwrap();
        assert!(plus_infty.is_infinite() && plus_infty.is_sign_positive());
        let neg_infty = f64::from_der(&[0x09, 0x01, 0b0100_0001]).unwrap();
        assert!(neg_infty.is_infinite() && neg_infty.is_sign_negative());
        let neg_zero = f64::from_der(&[0x09, 0x01, 0b0100_0011]).unwrap();
        assert!(neg_zero.is_sign_negative() && neg_zero.abs() < f64::EPSILON);
    }

    #[test]
    fn encode_subnormal() {
        // All subnormal fit in three bytes
        let mut buffer = [0u8; 3];
        assert_eq!(
            &[0x09, 0x01, 0b0100_0010],
            f64::NAN.encode_to_slice(&mut buffer).unwrap()
        );
        assert_eq!(
            &[0x09, 0x01, 0b0100_0000],
            f64::INFINITY.encode_to_slice(&mut buffer).unwrap()
        );
        assert_eq!(
            &[0x09, 0x01, 0b0100_0001],
            f64::NEG_INFINITY.encode_to_slice(&mut buffer).unwrap()
        );
        assert_eq!(
            &[0x09, 0x01, 0b0100_0011],
            (-0.0_f64).encode_to_slice(&mut buffer).unwrap()
        );
    }

    #[test]
    fn encdec_normal() {
        {
            let val = 0.0;
            let expected = &[0x09, 0x01, 0x0];
            let mut buffer = [0u8; 3];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!((decoded - val).abs() < f64::EPSILON);
        }

        {
            let val = -1.0;
            let expected = &[0x09, 0x07, 0xc1, 0x03, 0xff, 0x01];
            let mut buffer = [0u8; 6];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            // let decoded = f64::from_der(encoded).unwrap();
            // assert!((decoded - val).abs() < f64::EPSILON);
        }

        {
            let val = 1.0;
            let expected = &[0x09, 0x07, 0x81, 0x03, 0xff, 0x01];
            let mut buffer = [0u8; 6];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            // let decoded = f64::from_der(encoded).unwrap();
            // assert!((decoded - val).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn reject_non_canonical() {
        assert!(f64::from_der(&[0x05, 0x81, 0x00]).is_err());
    }

    #[test]
    fn encdec_f64() {
        use super::{integer_decode_f64, integer_encode_f64};
        // Test that the extraction and recreation works
        for val in [
            0.0,
            -1.0,
            1.0,
            f64::MIN_POSITIVE,
            f64::MAX,
            f64::MIN,
            3.1415,
            951.2357864,
        ] {
            let (m, e, s) = integer_decode_f64(val);
            let val2 = integer_encode_f64(m, e, s);
            assert!((val - val2).abs() < f64::EPSILON, "fail: {}", val);
        }
    }
}
