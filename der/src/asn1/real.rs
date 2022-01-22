//! ASN.1 `NULL` support.

use crate::asn1::integer::uint::{encode_bytes, encoded_len};
use crate::{
    asn1::Any, str_slice::StrSlice, ByteSlice, DecodeValue, Decoder, EncodeValue, Encoder, Error,
    ErrorKind, FixedTag, Length, Result, Tag,
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

            // Section 8.5.7.3
            let scaling_factor = mnth_bits_to_u8::<3, 2>(bytes);

            // Section 8.5.7.4
            let mantissa_start;
            let exponent = match mnth_bits_to_u8::<1, 0>(bytes) {
                0 => {
                    mantissa_start = 2;
                    u64::from_be_bytes([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, bytes[1]])
                }
                1 => {
                    mantissa_start = 3;
                    u64::from_be_bytes([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, bytes[1], bytes[2]])
                }
                _ => return Err(Error::new(ErrorKind::RealExponentTooLong, Length::ZERO)),
            };
            // Section 8.5.7.5: Read the remaining bytes for the mantissa
            // FIXME: Fill backward but in a better way
            let mut n_bytes = [0x0; 8];
            for (pos, byte) in bytes[mantissa_start..].iter().rev().enumerate() {
                n_bytes[7 - pos] = *byte;
            }
            let n = u64::from_be_bytes(n_bytes);
            // Multiply byt 2^F corresponds to just a left shift
            let mantissa = n << scaling_factor;
            // Create the f64
            Ok(integer_encode_f64(sign, exponent, mantissa))
        } else if is_nth_bit_one::<6>(bytes) {
            // This either a special value, or it's the value minus zero is encoded, section 8.5.9 applies
            match mnth_bits_to_u8::<1, 0>(bytes) {
                0 => Ok(f64::INFINITY),
                1 => Ok(f64::NEG_INFINITY),
                2 => Ok(f64::NAN),
                3 => Ok(-0.0_f64),
                _ => unreachable!(),
            }
        } else {
            let astr = StrSlice::from_bytes(&bytes[3..])?;
            match astr.inner.parse::<f64>() {
                Ok(val) => Ok(val),
                Err(_) => Err(Error::new(ErrorKind::RealISO6093Error, Length::ZERO)),
            }
        }
    }
}

impl EncodeValue for f64 {
    fn value_len(&self) -> Result<Length> {
        if self.is_nan()
            || self.is_infinite()
            || (self.is_sign_negative() && -self < f64::MIN_POSITIVE)
            || (self.is_sign_positive() && (*self) < f64::MIN_POSITIVE)
        {
            Ok(Length::ONE)
        } else {
            // The length is that of the first octets plus those needed for the exponent plus those needed for the mantissa
            let (_sign, exponent, mantissa) = integer_decode_f64(*self);
            let exponent_len = encoded_len(&exponent.to_be_bytes())?;
            let mantissa_len = encoded_len(&mantissa.to_be_bytes())?;
            Length::ONE + exponent_len + mantissa_len
        }
    }

    fn encode_value(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        // Check if special value
        // Encode zero first, if it's zero
        // Special value from section 8.5.9 if non zero
        if self.is_nan()
            || self.is_infinite()
            || (self.is_sign_negative() && -self < f64::MIN_POSITIVE)
            || (self.is_sign_positive() && (*self) < f64::MIN_POSITIVE)
        {
            if self.is_sign_positive() && (*self) < f64::MIN_POSITIVE {
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

            let (_sign, exponent, mut mantissa) = integer_decode_f64(*self);
            // Check that the mantissa is either zero or odd
            if mantissa % 2 == 0 && mantissa != 0 {
                // Shift by one, store that as scaling factor
                mantissa >>= 1;
                first_byte |= 0b0000_0100;
                assert!((mantissa % 2 == 0 && mantissa != 0) || (mantissa % 2 == 1));
            }
            // Encode the exponent as two's complement on 16 bits
            let exponent_bytes = (exponent as i16).to_be_bytes();
            // If the exponent is encoded only on two bytes, add that info
            if exponent_bytes[0] > 0x0 {
                first_byte |= 0b0000_0001;
            }

            encoder.bytes(&[first_byte])?;

            // Encode both bytes or just the last one, handled by encode_bytes directly
            encode_bytes(encoder, &exponent_bytes)?;

            // Now, encode the mantissa as unsigned binary number
            encode_bytes(encoder, &mantissa.to_be_bytes())?;
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

/// Is the N-th bit 1 in the first octet?
/// NOTE: this function is zero indexed
pub(crate) fn is_nth_bit_one<const N: usize>(bytes: &[u8]) -> bool {
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
pub(crate) fn mnth_bits_to_u8<const M: usize, const N: usize>(bytes: &[u8]) -> u8 {
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
pub(crate) fn integer_decode_f64(f: f64) -> (u64, u64, u64) {
    let bits = f.to_bits();
    let sign = bits >> 63;
    let exponent = bits >> 52 & 0x7ff;
    let mantissa = bits & 0xfffffffffffff;
    (sign, exponent, mantissa)
}

/// Encode an f64 from its sign, exponent, and mantissa using bit shifts
pub(crate) fn integer_encode_f64(sign: u64, exponent: u64, mantissa: u64) -> f64 {
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
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = f64::MIN_POSITIVE;
            let expected = &[0x09, 0x03, 0x80, 0x01, 0x0];
            let mut buffer = [0u8; 6];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = -1.0;
            let expected = &[0x09, 0x04, 0xc1, 0x03, 0xff, 0x00];
            let mut buffer = [0u8; 6];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = 1.0;
            let expected = &[0x09, 0x04, 0x81, 0x03, 0xff, 0x00];
            let mut buffer = [0u8; 6];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = -1.0000000000000002;
            let expected = &[0x09, 0x04, 0xc1, 0x03, 0xff, 0x01];
            let mut buffer = [0u8; 6];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = f64::MAX;
            let expected = &[9, 10, 129, 7, 254, 15, 255, 255, 255, 255, 255, 255];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }
    }

    #[test]
    fn encdec_irrationals() {
        {
            let val = core::f64::consts::PI;
            let expected = &[9, 10, 133, 4, 0, 4, 144, 253, 170, 34, 22, 140];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = core::f64::consts::E;
            let expected = &[9, 10, 129, 4, 0, 5, 191, 10, 139, 20, 87, 105];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }
        {
            let val = core::f64::consts::LN_2;
            let expected = &[9, 10, 129, 3, 254, 6, 46, 66, 254, 250, 57, 239];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }
    }

    #[test]
    fn encdec_reasonable_f64() {
        // Tests the encoding and decoding of reals with some arbitrary numbers
        {
            let val = 3221417.1584163485;
            let expected = &[9, 10, 133, 4, 20, 4, 73, 234, 74, 35, 126, 83];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = 13364022.365665454;
            let expected = &[9, 10, 133, 4, 22, 4, 190, 179, 101, 217, 196, 5];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = -32343.132588105735;
            let expected = &[9, 10, 197, 4, 13, 7, 202, 228, 62, 41, 105, 63];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = -27084.866751869475;
            let expected = &[9, 10, 193, 4, 13, 10, 115, 55, 120, 220, 213, 73];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = -252.28566647111404;
            let expected = &[9, 10, 197, 4, 6, 7, 196, 146, 23, 1, 111, 250];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = -14.399709612928548;
            let expected = &[9, 10, 193, 4, 2, 12, 204, 166, 189, 6, 217, 145];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = -0.08340570261832964;
            let expected = &[9, 10, 197, 3, 251, 2, 173, 9, 190, 133, 215, 30];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = 0.00536851453803701;
            let expected = &[9, 10, 133, 3, 247, 2, 254, 165, 210, 243, 166, 73];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = 0.00045183525648866433;
            let expected = &[9, 10, 133, 3, 243, 6, 206, 68, 211, 44, 153, 156];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = 0.000033869092002682955;
            let expected = &[9, 10, 129, 3, 240, 1, 193, 213, 35, 213, 84, 123];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = 0.0000011770891033600088;
            let expected = &[9, 10, 129, 3, 235, 3, 191, 143, 39, 244, 98, 85];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = 0.00000005549514041997082;
            let expected = &[9, 10, 133, 3, 230, 6, 229, 152, 213, 183, 92, 107];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = 0.0000000012707044685547803;
            let expected = &[9, 10, 133, 3, 225, 2, 234, 79, 5, 121, 127, 143];
            let mut buffer = [0u8; 12];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }

        {
            let val = 0.00000000002969611878378562;
            let expected = &[9, 9, 129, 3, 220, 83, 91, 111, 151, 238, 181];
            let mut buffer = [0u8; 11];
            let encoded = val.encode_to_slice(&mut buffer).unwrap();
            assert_eq!(expected, encoded, "invalid encoding of {}", val);
            let decoded = f64::from_der(encoded).unwrap();
            assert!(
                (decoded - val).abs() < f64::EPSILON,
                "wanted: {}\tgot: {}",
                val,
                decoded
            );
        }
    }

    #[test]
    fn reject_non_canonical() {
        assert!(f64::from_der(&[0x09, 0x81, 0x00]).is_err());
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
            let (s, e, m) = integer_decode_f64(val);
            let val2 = integer_encode_f64(s, e, m);
            assert!((val - val2).abs() < f64::EPSILON, "fail: {}", val);
        }
    }
}
