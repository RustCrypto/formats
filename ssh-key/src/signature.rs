//! Signatures (e.g. CA signatures over SSH certificates)

use crate::{
    checked::CheckedSum,
    decoder::{Decode, Decoder},
    encoder::{Encode, Encoder},
    Algorithm, EcdsaCurve, Error, Result,
};

/// Digital signature (e.g. DSA, ECDSA, Ed25519).
///
/// These are used as part of the OpenSSH certificate format to represent
/// signatures by certificate authorities (CAs).
///
/// From OpenSSH's [PROTOCOL.certkeys] specification:
///
/// > Signatures are computed and encoded according to the rules defined for
/// > the CA's public key algorithm ([RFC4253 section 6.6] for ssh-rsa and
/// > ssh-dss, [RFC5656] for the ECDSA types, and [RFC8032] for Ed25519).
///
/// [PROTOCOL.certkeys]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
/// [RFC4253 section 6.6]: https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
/// [RFC5656]: https://datatracker.ietf.org/doc/html/rfc5656
/// [RFC8032]: https://datatracker.ietf.org/doc/html/rfc8032
// TODO(tarcieri): RSA support
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Signature {
    /// DSA signature.
    Dsa([u8; 40]),

    /// ECDSA/NIST-P256 signature.
    EcdsaSha2NistP256([u8; 64]),

    /// ECDSA/NIST-P384 signature.
    EcdsaSha2NistP384([u8; 96]),

    /// ECDSA/NIST-P384 signature.
    EcdsaSha2NistP521([u8; 132]),

    /// Ed25519 signature.
    Ed25519([u8; 64]),
}

impl Signature {
    /// Get the [`Algorithm`] associated with this signature.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Dsa(_) => Algorithm::Dsa,
            Self::EcdsaSha2NistP256(_) => Algorithm::Ecdsa(EcdsaCurve::NistP256),
            Self::EcdsaSha2NistP384(_) => Algorithm::Ecdsa(EcdsaCurve::NistP384),
            Self::EcdsaSha2NistP521(_) => Algorithm::Ecdsa(EcdsaCurve::NistP521),
            Self::Ed25519(_) => Algorithm::Ed25519,
        }
    }

    /// Get the raw signature as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Dsa(bytes) => bytes,
            Self::EcdsaSha2NistP256(bytes) => bytes,
            Self::EcdsaSha2NistP384(bytes) => bytes,
            Self::EcdsaSha2NistP521(bytes) => bytes,
            Self::Ed25519(bytes) => bytes,
        }
    }

    /// Is this a DSA signature?
    pub fn is_dsa(&self) -> bool {
        matches!(self, Self::Dsa(_))
    }

    /// Is this an ECDSA signature?
    pub fn is_ecdsa(&self) -> bool {
        matches!(
            self,
            Self::EcdsaSha2NistP256(_) | Self::EcdsaSha2NistP384(_) | Self::EcdsaSha2NistP521(_)
        )
    }

    /// Is this an Ed25519 signature?
    pub fn is_ed25519(&self) -> bool {
        matches!(self, Self::Ed25519(_))
    }
}

impl Decode for Signature {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        match Algorithm::decode(decoder)? {
            Algorithm::Dsa => {
                let mut bytes = [0u8; 40];
                decoder.decode_length_prefixed(|decoder, _len| decoder.decode_raw(&mut bytes))?;
                Ok(Self::Dsa(bytes))
            }
            Algorithm::Ecdsa(EcdsaCurve::NistP256) => {
                decode_ecdsa_signature(decoder).map(Self::EcdsaSha2NistP256)
            }
            Algorithm::Ecdsa(EcdsaCurve::NistP384) => {
                decode_ecdsa_signature(decoder).map(Self::EcdsaSha2NistP384)
            }
            Algorithm::Ecdsa(EcdsaCurve::NistP521) => {
                decode_ecdsa_signature(decoder).map(Self::EcdsaSha2NistP521)
            }
            Algorithm::Ed25519 => {
                let mut bytes = [0u8; 64];
                decoder.decode_length_prefixed(|decoder, _len| decoder.decode_raw(&mut bytes))?;
                Ok(Self::Ed25519(bytes))
            }
            _ => Err(Error::Algorithm),
        }
    }
}

impl Encode for Signature {
    fn encoded_len(&self) -> Result<usize> {
        [
            self.algorithm().encoded_len()?,
            4, // signature data length prefix (uint32)
            self.as_bytes().len(),
            8usize
                .checked_mul(usize::from(self.is_ecdsa())) // ecdsa `r`/`s` lengths
                .ok_or(Error::Length)?,
        ]
        .checked_sum()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.algorithm().encode(encoder)?;

        if self.is_ecdsa() {
            encoder.encode_usize([8, self.as_bytes().len()].checked_sum()?)?;
            let (r, s) = self.as_bytes().split_at(self.as_bytes().len() / 2);
            encoder.encode_byte_slice(r)?;
            encoder.encode_byte_slice(s)?;
        } else {
            encoder.encode_byte_slice(self.as_bytes())?;
        }

        Ok(())
    }
}

fn decode_ecdsa_signature<const SIZE: usize>(decoder: &mut impl Decoder) -> Result<[u8; SIZE]> {
    decoder.decode_length_prefixed(|decoder, _len| {
        let mut bytes = [0u8; SIZE];

        // Decode `r` and `s` components of the signature concatenated.
        for chunk in bytes.chunks_mut(SIZE / 2) {
            let len = decoder.decode_byte_slice(chunk)?.len();

            if len != SIZE / 2 {
                return Err(Error::Crypto);
            }
        }

        Ok(bytes)
    })
}

#[cfg(test)]
#[allow(const_item_mutation)] // to use `Decode` impl on `&[u8]`
mod tests {
    use super::Signature;
    use crate::{decoder::Decode, Algorithm, EcdsaCurve};
    use hex_literal::hex;

    #[cfg(feature = "alloc")]
    use {crate::encoder::Encode, alloc::vec::Vec};

    const DSA_SIGNATURE: &[u8] = &hex!("000000077373682d6473730000002866725bf3c56100e975e21fff28a60f73717534d285ea3e1beefc2891f7189d00bd4d94627e84c55c");
    const ECDSA_SHA2_P256_SIGNATURE: &[u8] = &hex!("0000001365636473612d736861322d6e6973747032353600000048000000201298ab320720a32139cda8a40c97a13dc54ce032ea3c6f09ea9e87501e48fa1d0000002046e4ac697a6424a9870b9ef04ca1182cd741965f989bd1f1f4a26fd83cf70348");
    const ED25519_SIGNATURE: &[u8] = &hex!("0000000b7373682d65643235353139000000403d6b9906b76875aef1e7b2f1e02078a94f439aebb9a4734da1a851a81e22ce0199bbf820387a8de9c834c9c3cc778d9972dcbe70f68d53cc6bc9e26b02b46d04");

    #[test]
    fn decode_dsa() {
        let signature = Signature::decode(&mut DSA_SIGNATURE).unwrap();
        assert_eq!(Algorithm::Dsa, signature.algorithm());
    }

    #[test]
    fn decode_ecdsa_sha2_p256() {
        let signature = Signature::decode(&mut ECDSA_SHA2_P256_SIGNATURE).unwrap();
        assert_eq!(
            Algorithm::Ecdsa(EcdsaCurve::NistP256),
            signature.algorithm()
        );
    }

    #[test]
    fn decode_ed25519() {
        let signature = Signature::decode(&mut ED25519_SIGNATURE).unwrap();
        assert_eq!(Algorithm::Ed25519, signature.algorithm());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn encode_dsa() {
        let signature = Signature::decode(&mut DSA_SIGNATURE).unwrap();

        let mut result = Vec::new();
        signature.encode(&mut result).unwrap();
        assert_eq!(DSA_SIGNATURE, &result);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn encode_ecdsa_sha2_p256() {
        let signature = Signature::decode(&mut ECDSA_SHA2_P256_SIGNATURE).unwrap();

        let mut result = Vec::new();
        signature.encode(&mut result).unwrap();
        assert_eq!(ECDSA_SHA2_P256_SIGNATURE, &result);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn encode_ed25519() {
        let signature = Signature::decode(&mut ED25519_SIGNATURE).unwrap();

        let mut result = Vec::new();
        signature.encode(&mut result).unwrap();
        assert_eq!(ED25519_SIGNATURE, &result);
    }
}
