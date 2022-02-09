use core::ops::Deref;

use const_oid::{ObjectIdentifier, Typed};
use der::{asn1::BitString, DecodeValue, EncodeValue, FixedTag};
use flagset::{flags, FlagSet};

flags! {
    /// The set of valid key usages
    pub enum KeyUsages: u16 {
        /// DigitalSignature
        DigitalSignature,

        /// NonRepudiation
        NonRepudiation,

        /// KeyEncipherment
        KeyEncipherment,

        /// DataEncipherment
        DataEncipherment,

        /// KeyAgreement
        KeyAgreement,

        /// KeyCertSign
        KeyCertSign,

        /// CRLSign
        CRLSign,

        /// EncipherOnly
        EncipherOnly,

        /// DecipherOnly
        DecipherOnly,
    }
}

/// Key usage extension as defined in [RFC 5280 Section 4.2.1.3].
///
/// ```text
/// KeyUsage ::= BIT STRING {
///     digitalSignature        (0),
///     nonRepudiation          (1),  -- recent editions of X.509 have
///                                   -- renamed this bit to contentCommitment
///     keyEncipherment         (2),
///     dataEncipherment        (3),
///     keyAgreement            (4),
///     keyCertSign             (5),
///     cRLSign                 (6),
///     encipherOnly            (7),
///     decipherOnly            (8)
/// }
/// ```
///
/// [RFC 5280 Section 4.2.1.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct KeyUsage(FlagSet<KeyUsages>);

impl From<FlagSet<KeyUsages>> for KeyUsage {
    fn from(usage: FlagSet<KeyUsages>) -> Self {
        Self(usage)
    }
}

impl From<KeyUsage> for FlagSet<KeyUsages> {
    fn from(usage: KeyUsage) -> Self {
        usage.0
    }
}

impl Deref for KeyUsage {
    type Target = FlagSet<KeyUsages>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Typed for KeyUsage {
    const OID: const_oid::ObjectIdentifier = ObjectIdentifier::new("2.5.29.15");
}

impl FixedTag for KeyUsage {
    const TAG: der::Tag = BitString::TAG;
}

impl<'a> DecodeValue<'a> for KeyUsage {
    fn decode_value(decoder: &mut der::Decoder<'a>, header: der::Header) -> der::Result<Self> {
        Ok(Self(FlagSet::decode_value(decoder, header)?))
    }
}

impl<'a> EncodeValue for KeyUsage {
    fn value_len(&self) -> der::Result<der::Length> {
        self.0.value_len()
    }

    fn encode_value(&self, encoder: &mut der::Encoder<'_>) -> der::Result<()> {
        self.0.encode_value(encoder)
    }
}
