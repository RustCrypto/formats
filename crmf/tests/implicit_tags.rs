//! RFC 4211's ASN.1 module is `DEFINITIONS IMPLICIT TAGS`: a context-specific tag replaces the
//! inner type's tag unless the inner type is a CHOICE (X.680 31.2.7), which is tagged explicitly.

use crmf::controls::PkiArchiveOptions;
use crmf::pop::{POPOPrivKey, ProofOfPossession, SubsequentMessage};
use der::{Decode, Encode};

/// Decode, and check the value re-encodes to the same bytes.
fn round_trip<'a, T>(bytes: &'a [u8]) -> T
where
    T: Decode<'a> + Encode,
    <T as Decode<'a>>::Error: core::fmt::Debug,
{
    let value = T::from_der(bytes).unwrap();
    assert_eq!(value.to_der().unwrap(), bytes);
    value
}

/// `POPOPrivKey` alternatives, encoded by pyasn1 from the RFC 4211 module.
#[test]
fn popo_priv_key_alternatives() {
    assert!(matches!(
        round_trip::<POPOPrivKey>(&[0x80, 0x02, 0x00, 0xa5]),
        POPOPrivKey::ThisMessage(_)
    ));
    assert!(matches!(
        round_trip::<POPOPrivKey>(&[0x81, 0x01, 0x01]),
        POPOPrivKey::SubsequentMessage(SubsequentMessage::ChallengeResp)
    ));
    assert!(matches!(
        round_trip::<POPOPrivKey>(&[0x82, 0x02, 0x00, 0x5a]),
        POPOPrivKey::DhMac(_)
    ));
    // agreeMAC [3] PKMACValue { algId { 1.2.840.113533.7.66.13 }, value BIT STRING 0102 }
    assert!(matches!(
        round_trip::<POPOPrivKey>(&[
            0xa3, 0x12, 0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf6, 0x7d, 0x07, 0x42,
            0x0d, 0x03, 0x03, 0x00, 0x01, 0x02
        ]),
        POPOPrivKey::AgreeMac(_)
    ));
}

/// `PKIArchiveOptions` alternatives, encoded by pyasn1 from the RFC 4211 module.
#[test]
fn pki_archive_options_alternatives() {
    assert!(matches!(
        round_trip::<PkiArchiveOptions>(&[0x81, 0x03, 0x01, 0x02, 0x03]),
        PkiArchiveOptions::KeyGenParameters(_)
    ));
    assert!(matches!(
        round_trip::<PkiArchiveOptions>(&[0x82, 0x01, 0xff]),
        PkiArchiveOptions::ArchiveRemGenPrivKey(true)
    ));
}

/// The `ProofOfPossession` of an `ir` produced by OpenSSL 3.5 `openssl cmp -popo 2` (key
/// encipherment): `[2] { [1] subsequentMessage encrCert }`.
#[test]
fn openssl_key_encipherment_popo() {
    let popo = round_trip::<ProofOfPossession>(&[0xa2, 0x03, 0x81, 0x01, 0x00]);
    assert!(matches!(
        popo,
        ProofOfPossession::KeyEncipherment(POPOPrivKey::SubsequentMessage(
            SubsequentMessage::EncrCert
        ))
    ));
}
