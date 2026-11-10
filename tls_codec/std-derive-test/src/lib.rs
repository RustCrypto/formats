//! Derived `std` codecs (`TlsSerialize` / `TlsDeserialize`) of one struct and one enum, shaped
//! like OpenMLS wire types (a test of TlsCodec's std derive tactics).

use tls_codec::{
    TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSerializeBytes, TlsSize, VLBytes,
};

/// A struct with two variable-length fields and a fixed-width one (cf. `HpkeCiphertext`).
#[derive(
    PartialEq, TlsSize, TlsSerialize, TlsDeserialize, TlsSerializeBytes, TlsDeserializeBytes,
)]
pub struct Pair2 {
    pub kem_output: VLBytes,
    pub tag: u16,
    pub ciphertext: VLBytes,
}

/// A `u8`-tagged enum with a unit variant and payload variants (cf. OpenMLS `Proposal`).
#[derive(
    PartialEq, TlsSize, TlsSerialize, TlsDeserialize, TlsSerializeBytes, TlsDeserializeBytes,
)]
#[repr(u8)]
pub enum Choice {
    #[tls_codec(discriminant = 1)]
    Empty,
    #[tls_codec(discriminant = 2)]
    Bytes(VLBytes),
    #[tls_codec(discriminant = 3)]
    Num(u16),
}
