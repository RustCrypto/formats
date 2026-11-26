use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
enum EnumWithRawIdentifierVariant {
    r#Type(u8),
}

fn main() {}
