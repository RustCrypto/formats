use tls_codec_derive::TlsDeserializeBytes;

#[derive(TlsDeserializeBytes)]
struct StructWithRawIdentifierField {
    r#type: u8,
}

fn main() {}
