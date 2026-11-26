use tls_codec_derive::{TlsSerialize, TlsSize, conditionally_deserializable};

#[conditionally_deserializable]
#[derive(TlsSerialize, TlsSize)]
struct ReservedConstName<const __TLS_CODEC_IS_DESERIALIZABLE: bool> {
    a: u8,
}

#[allow(non_camel_case_types)]
#[conditionally_deserializable]
#[derive(TlsSerialize, TlsSize)]
struct ReservedTypeName<__TLS_CODEC_IS_DESERIALIZABLE> {
    a: __TLS_CODEC_IS_DESERIALIZABLE,
}

fn main() {}
