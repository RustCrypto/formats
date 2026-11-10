use tls_codec_derive::{TlsSerializeBytes, TlsSize};

const FIVE: u8 = 5;

#[derive(TlsSerializeBytes, TlsSize)]
#[repr(u8)]
enum ImplicitAfterPath {
    #[tls_codec(discriminant = "FIVE")]
    A(u8),
    B(u8),
}

fn main() {}
