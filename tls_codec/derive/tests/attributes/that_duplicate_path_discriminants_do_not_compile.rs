use tls_codec_derive::{TlsSerializeBytes, TlsSize};

const ONE: u8 = 1;
const ALSO_ONE: u8 = 1;

#[derive(TlsSerializeBytes, TlsSize)]
#[repr(u8)]
enum PathAndLiteral {
    #[tls_codec(discriminant = 1)]
    A(u8),
    #[tls_codec(discriminant = "ONE")]
    B(u8),
}

#[derive(TlsSerializeBytes, TlsSize)]
#[repr(u8)]
enum TwoPaths {
    #[tls_codec(discriminant = "ONE")]
    A(u8),
    #[tls_codec(discriminant = "ALSO_ONE")]
    B(u8),
}

fn main() {}
