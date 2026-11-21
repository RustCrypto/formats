use tls_codec_derive::{TlsSerializeBytes, TlsSize};

const TOO_LARGE: u16 = 256;

#[derive(TlsSerializeBytes, TlsSize)]
#[repr(u8)]
enum PathTooLarge {
    #[tls_codec(discriminant = "TOO_LARGE")]
    A(u8),
}

fn main() {}
