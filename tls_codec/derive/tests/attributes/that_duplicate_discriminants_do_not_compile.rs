use tls_codec_derive::{TlsSerializeBytes, TlsSize};

#[derive(TlsSerializeBytes, TlsSize)]
#[repr(u8)]
enum ExplicitDuplicate {
    #[tls_codec(discriminant = 1)]
    A(u8),
    #[tls_codec(discriminant = 1)]
    B(u8),
}

// `B` implicitly gets 2, which `C` uses explicitly.
#[derive(TlsSerializeBytes, TlsSize)]
#[repr(u8)]
enum ImplicitDuplicate {
    #[tls_codec(discriminant = 1)]
    A(u8),
    B(u8),
    #[tls_codec(discriminant = 2)]
    C(u8),
}

fn main() {}
