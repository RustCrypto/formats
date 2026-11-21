use tls_codec_derive::TlsSize;

#[derive(TlsSize)]
#[repr(u8)]
enum ExplicitTooLarge {
    #[tls_codec(discriminant = 256)]
    A(u8),
}

#[derive(TlsSize)]
#[repr(u8)]
enum ImplicitTooLarge {
    #[tls_codec(discriminant = 255)]
    A(u8),
    B(u8),
}

fn main() {}
