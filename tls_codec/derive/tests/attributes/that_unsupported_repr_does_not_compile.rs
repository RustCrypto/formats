use tls_codec_derive::TlsSize;

#[derive(TlsSize)]
#[repr(i8)]
enum Signed {
    A,
}

#[derive(TlsSize)]
#[repr(usize)]
enum PointerSized {
    A(u8),
}

#[derive(TlsSize)]
#[repr(C)]
enum NotAnInteger {
    A(u8),
}

fn main() {}
