use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

// The explicit discriminant of `A` is `usize::MAX`, so the implicit
// discriminant of `B` cannot be represented. Wrapping around would silently
// give `B` the same discriminant as a variant with discriminant 0.
#[derive(TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u64)]
enum EnumWithOverflowingDiscriminant {
    #[tls_codec(discriminant = 18446744073709551615)]
    A(u8),
    B(u8),
}

fn main() {}
