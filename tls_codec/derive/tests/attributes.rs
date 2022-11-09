#[test]
fn that_duplicate_skip_attributes_dont_compile() {
    // TODO: It works. But how to test this?
    // use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
    //
    // #[derive(TlsDeserialize, TlsSerialize, TlsSize)]
    // struct StructWithDuplicateSkip {
    //     #[tls_codec(skip, skip)]
    //     a: u8,
    // }
}

#[test]
fn that_skip_attribute_does_not_compile_on_enums() {
    // TODO: It works. But how to test this?
    // use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
    //
    // #[derive(TlsDeserialize, TlsSerialize, TlsSize)]
    // #[repr(u8)]
    // enum EnumWithSkip {
    //     #[tls_codec(skip)]
    //     A,
    //     B,
    // }
}

#[test]
fn that_non_default_field_does_not_compile() {
    // TODO: It works. But how to test this?
    // use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
    //
    // struct NonDefaultField {}
    //
    // #[derive(TlsDeserialize, TlsSerialize, TlsSize)]
    // struct StructWithNonDefaultField {
    //     #[tls_codec(skip)]
    //     a: NonDefaultField,
    //     b: u8,
    // }
}
