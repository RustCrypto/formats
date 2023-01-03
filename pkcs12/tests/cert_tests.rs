use der::Decode;

use pkcs12::{content_info::ContentInfo, pfx::Pfx};

#[test]
fn decode_sample_pfx() -> der::Result<()> {
    let bytes = include_bytes!("examples/example.pfx");

    let content = Pfx::from_der(bytes).expect("expected valid data");

    match content.auth_safe {
        ContentInfo::Data(_) => Ok(()),
        ContentInfo::SignedData(_) => todo!(),
    }
}

#[test]
fn decode_sample_pfx2() -> der::Result<()> {
    let bytes = include_bytes!("examples/example2.pfx");

    let content = Pfx::from_der(bytes).expect("expected valid data");

    match content.auth_safe {
        ContentInfo::Data(_) => Ok(()),
        ContentInfo::SignedData(_) => todo!(),
    }
}
