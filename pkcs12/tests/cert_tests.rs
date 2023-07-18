use der::{Decode, Encode};

use pkcs12::{pfx::Pfx};

#[test]
fn decode_sample_pfx() {
    let bytes = include_bytes!("examples/example.pfx");

    let content = Pfx::from_der(bytes).expect("expected valid data");
    let reenc_content = content.to_der().unwrap();
    assert_eq!(bytes, reenc_content.as_slice());
    println!("{:?}", content);
}

#[test]
fn decode_sample_pfx2()  {
    let bytes = include_bytes!("examples/example2.pfx");

    let content = Pfx::from_der(bytes).expect("expected valid data");
    let reenc_content = content.to_der().unwrap();
    assert_eq!(bytes, reenc_content.as_slice());
    println!("{:?}", content);
}
