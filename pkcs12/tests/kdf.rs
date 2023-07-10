#[cfg(feature="alloc")]
use pkcs12::kdf::pkcs12_key_gen;
use hex_literal::hex;

const PASS_SHORT: &str = "ge@äheim";
const SALT_INC: [u8; 8] = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];
 
#[test]
#[cfg(feature="alloc")]
fn pkcs12_key_gen_sha256() {
    let iter = 100;
    let id = pkcs12::kdf::Pkcs12KeyType::Mac;
    assert_eq!(pkcs12_key_gen::<32>(PASS_SHORT, &SALT_INC, id, iter).unwrap(),
        hex!("136355ed9434516682534f46d63956db5ff06b844702c2c1f3b46321e2524a4d"));
}


