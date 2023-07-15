use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature="alloc")] {

        #[test]
        fn pkcs12_key_derive_sha256() {
            use hex_literal::hex;
            use pkcs12::kdf::{derive_key, Pkcs12KeyType};

            const PASS_SHORT: &str = "ge@äheim";
            const SALT_INC: [u8; 8] = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];

            assert_eq!(
                derive_key::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::EncryptionKey, 100, 32)
                    .unwrap(),
                hex!("fae4d4957a3cc781e1180b9d4fb79c1e0c8579b746a3177e5b0768a3118bf863")
            );

            assert_eq!(
                derive_key::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Iv, 100, 32).unwrap(),
                hex!("e5ff813bc6547de5155b14d2fada85b3201a977349db6e26ccc998d9e8f83d6c")
            );

            assert_eq!(
                derive_key::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Mac, 100, 32).unwrap(),
                hex!("136355ed9434516682534f46d63956db5ff06b844702c2c1f3b46321e2524a4d")
            );

            assert_eq!(
                derive_key::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::EncryptionKey, 100, 20)
                    .unwrap(),
                hex!("fae4d4957a3cc781e1180b9d4fb79c1e0c8579b7")
            );

            assert_eq!(
                derive_key::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Iv, 100, 20).unwrap(),
                hex!("e5ff813bc6547de5155b14d2fada85b3201a9773")
            );

            assert_eq!(
                derive_key::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Mac, 100, 20).unwrap(),
                hex!("136355ed9434516682534f46d63956db5ff06b84")
            );

            assert_eq!(
                derive_key::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::EncryptionKey, 100, 12)
                    .unwrap(),
                hex!("fae4d4957a3cc781e1180b9d")
            );

            assert_eq!(
                derive_key::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Iv, 100, 12).unwrap(),
                hex!("e5ff813bc6547de5155b14d2")
            );

            assert_eq!(
                derive_key::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Mac, 100, 12).unwrap(),
                hex!("136355ed9434516682534f46")
            );

            assert_eq!(
                derive_key::<sha2::Sha256>(
                    PASS_SHORT,
                    &SALT_INC,
                    Pkcs12KeyType::EncryptionKey,
                    1000,
                    32
                )
                .unwrap(),
                hex!("2b95a0569b63f641fae1efca32e84db3699ab74540628ba66283b58cf5400527")
            );

            assert_eq!(
                derive_key::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Iv, 1000, 32).unwrap(),
                hex!("6472c0ebad3fab4123e8b5ed7834de21eeb20187b3eff78a7d1cdffa4034851d")
            );

            assert_eq!(
                derive_key::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Mac, 1000, 32).unwrap(),
                hex!("3f9113f05c30a996c4a516409bdac9d065f44296ccd52bb75de3fcfdbe2bf130")
            );

            assert_eq!(
                derive_key::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Mac, 1000, 32).unwrap(),
                hex!("3f9113f05c30a996c4a516409bdac9d065f44296ccd52bb75de3fcfdbe2bf130")
            );
        }

        #[test]
        fn pkcs12_key_derive_sha512() {
            use hex_literal::hex;
            use pkcs12::kdf::{derive_key, Pkcs12KeyType};

            const PASS_SHORT: &str = "ge@äheim";
            const SALT_INC: [u8; 8] = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];

            assert_eq!(
                derive_key::<sha2::Sha512>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::EncryptionKey, 100, 32)
                    .unwrap(),
                hex!("b14a9f01bfd9dce4c9d66d2fe9937e5fd9f1afa59e370a6fa4fc81c1cc8ec8ee")
            );
        }

        #[test]
        fn pkcs12_key_derive_whirlpool() {
            use hex_literal::hex;
            use pkcs12::kdf::{derive_key, Pkcs12KeyType};

            const PASS_SHORT: &str = "ge@äheim";
            const SALT_INC: [u8; 8] = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];

            assert_eq!(
                derive_key::<whirlpool::Whirlpool>(
                    PASS_SHORT,
                    &SALT_INC,
                    Pkcs12KeyType::EncryptionKey,
                    100,
                    32
                )
                .unwrap(),
                hex!("3324282adb468bff0734d3b7e399094ec8500cb5b0a3604055da107577aaf766")
            );
        }
    }
}
