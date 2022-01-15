//! SSH private key tests.

use hex_literal::hex;
use ssh_key::{Algorithm, PrivateKey};

#[cfg(feature = "ecdsa")]
use ssh_key::EcdsaCurve;

/// DSA OpenSSH-formatted public key
#[cfg(feature = "alloc")]
const OSSH_DSA_EXAMPLE: &str = include_str!("examples/id_dsa_1024");

/// Ed25519 OpenSSH-formatted private key
const OSSH_ED25519_EXAMPLE: &str = include_str!("examples/id_ed25519");

/// ECDSA/P-256 OpenSSH-formatted public key
#[cfg(feature = "ecdsa")]
const OSSH_ECDSA_P256_EXAMPLE: &str = include_str!("examples/id_ecdsa_p256");

/// ECDSA/P-384 OpenSSH-formatted public key
#[cfg(feature = "ecdsa")]
const OSSH_ECDSA_P384_EXAMPLE: &str = include_str!("examples/id_ecdsa_p384");

/// ECDSA/P-521 OpenSSH-formatted public key
#[cfg(feature = "ecdsa")]
const OSSH_ECDSA_P521_EXAMPLE: &str = include_str!("examples/id_ecdsa_p521");

/// RSA (3072-bit) OpenSSH-formatted public key
#[cfg(feature = "alloc")]
const OSSH_RSA_3072_EXAMPLE: &str = include_str!("examples/id_rsa_3072");

// /// RSA (4096-bit) OpenSSH-formatted public key
// #[cfg(feature = "alloc")]
// const OSSH_RSA_4096_EXAMPLE: &str = include_str!("examples/id_rsa_4096");

#[cfg(feature = "alloc")]
#[test]
fn decode_dsa_openssh() {
    let ossh_key = PrivateKey::from_openssh(OSSH_DSA_EXAMPLE).unwrap();
    assert_eq!(Algorithm::Dsa, ossh_key.key_data.algorithm());

    let dsa_keypair = ossh_key.key_data.dsa().unwrap();
    assert_eq!(
        &hex!(
            "00dc3d89250ed9462114cb2c8d4816e3a511aaff1b06b0e01de17c1cb04e581bcab97176471d89fd7ca1817
             e3c48e2ccbafd2170f69e8e5c8b6ab69b9c5f45d95e1d9293e965227eee5b879b1123371c21b1db60f14b5e
             5c05a4782ceb43a32f449647703063621e7a286bec95b16726c18b5e52383d00b297a6b03489b06068a5"
        ),
        dsa_keypair.public.p.as_bytes(),
    );
    assert_eq!(
        &hex!("00891815378597fe42d3fd261fe76df365845bbb87"),
        dsa_keypair.public.q.as_bytes(),
    );
    assert_eq!(
        &hex!(
            "4739b3908a8415466dc7b156fb98ecb71552a170ba0b3b7aa81bd81391de0a7ae7a1b45002dfeadc9225fbc
             520a713fe4104a74bed53fd5915da736365afd3f09777bbccfbadf7ac2b087b7f4d95fabe47d72a46e95088
             f9cd2a9fbf236b58a6982647f3c00430ad7352d47a25ebbe9477f0c3127da86ad7448644b76de5875c"
        ),
        dsa_keypair.public.g.as_bytes(),
    );
    assert_eq!(
        &hex!(
            "6042a6b3fd861344cb21ccccd8719e25aa0be0980e79cbabf4877f5ef071f6039770352eac3d4c368f29daf
             a57b475c78d44989f16577527e598334be6aae4abd750c36af80489d392697c1f32f3cf3c9a8b99bcddb53d
             7a37e1a28fd53d4934131cf41c437c6734d1e04004adcd925b84b3956c30c3a3904eecb31400b0df48"
        ),
        dsa_keypair.public.y.as_bytes(),
    );
    assert_eq!(
        &hex!("0c377ac449e770d89a3557743cbd050396114b62"),
        dsa_keypair.private.as_bytes()
    );
    assert_eq!("user@example.com", ossh_key.comment);
}

#[cfg(feature = "ecdsa")]
#[test]
fn decode_ecdsa_p256_openssh() {
    let ossh_key = PrivateKey::from_openssh(OSSH_ECDSA_P256_EXAMPLE).unwrap();
    assert_eq!(
        Algorithm::Ecdsa(EcdsaCurve::NistP256),
        ossh_key.key_data.algorithm(),
    );

    let ecdsa_keypair = ossh_key.key_data.ecdsa().unwrap();
    assert_eq!(EcdsaCurve::NistP256, ecdsa_keypair.curve());
    assert_eq!(
        &hex!(
            "047c1fd8730ce53457be8d924098ec3648830f92aa8a2363ac656fdd4521fa6313e511f1891b4e9e5aaf8e1
             42d06ad15a66a4257f3f051d84e8a0e2f91ba807047"
        ),
        ecdsa_keypair.public_key_bytes(),
    );
    assert_eq!(
        &hex!("ca78a64774bfae37123224937f0398960189707aca0a8645ceb4359c423ba079"),
        ecdsa_keypair.private_key_bytes(),
    );

    #[cfg(feature = "alloc")]
    assert_eq!("user@example.com", ossh_key.comment);
}

#[cfg(feature = "ecdsa")]
#[test]
fn decode_ecdsa_p384_openssh() {
    let ossh_key = PrivateKey::from_openssh(OSSH_ECDSA_P384_EXAMPLE).unwrap();
    assert_eq!(
        Algorithm::Ecdsa(EcdsaCurve::NistP384),
        ossh_key.key_data.algorithm(),
    );

    let ecdsa_keypair = ossh_key.key_data.ecdsa().unwrap();
    assert_eq!(EcdsaCurve::NistP384, ecdsa_keypair.curve());
    assert_eq!(
        &hex!(
            "042e6e82dc5407f104a11117c7c05b1993c3ceb3db25fae68ba169502a4ff9395d9ad36b543e8014ff15d70
             8e21f09f585aa6dfad575b79b943418b86198d9bcd9b07fff9399b15d43d34efaeb2e56b7b33cff880b242b
             3e0b58af96c75841ec41"
        ),
        ecdsa_keypair.public_key_bytes(),
    );
    assert_eq!(
        &hex!(
            "0377d9e9328b2925196977320a2bfe013801897fa0287848af817bdc7f400e8801fd0f9c057d106914b389c
             b156f600b"
        ),
        ecdsa_keypair.private_key_bytes(),
    );

    #[cfg(feature = "alloc")]
    assert_eq!("user@example.com", ossh_key.comment);
}

#[cfg(feature = "ecdsa")]
#[test]
fn decode_ecdsa_p521_openssh() {
    let ossh_key = PrivateKey::from_openssh(OSSH_ECDSA_P521_EXAMPLE).unwrap();
    assert_eq!(
        Algorithm::Ecdsa(EcdsaCurve::NistP521),
        ossh_key.key_data.algorithm(),
    );

    let ecdsa_keypair = ossh_key.key_data.ecdsa().unwrap();
    assert_eq!(EcdsaCurve::NistP521, ecdsa_keypair.curve());
    assert_eq!(
        &hex!(
            "04016136934f192b23d961fbf44c8184166002cea2c7d18b20ad018d046ef068d3e8250fd4e9f17ca6693a8
             554c3269a6d9f5762a2f9a2cb8797d4b201de421d3dcc580103cb947a858bb7783df863f82951d96f91a792
             5d7e2baad26e47e3f2fa5b07c8272848a4423b750d7ad2b8b692d66ddecaec5385086b1fd1b682ca291c88d
             63762"
        ),
        ecdsa_keypair.public_key_bytes(),
    );
    assert_eq!(
        &hex!(
            "01ec905f2ab7a9169f161f09e567fcab225bbe6276727a5f2724535c2b663d7ad8e32527d7f5998a992240c
             bb90cec3ed67fe902bced588beb972c7716e0927cda82"
        ),
        ecdsa_keypair.private_key_bytes(),
    );

    #[cfg(feature = "alloc")]
    assert_eq!("user@example.com", ossh_key.comment);
}

#[test]
fn decode_ed25519_openssh() {
    let ossh_key = PrivateKey::from_openssh(OSSH_ED25519_EXAMPLE).unwrap();
    assert_eq!(Algorithm::Ed25519, ossh_key.key_data.algorithm());

    let ed25519_keypair = ossh_key.key_data.ed25519().unwrap();
    assert_eq!(
        &hex!("b33eaef37ea2df7caa010defdea34e241f65f1b529a4f43ed14327f5c54aab62"),
        ed25519_keypair.public.as_ref(),
    );
    assert_eq!(
        &hex!("b606c222d10c16dae16c70a4d45173472ec617e05c656920d26e56c08fb591ed"),
        ed25519_keypair.private.as_ref(),
    );

    #[cfg(feature = "alloc")]
    assert_eq!(ossh_key.comment, "user@example.com");
}

#[cfg(feature = "alloc")]
#[test]
fn decode_rsa_3072_openssh() {
    let ossh_key = PrivateKey::from_openssh(OSSH_RSA_3072_EXAMPLE).unwrap();
    assert_eq!(Algorithm::Rsa, ossh_key.key_data.algorithm());

    let rsa_keypair = ossh_key.key_data.rsa().unwrap();
    assert_eq!(&hex!("010001"), rsa_keypair.public.e.as_bytes());
    assert_eq!(
        &hex!(
            "00a68e478c9bc93726436b7f5e9e6f9a46e1b73bec1e8cb7754de2c6a5b6c455f2f012a7259afcf94181d69
             e95d39a349e4d2b482a5372b28943731db75c73ce7bd9eec85010c94bfae56960118922f86a8b3655b357d2
             4e7a679cd8a7d9bf6eae66f7f9a56fe3d090d0632218a682960d8aad93c01898780ead2dbefd70fb4703471
             7e412e4fdae685292ec891e2423f7fe43df2f54329ab0a5d7561e582e42e86ebaee0c1e9eaf603d7ce70850
             5d0ee090912e1fc3735eb5804ddf42b6133107a76e9a59cdfc6b65f43c6302cfbca8e7aa6f97457fa96d3b5
             a26e8f41204d2cd42be119c684b0f02370899a71ae3c1e71331543cc3fb2b4268780011ae4ea934c0ff0770
             8ee183e7e906fee489e8e1e57fce7a1c6df8fbaef39bbd1955dbd5ad1abffbe126f50205cb884af080ff3d7
             0549d3174b85bd7f6624c3753cf235b650d0e4228f32be7b54a590d869fb7786559bb7a4d66f9d3a69c085e
             fdf083a915d47a1d9161a08756b263b06e739d99f2890362abc96ade42cce8f939a40daff9"
        ),
        rsa_keypair.public.n.as_bytes(),
    );
    assert_eq!(
        &hex!(
            "6b630b10c6950ac0d9f16273103626c392dec07cf2098a73d09ee9b388ceb817e5e030f2d7264a538932669
             775925460c8a2a269dfd9f0f0fd932852c4024adca1dc0a3d4d456c7ebd119f064f6443c4f633373865e44c
             0331f0f7e3e94a3b43a952331d0eb2551439b7e11101b2eaaa9a8265e41237a418da61c765c345d03875cb1
             a9b70177c2ef9268fe9ac8c62c08fa9152a7fe00ccade72a3acf6f004e5b617424a8027922dbc175f228626
             29e4727198ca940b3bc24c9268e3ab5f5e5965b8387e1470679b3ea680965f81593cb141310d4c41569e25b
             376a2dc4ed92f9149b75e970e8224730946cc20f351f8115b1bbfcbb38f6bd06c620472b76d641d35802ade
             f15220ab9b2a57e35918fe27e138119cca56a98ccf3c0fc683a19f2721a8766ecdd9c57677662656f3d3e05
             325f3fb37326623dbbec63b3d984830b2dd27bebb6bd2ed5345dfff18df1806adebceda9845804968930681
             ac3e523138c5216cb135997e3e143a7816acc3d8741eacec7e15f53da0f0810691708d9d"
        ),
        rsa_keypair.private.d.as_bytes()
    );
    assert_eq!(
        &hex!(
            "54405aa663ae9e080035a71002f4c351d7d002c35200725e6dc0ff6d901a304b103a2ea016507996d319358
             b5bea4feb4098f530528f12b98c50c7ddfc85fc4af9257baf9aa7235cdf4677349b77e52a40a5e2f44122d1
             8ce40941914e99169c48b708898d29869656607b7e2eb63541e0bbd568e4f774bec3137d02a591c8c77b2e1
             88dd6f72eef5cff1927cde573a4ca0d43c2b6c6a95721445122e1cf6aa5f05b65cb9c86124f9f79fa29f05e
             3f06f3b83edca9941f571650e0fb468aae4c"
        ),
        rsa_keypair.private.iqmp.as_bytes()
    );
    assert_eq!(
        &hex!(
            "00d11e7ae248640d3b20293691886544cdfe0779a9aab56c8f9626bf1e6648bfd988bdb0ac7d11a73e34056
             336d4ad3900ff7184ee404b84baeb11a2a302f982d94eefb757030ec6d77d9115eaef80ab5749a0f5b590b2
             99ffde94f9930dedbab2af333095b08a504b9b30f1112dce51f37ed00d043343d420d2e2fb88bd7f881b7c8
             990e48b93fd1d284fcc8c1c07fbefc04d02925b2f159a9a9f567073e1c94fdc6e472f48963be16c5c545385
             6ad2bf7916e42c36e75a5018910d8dad038d73"
        ),
        rsa_keypair.private.p.as_bytes()
    );
    assert_eq!(
        &hex!(
            "00cbe50e7ecdf5e2c86e76ca94be8b0c05b09041d2bcddeeb4672e7120eacc8380e5d6b77c85583c508f8ee
             8d557cabcb6dfae8c72385f0f69345ebc15a5dfec949c0770d02d7945dd3592562da7388662e053c5454d26
             90de2a63cc555e1a010e2da0ae307d1c11f852a9c7568e02f93d49b2a8f927b79943b2920cad321aa208410
             9d136d085c1d05c39f4c36cf89fdc3c66a755e63f446e16302b13599400f0a83321a2e6b9153df02f03de31
             8ea09039282853f2011e0905d1157667caf1e3"
        ),
        rsa_keypair.private.q.as_bytes()
    );
    assert_eq!("user@example.com", ossh_key.comment);
}
