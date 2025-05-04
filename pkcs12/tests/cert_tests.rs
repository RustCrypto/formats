use cms::encrypted_data::EncryptedData;
use const_oid::db::{
    rfc5911::{ID_DATA, ID_ENCRYPTED_DATA},
    rfc5912::ID_SHA_256,
};
use der::{
    Decode, Encode,
    asn1::{ContextSpecific, OctetString},
};
use hex_literal::hex;
use pkcs8::{
    EncryptedPrivateKeyInfoRef,
    pkcs5::{
        self,
        pbes2::{AES_256_CBC_OID, HMAC_WITH_SHA256_OID, PBES2_OID, PBKDF2_OID},
    },
};
use spki::AlgorithmIdentifierOwned;

use pkcs12::{
    pbe_params::Pbkdf2Params,
    pfx::Pfx,
    pfx::Version,
    safe_bag::SafeContents,
    {AuthenticatedSafe, CertBag},
};

//    0 1871: SEQUENCE {
//    4    1:   INTEGER 3
//    7 1797:   SEQUENCE {
//   11    9:     OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
//   22 1782:     [0] {
//   26 1778:       OCTET STRING, encapsulates {
//   30 1774:         SEQUENCE {
//   34  946:           SEQUENCE {
//   38    9:             OBJECT IDENTIFIER encryptedData (1 2 840 113549 1 7 6)
//   49  931:             [0] {
//   53  927:               SEQUENCE {
//   57    1:                 INTEGER 0
//   60  920:                 SEQUENCE {
//   64    9:                   OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
//   75   87:                   SEQUENCE {
//   77    9:                     OBJECT IDENTIFIER
//          :                       pkcs5PBES2 (1 2 840 113549 1 5 13)
//   88   74:                     SEQUENCE {
//   90   41:                       SEQUENCE {
//   92    9:                         OBJECT IDENTIFIER
//          :                           pkcs5PBKDF2 (1 2 840 113549 1 5 12)
//  103   28:                         SEQUENCE {
//  105    8:                           OCTET STRING 9A A2 77 B5 F0 51 B4 50
//  115    2:                           INTEGER 2048
//  119   12:                           SEQUENCE {
//  121    8:                             OBJECT IDENTIFIER
//          :                               hmacWithSHA256 (1 2 840 113549 2 9)
//  131    0:                             NULL
//          :                             }
//          :                           }
//          :                         }
//  133   29:                       SEQUENCE {
//  135    9:                         OBJECT IDENTIFIER
//          :                           aes256-CBC (2 16 840 1 101 3 4 1 42)
//  146   16:                         OCTET STRING
//          :                     2E 23 6C 8C 7A 44 0C 3E 0F 4E 0D 32 C9 90 E9 97
//          :                         }
//          :                       }
//          :                     }
//  164  816:                   [0]
//          :                     85 52 18 B2 A1 7A 46 59 0D 64 F8 39 52 CC BF 79
//          :                     50 AA 2B 7A DF 24 9C 8F A4 9E 3A FB 03 7F 05 CD
//          :                     8A 18 F4 6E 28 B0 AA 99 D0 07 4E 4C DF 31 A5 E7
//          :                     C0 4B 8E 55 49 39 B9 5D 52 07 00 06 A1 39 53 17
//          :                     A8 D1 9B 16 7B 31 51 0C 67 9A 5C 5E B7 16 B5 E2
//          :                     BB 24 2E A8 7C 30 95 2B 0F 3C FF D7 3F F1 B2 13
//          :                     E5 8D 4D 49 70 F3 41 2B 20 57 51 C8 53 C4 EA 60
//          :                     11 05 AF 87 A7 8B 40 E7 96 61 0D 7E B2 6A 8A 76
//          :                             [ Another 688 bytes skipped ]
//          :                   }
//          :                 }
//          :               }
//          :             }
//  984  820:           SEQUENCE {
//  988    9:             OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
//  999  805:             [0] {
// 1003  801:               OCTET STRING, encapsulates {
// 1007  797:                 SEQUENCE {
// 1011  793:                   SEQUENCE {
// 1015   11:                     OBJECT IDENTIFIER
//          :                       pkcs-12-pkcs-8ShroudedKeyBag (1 2 840 113549 1 12 10 1 2)
// 1028  737:                     [0] {
// 1032  733:                       SEQUENCE {
// 1036   87:                         SEQUENCE {
// 1038    9:                           OBJECT IDENTIFIER
//          :                             pkcs5PBES2 (1 2 840 113549 1 5 13)
// 1049   74:                           SEQUENCE {
// 1051   41:                             SEQUENCE {
// 1053    9:                               OBJECT IDENTIFIER
//          :                                 pkcs5PBKDF2 (1 2 840 113549 1 5 12)
// 1064   28:                               SEQUENCE {
// 1066    8:                                 OCTET STRING 10 AF 41 1E 77 84 BA CD
// 1076    2:                                 INTEGER 2048
// 1080   12:                                 SEQUENCE {
// 1082    8:                                   OBJECT IDENTIFIER
//          :                                     hmacWithSHA256 (1 2 840 113549 2 9)
// 1092    0:                                   NULL
//          :                                   }
//          :                                 }
//          :                               }
// 1094   29:                             SEQUENCE {
// 1096    9:                               OBJECT IDENTIFIER
//          :                                 aes256-CBC (2 16 840 1 101 3 4 1 42)
// 1107   16:                               OCTET STRING
//          :                     46 21 13 61 4C 99 4D 1F DA 70 B4 71 16 5A AE 4A
//          :                               }
//          :                             }
//          :                           }
// 1125  640:                         OCTET STRING
//          :                     2F 92 BB F4 9C B4 53 90 85 09 54 3B 4F 67 01 3A
//          :                     F5 5E 69 14 3A 03 B7 0A 12 3F 9E 80 CB 8A 1F 19
//          :                     42 84 5F AC 3E C2 D4 0F 97 F5 B4 66 F1 A8 A3 68
//          :                     F9 59 E2 7B 62 52 15 1B 61 63 48 3D 83 8A 9E 88
//          :                     6F F3 BA 9D A7 91 B6 CF 6B 87 87 E6 2E 72 2C D3
//          :                     A6 C5 54 43 D3 84 3D 16 78 80 A7 E8 AD 50 8F D6
//          :                     87 82 B6 8A 70 84 AB 93 26 9D A9 9B 64 7E 98 41
//          :                     5D CB 59 04 24 94 39 71 B0 F1 94 4A E8 5D 8C B4
//          :                             [ Another 512 bytes skipped ]
//          :                         }
//          :                       }
// 1769   37:                     SET {
// 1771   35:                       SEQUENCE {
// 1773    9:                         OBJECT IDENTIFIER
//          :                           localKeyID (for PKCS #12) (1 2 840 113549 1 9 21)
// 1784   22:                         SET {
// 1786   20:                           OCTET STRING
//          :                     EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15
//          :                     D0 7B 00 6D
//          :                           }
//          :                         }
//          :                       }
//          :                     }
//          :                   }
//          :                 }
//          :               }
//          :             }
//          :           }
//          :         }
//          :       }
//          :     }
// 1808   65:   SEQUENCE {
// 1810   49:     SEQUENCE {
// 1812   13:       SEQUENCE {
// 1814    9:         OBJECT IDENTIFIER sha-256 (2 16 840 1 101 3 4 2 1)
// 1825    0:         NULL
//          :         }
// 1827   32:       OCTET STRING
//          :         10 06 A1 92 F8 EE F8 A4 A2 46 6F EB 87 16 69 57
//          :         B9 63 CD CB C9 DC D7 73 6F 47 3C BB 11 EC 00 D7
//          :       }
// 1861    8:     OCTET STRING FF 08 ED 21 81 C8 A8 E3
// 1871    2:     INTEGER 2048
//          :     }
//          :   }
#[test]
fn decode_sample_pfx() {
    let bytes = include_bytes!("examples/example.pfx");

    let pfx = Pfx::from_der(bytes).expect("expected valid data");
    let reenc_content = pfx.to_der().unwrap();
    assert_eq!(bytes, reenc_content.as_slice());
    println!("{pfx:?}");

    assert_eq!(Version::V3, pfx.version);
    assert_eq!(ID_DATA, pfx.auth_safe.content_type);
    let auth_safes_os = OctetString::from_der(&pfx.auth_safe.content.to_der().unwrap()).unwrap();
    let auth_safes = AuthenticatedSafe::from_der(auth_safes_os.as_bytes()).unwrap();

    // Process first auth safe (from offset 34)
    let auth_safe0 = auth_safes.first().unwrap();
    assert_eq!(ID_ENCRYPTED_DATA, auth_safe0.content_type);
    let enc_data_os = &auth_safe0.content.to_der().unwrap();
    let enc_data = EncryptedData::from_der(enc_data_os.as_slice()).unwrap();
    assert_eq!(ID_DATA, enc_data.enc_content_info.content_type);
    assert_eq!(PBES2_OID, enc_data.enc_content_info.content_enc_alg.oid);
    let enc_params = enc_data
        .enc_content_info
        .content_enc_alg
        .parameters
        .as_ref()
        .unwrap()
        .to_der()
        .unwrap();

    let params = pkcs8::pkcs5::pbes2::Parameters::from_der(&enc_params).unwrap();

    let scheme = pkcs5::EncryptionScheme::from(params.clone());
    let ciphertext_os = enc_data.enc_content_info.encrypted_content.clone().unwrap();
    let mut ciphertext = ciphertext_os.as_bytes().to_vec();
    let plaintext = scheme.decrypt_in_place("", &mut ciphertext).unwrap();
    let cert_bags = SafeContents::from_der(plaintext).unwrap();
    for cert_bag in cert_bags {
        match cert_bag.bag_id {
            pkcs12::PKCS_12_CERT_BAG_OID => {
                let cs: der::asn1::ContextSpecific<CertBag> =
                    ContextSpecific::from_der(&cert_bag.bag_value).unwrap();
                let cb = cs.value;
                assert_eq!(
                    include_bytes!("examples/cert.der"),
                    cb.cert_value.as_bytes()
                );
            }
            _ => panic!(),
        };
    }

    let k = params.kdf.to_der().unwrap();
    let kdf_alg_info = AlgorithmIdentifierOwned::from_der(&k).unwrap();
    assert_eq!(PBKDF2_OID, kdf_alg_info.oid);
    let k_params = kdf_alg_info.parameters.unwrap().to_der().unwrap();

    let pbkdf2_params = Pbkdf2Params::from_der(&k_params).unwrap();
    assert_eq!(2048, pbkdf2_params.iteration_count);
    assert_eq!(
        hex!("9A A2 77 B5 F0 51 B4 50"),
        pbkdf2_params.salt.as_bytes()
    );
    assert_eq!(HMAC_WITH_SHA256_OID, pbkdf2_params.prf.oid);

    let e = params.encryption.to_der().unwrap();
    let enc_alg_info = AlgorithmIdentifierOwned::from_der(&e).unwrap();
    assert_eq!(AES_256_CBC_OID, enc_alg_info.oid);
    assert_eq!(
        hex!("04 10 2E 23 6C 8C 7A 44 0C 3E 0F 4E 0D 32 C9 90 E9 97"),
        enc_alg_info.parameters.to_der().unwrap().as_slice()
    );

    // Process second auth safe (from offset 984)
    let auth_safe1 = auth_safes.get(1).unwrap();
    assert_eq!(ID_DATA, auth_safe1.content_type);

    let auth_safe1_auth_safes_os =
        OctetString::from_der(&auth_safe1.content.to_der().unwrap()).unwrap();
    let safe_bags = SafeContents::from_der(auth_safe1_auth_safes_os.as_bytes()).unwrap();
    for safe_bag in safe_bags {
        match safe_bag.bag_id {
            pkcs12::PKCS_12_PKCS8_KEY_BAG_OID => {
                let cs: ContextSpecific<EncryptedPrivateKeyInfoRef<'_>> =
                    ContextSpecific::from_der(&safe_bag.bag_value).unwrap();
                let mut ciphertext = cs.value.encrypted_data.as_bytes().to_vec();
                let plaintext = cs
                    .value
                    .encryption_algorithm
                    .decrypt_in_place("", &mut ciphertext)
                    .unwrap();
                assert_eq!(include_bytes!("examples/key.der"), plaintext);

                //todo inspect parameters
            }
            _ => panic!(),
        };
    }

    // process mac data
    let mac_data = pfx.mac_data.unwrap();
    assert_eq!(ID_SHA_256, mac_data.mac.algorithm.oid);
    assert_eq!(
        hex!(
            "10 06 A1 92 F8 EE F8 A4 A2 46 6F EB 87 16 69 57 B9 63 CD CB C9 DC D7 73 6F 47 3C BB 11 EC 00 D7"
        ),
        mac_data.mac.digest.as_bytes()
    );
    assert_eq!(
        hex!("FF 08 ED 21 81 C8 A8 E3"),
        mac_data.mac_salt.as_bytes()
    );
    assert_eq!(2048, mac_data.iterations);
}

//    0 1752: SEQUENCE {
//    4    1:   INTEGER 3
//    7 1678:   SEQUENCE {
//   11    9:     OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
//   22 1663:     [0] {
//   26 1659:       OCTET STRING, encapsulates {
//   30 1655:         SEQUENCE {
//   34  827:           SEQUENCE {
//   38    9:             OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
//   49  812:             [0] {
//   53  808:               OCTET STRING, encapsulates {
//   57  804:                 SEQUENCE {
//   61  800:                   SEQUENCE {
//   65   11:                     OBJECT IDENTIFIER
//          :                       pkcs-12-certBag (1 2 840 113549 1 12 10 1 3)
//   78  744:                     [0] {
//   82  740:                       SEQUENCE {
//   86   10:                         OBJECT IDENTIFIER
//          :                           x509Certificate (for PKCS #12) (1 2 840 113549 1 9 22 1)
//   98  724:                         [0] {
//  102  720:                           OCTET STRING, encapsulates {
//  106  716:                             SEQUENCE {
//  110  565:                               SEQUENCE {
//  114    3:                                 [0] {
//  116    1:                                   INTEGER 2
//          :                                   }
//  119   20:                                 INTEGER
//          :                     64 C0 EB 72 59 55 A3 2A 66 1F D7 7C 98 67 4F 00
//          :                     29 30 59 1B
//  141   13:                                 SEQUENCE {
//  143    9:                                   OBJECT IDENTIFIER
//          :                                     sha256WithRSAEncryption (1 2 840 113549 1 1 11)
//  154    0:                                   NULL
//          :                                   }
//  156  120:                                 SEQUENCE {
//  158   11:                                   SET {
//  160    9:                                     SEQUENCE {
//  162    3:                                       OBJECT IDENTIFIER
//          :                                         countryName (2 5 4 6)
//  167    2:                                       PrintableString 'DK'
//          :                                       }
//          :                                     }
//  171   20:                                   SET {
//  173   18:                                     SEQUENCE {
//  175    3:                                       OBJECT IDENTIFIER
//          :                                         stateOrProvinceName (2 5 4 8)
//  180   11:                                       UTF8String 'Hovedstaden'
//          :                                       }
//          :                                     }
//  193   21:                                   SET {
//  195   19:                                     SEQUENCE {
//  197    3:                                       OBJECT IDENTIFIER
//          :                                         localityName (2 5 4 7)
//  202   12:                                       UTF8String 'K....benhavn'
//          :                                       }
//          :                                     }
//  216   12:                                   SET {
//  218   10:                                     SEQUENCE {
//  220    3:                                       OBJECT IDENTIFIER
//          :                                         organizationName (2 5 4 10)
//  225    3:                                       UTF8String '...'
//          :                                       }
//          :                                     }
//  230   12:                                   SET {
//  232   10:                                     SEQUENCE {
//  234    3:                                       OBJECT IDENTIFIER
//          :                                         organizationalUnitName (2 5 4 11)
//  239    3:                                       UTF8String '...'
//          :                                       }
//          :                                     }
//  244   12:                                   SET {
//  246   10:                                     SEQUENCE {
//  248    3:                                       OBJECT IDENTIFIER
//          :                                         commonName (2 5 4 3)
//  253    3:                                       UTF8String '...'
//          :                                       }
//          :                                     }
//  258   18:                                   SET {
//  260   16:                                     SEQUENCE {
//  262    9:                                       OBJECT IDENTIFIER
//          :                                         emailAddress (1 2 840 113549 1 9 1)
//  273    3:                                       IA5String '...'
//          :                                       }
//          :                                     }
//          :                                   }
//  278   30:                                 SEQUENCE {
//  280   13:                                   UTCTime 03/01/2023 17:20:50 GMT
//  295   13:                                   UTCTime 03/01/2024 17:20:50 GMT
//          :                                   }
//  310  120:                                 SEQUENCE {
//  312   11:                                   SET {
//  314    9:                                     SEQUENCE {
//  316    3:                                       OBJECT IDENTIFIER
//          :                                         countryName (2 5 4 6)
//  321    2:                                       PrintableString 'DK'
//          :                                       }
//          :                                     }
//  325   20:                                   SET {
//  327   18:                                     SEQUENCE {
//  329    3:                                       OBJECT IDENTIFIER
//          :                                         stateOrProvinceName (2 5 4 8)
//  334   11:                                       UTF8String 'Hovedstaden'
//          :                                       }
//          :                                     }
//  347   21:                                   SET {
//  349   19:                                     SEQUENCE {
//  351    3:                                       OBJECT IDENTIFIER
//          :                                         localityName (2 5 4 7)
//  356   12:                                       UTF8String 'K....benhavn'
//          :                                       }
//          :                                     }
//  370   12:                                   SET {
//  372   10:                                     SEQUENCE {
//  374    3:                                       OBJECT IDENTIFIER
//          :                                         organizationName (2 5 4 10)
//  379    3:                                       UTF8String '...'
//          :                                       }
//          :                                     }
//  384   12:                                   SET {
//  386   10:                                     SEQUENCE {
//  388    3:                                       OBJECT IDENTIFIER
//          :                                         organizationalUnitName (2 5 4 11)
//  393    3:                                       UTF8String '...'
//          :                                       }
//          :                                     }
//  398   12:                                   SET {
//  400   10:                                     SEQUENCE {
//  402    3:                                       OBJECT IDENTIFIER
//          :                                         commonName (2 5 4 3)
//  407    3:                                       UTF8String '...'
//          :                                       }
//          :                                     }
//  412   18:                                   SET {
//  414   16:                                     SEQUENCE {
//  416    9:                                       OBJECT IDENTIFIER
//          :                                         emailAddress (1 2 840 113549 1 9 1)
//  427    3:                                       IA5String '...'
//          :                                       }
//          :                                     }
//          :                                   }
//  432  159:                                 SEQUENCE {
//  435   13:                                   SEQUENCE {
//  437    9:                                     OBJECT IDENTIFIER
//          :                                       rsaEncryption (1 2 840 113549 1 1 1)
//  448    0:                                     NULL
//          :                                     }
//  450  141:                                   BIT STRING, encapsulates {
//  454  137:                                     SEQUENCE {
//  457  129:                                       INTEGER
//          :                     00 B1 71 2C BD AB C7 58 A5 6D F5 E2 23 78 8C 22
//          :                     B8 C8 7A 7B B7 B9 C1 F2 B0 C6 21 D2 DD 5F EA 64
//          :                     F2 02 A0 EC 83 B0 B9 54 48 79 08 44 85 6C 61 1C
//          :                     D7 4B EE E5 9A C6 7F 1D E2 44 4A 45 CA E2 BF B0
//          :                     C7 F8 0C 9F 89 1C DC 39 9D E9 8C 05 C4 72 79 D1
//          :                     DC 73 1D AA 2C 3A 9E 4E 6B 70 45 00 8F 69 22 66
//          :                     E8 3D 69 18 00 91 46 3A 43 32 5F EC F8 51 64 C4
//          :                     F5 01 78 61 9E AE 42 65 6E 8C 3E AC 2E 40 9D 94
//          :                     B7
//  589    3:                                       INTEGER 65537
//          :                                       }
//          :                                     }
//          :                                   }
//  594   83:                                 [3] {
//  596   81:                                   SEQUENCE {
//  598   29:                                     SEQUENCE {
//  600    3:                                       OBJECT IDENTIFIER
//          :                                         subjectKeyIdentifier (2 5 29 14)
//  605   22:                                       OCTET STRING, encapsulates {
//  607   20:                                         OCTET STRING
//          :                     7A 80 DB 37 D1 0D FE 24 FA B1 D2 74 DD C9 6D 4E
//          :                     0C 15 94 43
//          :                                         }
//          :                                       }
//  629   31:                                     SEQUENCE {
//  631    3:                                       OBJECT IDENTIFIER
//          :                                         authorityKeyIdentifier (2 5 29 35)
//  636   24:                                       OCTET STRING, encapsulates {
//  638   22:                                         SEQUENCE {
//  640   20:                                           [0]
//          :                     7A 80 DB 37 D1 0D FE 24 FA B1 D2 74 DD C9 6D 4E
//          :                     0C 15 94 43
//          :                                           }
//          :                                         }
//          :                                       }
//  662   15:                                     SEQUENCE {
//  664    3:                                       OBJECT IDENTIFIER
//          :                                         basicConstraints (2 5 29 19)
//  669    1:                                       BOOLEAN TRUE
//  672    5:                                       OCTET STRING, encapsulates {
//  674    3:                                         SEQUENCE {
//  676    1:                                           BOOLEAN TRUE
//          :                                           }
//          :                                         }
//          :                                       }
//          :                                     }
//          :                                   }
//          :                                 }
//  679   13:                               SEQUENCE {
//  681    9:                                 OBJECT IDENTIFIER
//          :                                   sha256WithRSAEncryption (1 2 840 113549 1 1 11)
//  692    0:                                 NULL
//          :                                 }
//  694  129:                               BIT STRING
//          :                     03 2F 63 C5 7D 4A 2F B5 66 31 91 40 2A 92 4E D9
//          :                     64 69 A9 18 38 47 E0 9D FA 97 39 46 C6 36 73 BA
//          :                     EE FB 09 6D 25 F7 4B 40 86 D1 C8 8C 6D A2 31 C8
//          :                     C1 B6 4E 44 73 49 F2 62 38 33 9B 94 2E 51 9D 78
//          :                     3B 10 5D 27 53 4A 0D 04 86 30 DC 56 38 D2 54 C3
//          :                     AC 28 2A 41 5E 1A 11 84 9C 3C 29 AE 1D 2E E9 18
//          :                     CF 3B 55 3A DC C5 B3 18 FB 5B CF AB A8 92 69 D9
//          :                     F8 8A 38 9F 39 A0 69 8F B6 79 7A C5 B0 55 A5 29
//          :                               }
//          :                             }
//          :                           }
//          :                         }
//          :                       }
//  826   37:                     SET {
//  828   35:                       SEQUENCE {
//  830    9:                         OBJECT IDENTIFIER
//          :                           localKeyID (for PKCS #12) (1 2 840 113549 1 9 21)
//  841   22:                         SET {
//  843   20:                           OCTET STRING
//          :                     EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15
//          :                     D0 7B 00 6D
//          :                           }
//          :                         }
//          :                       }
//          :                     }
//          :                   }
//          :                 }
//          :               }
//          :             }
//  865  820:           SEQUENCE {
//  869    9:             OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
//  880  805:             [0] {
//  884  801:               OCTET STRING, encapsulates {
//  888  797:                 SEQUENCE {
//  892  793:                   SEQUENCE {
//  896   11:                     OBJECT IDENTIFIER
//          :                       pkcs-12-pkcs-8ShroudedKeyBag (1 2 840 113549 1 12 10 1 2)
//  909  737:                     [0] {
//  913  733:                       SEQUENCE {
//  917   87:                         SEQUENCE {
//  919    9:                           OBJECT IDENTIFIER
//          :                             pkcs5PBES2 (1 2 840 113549 1 5 13)
//  930   74:                           SEQUENCE {
//  932   41:                             SEQUENCE {
//  934    9:                               OBJECT IDENTIFIER
//          :                                 pkcs5PBKDF2 (1 2 840 113549 1 5 12)
//  945   28:                               SEQUENCE {
//  947    8:                                 OCTET STRING CA 65 8B 95 83 F0 79 23
//  957    2:                                 INTEGER 2048
//  961   12:                                 SEQUENCE {
//  963    8:                                   OBJECT IDENTIFIER
//          :                                     hmacWithSHA256 (1 2 840 113549 2 9)
//  973    0:                                   NULL
//          :                                   }
//          :                                 }
//          :                               }
//  975   29:                             SEQUENCE {
//  977    9:                               OBJECT IDENTIFIER
//          :                                 aes256-CBC (2 16 840 1 101 3 4 1 42)
//  988   16:                               OCTET STRING
//          :                     74 4C 0F 63 4C 1D 26 94 80 08 C0 F0 DD E7 CA 4E
//          :                               }
//          :                             }
//          :                           }
// 1006  640:                         OCTET STRING
//          :                     1D D7 61 88 5D EE CB C2 A5 90 EA 53 92 94 16 B5
//          :                     C1 58 EA CA 50 E3 AA 31 33 36 48 52 E9 6B 3D 4A
//          :                     54 C1 1E 2A 4E D3 42 9E B2 3A DC F1 A2 A1 05 D2
//          :                     62 59 B2 81 6A 63 C3 8C 8E CD E4 2F 45 47 EB 0C
//          :                     A6 9D A5 21 72 C2 4C 39 9F 03 70 BF 19 4B 21 78
//          :                     72 39 47 16 CE B8 42 0A 84 11 90 CA 02 13 69 BF
//          :                     58 7F E3 D9 44 C1 FA 21 75 0A 13 46 43 FB BE 3F
//          :                     41 78 0A 8C C0 87 97 4E D6 EF F5 E5 D3 6E B6 96
//          :                             [ Another 512 bytes skipped ]
//          :                         }
//          :                       }
// 1650   37:                     SET {
// 1652   35:                       SEQUENCE {
// 1654    9:                         OBJECT IDENTIFIER
//          :                           localKeyID (for PKCS #12) (1 2 840 113549 1 9 21)
// 1665   22:                         SET {
// 1667   20:                           OCTET STRING
//          :                     EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15
//          :                     D0 7B 00 6D
//          :                           }
//          :                         }
//          :                       }
//          :                     }
//          :                   }
//          :                 }
//          :               }
//          :             }
//          :           }
//          :         }
//          :       }
//          :     }
// 1689   65:   SEQUENCE {
// 1691   49:     SEQUENCE {
// 1693   13:       SEQUENCE {
// 1695    9:         OBJECT IDENTIFIER sha-256 (2 16 840 1 101 3 4 2 1)
// 1706    0:         NULL
//          :         }
// 1708   32:       OCTET STRING
//          :         BC 79 0E 04 37 14 F1 8F 9C 07 66 1D FE 53 82 E3
//          :         E7 F4 31 13 27 E4 C8 E7 61 D0 BA 7A EA 54 A8 A8
//          :       }
// 1742    8:     OCTET STRING E1 14 4F 8C B4 AF B2 FE
// 1752    2:     INTEGER 2048
//          :     }
//          :   }
#[test]
fn decode_sample_pfx2() {
    let bytes = include_bytes!("examples/example2.pfx");

    let pfx = Pfx::from_der(bytes).expect("expected valid data");
    let reenc_content = pfx.to_der().unwrap();
    assert_eq!(bytes, reenc_content.as_slice());
    println!("{pfx:?}");

    assert_eq!(Version::V3, pfx.version);
    assert_eq!(ID_DATA, pfx.auth_safe.content_type);
    let auth_safes_os = OctetString::from_der(&pfx.auth_safe.content.to_der().unwrap()).unwrap();
    let auth_safes = AuthenticatedSafe::from_der(auth_safes_os.as_bytes()).unwrap();

    // Process first auth safe (from offset 34)
    let auth_safe0 = auth_safes.first().unwrap();
    assert_eq!(ID_DATA, auth_safe0.content_type);

    let auth_safe0_auth_safes_os =
        OctetString::from_der(&auth_safe0.content.to_der().unwrap()).unwrap();
    let safe_bags = SafeContents::from_der(auth_safe0_auth_safes_os.as_bytes()).unwrap();
    for safe_bag in safe_bags {
        match safe_bag.bag_id {
            pkcs12::PKCS_12_CERT_BAG_OID => {
                let cs: ContextSpecific<CertBag> =
                    ContextSpecific::from_der(&safe_bag.bag_value).unwrap();
                assert_eq!(
                    include_bytes!("examples/cert.der"),
                    cs.value.cert_value.as_bytes()
                );
            }
            _ => panic!(),
        };
        //todo inspect attributes
    }

    // Process second auth safe (from offset 984)
    let auth_safe1 = auth_safes.get(1).unwrap();
    assert_eq!(ID_DATA, auth_safe1.content_type);

    let auth_safe1_auth_safes_os =
        OctetString::from_der(&auth_safe1.content.to_der().unwrap()).unwrap();
    let safe_bags = SafeContents::from_der(auth_safe1_auth_safes_os.as_bytes()).unwrap();
    for safe_bag in safe_bags {
        match safe_bag.bag_id {
            pkcs12::PKCS_12_PKCS8_KEY_BAG_OID => {
                let cs: ContextSpecific<EncryptedPrivateKeyInfoRef<'_>> =
                    ContextSpecific::from_der(&safe_bag.bag_value).unwrap();
                let mut ciphertext = cs.value.encrypted_data.as_bytes().to_vec();
                let plaintext = cs
                    .value
                    .encryption_algorithm
                    .decrypt_in_place("1234", &mut ciphertext)
                    .unwrap();
                assert_eq!(include_bytes!("examples/key.der"), plaintext);

                //todo inspect parameters
            }
            _ => panic!(),
        };
        //todo inspect attributes
    }

    // process mac data
    let mac_data = pfx.mac_data.unwrap();
    assert_eq!(ID_SHA_256, mac_data.mac.algorithm.oid);
    assert_eq!(
        hex!(
            "BC 79 0E 04 37 14 F1 8F 9C 07 66 1D FE 53 82 E3 E7 F4 31 13 27 E4 C8 E7 61 D0 BA 7A EA 54 A8 A8"
        ),
        mac_data.mac.digest.as_bytes()
    );
    assert_eq!(
        hex!("E1 14 4F 8C B4 AF B2 FE"),
        mac_data.mac_salt.as_bytes()
    );
    assert_eq!(2048, mac_data.iterations);
}
