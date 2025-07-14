#[cfg(test)]
mod tests {
    use cms::content_info::ContentInfo;
    use der::Decode;

    #[test]
    fn convert_indefinite_ber_ejbca_cms() {
        // This represents the cms structure sent by EJBCA for SCEP requests.
        #[rustfmt::skip]
        const EXAMPLE_BER: &[u8] = &[
            0x30, 0x80,                                                                         // ContentInfo SEQUENCE (2 elem) (indefinite length)
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,               //   contentType ContentType OBJECT IDENTIFIER
                0xa0, 0x80,                                                                     //   content [0] ANY (1 elem) (indefinite length)
                    0x30, 0x80,                                                                 //     SignedData SEQUENCE (5 elem) (indefinite length)
                        0x02, 0x01, 0x01,                                                       //       version CMSVersion INTEGER 1
                        0x31, 0x00,                                                             //       digestAlgorithms DigestAlgorithmIdentifiers SET (0 elem)
                        0x30, 0x0b,                                                             //       encapContentInfo EncapsulatedContentInfo SEQUENCE (1 elem)
                            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,   //         eContentType ContentType OBJECT IDENTIFIER
                        0xa0, 0x80,                                                             //       CertificateSet ANY (2 elem) (indefinite length)
                            0x30, 0x06,                                                         //         CertificateChoices SEQUENCE (3 elem)
                                0x30, 0x00,
                                0x30, 0x00,
                                0x30, 0x00,
                            0x30, 0x06,                                                         //         CertificateChoices SEQUENCE (3 elem)
                                0x30, 0x00,
                                0x30, 0x00,
                                0x30, 0x00,
                        0x00, 0x00,
                        0x31, 0x00,                                                             //       signerInfos SignerInfos SET (0 elem)
                    0x00, 0x00,
                0x00, 0x00,
            0x00, 0x00,
        ];
        assert!(matches!(ContentInfo::from_ber(EXAMPLE_BER), Ok(_)));
    }
}
