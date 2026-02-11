#[cfg(test)]
mod tests {
    use cms::content_info::ContentInfo;
    use der::Decode;
    use hex_literal::hex;

    #[test]
    fn convert_indefinite_ber_ejbca_cms() {
        // This represents the cms structure sent by EJBCA for SCEP requests.
        #[rustfmt::skip]
        const EXAMPLE_BER: &[u8] = &hex![
            "30 80"                                            // ContentInfo SEQUENCE (2 elem) (indefinite length)
                "06 09 2a 86 48 86 f7 0d 01 07 02"             //   contentType ContentType OBJECT IDENTIFIER
                "a0 80"                                        //   content [0] ANY (1 elem) (indefinite length)
                    "30 80"                                    //     SignedData SEQUENCE (5 elem) (indefinite length)
                        "02 01 01"                             //       version CMSVersion INTEGER 1
                        "31 00"                                //       digestAlgorithms DigestAlgorithmIdentifiers SET (0 elem)
                        "30 0b"                                //       encapContentInfo EncapsulatedContentInfo SEQUENCE (1 elem)
                            "06 09 2a 86 48 86 f7 0d 01 07 01" //         eContentType ContentType OBJECT IDENTIFIER
                        "a0 80"                                //       CertificateSet ANY (2 elem) (indefinite length)
                            "30 06"                            //         CertificateChoices SEQUENCE (3 elem)
                                "30 00"
                                "30 00"
                                "30 00"
                            "30 06"                            //         CertificateChoices SEQUENCE (3 elem)
                                "30 00"
                                "30 00"
                                "30 00"
                        "00 00"
                        "31 00"                                //       signerInfos SignerInfos SET (0 elem)
                    "00 00"
                "00 00"
            "00 00"
        ];
        assert!(ContentInfo::from_ber(EXAMPLE_BER).is_ok());
    }
}
