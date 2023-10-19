use std::println;

use der::{Decode, PemReader};
use pkcs10::CertificationRequest;

#[test]
fn parsing_test() -> der::Result<()> {
    // This CSR is from Wikipedia and prints as follows:
    // $ openssl req -text -noout -in request.pem
    //Certificate Request:
    //    Data:
    //      Version: 0 (0x0)
    //      Subject: C=US, ST=California, L=San Francisco, O=Wikimedia Foundation, Inc., CN=*.wikipedia.org
    //      Subject Public Key Info:
    //          Public Key Algorithm: rsaEncryption
    //          RSA Public Key: (512 bit)
    //              Modulus (512 bit):
    //                  00:be:a2:0c:4c:e9:3f:47:c2:1c:c1:b9:f0:53:c4:
    //                  41:4a:60:b8:5a:88:d4:54:c3:ef:3e:28:ff:15:e0:
    //                  54:ce:f6:6c:bb:e4:99:25:af:04:a9:6b:8c:a6:a4:
    //                  03:0c:a5:3c:8a:f5:c6:38:1c:86:89:39:76:76:d6:
    //                  89:bc:e5:cd:2f
    //              Exponent: 65537 (0x10001)
    //      Attributes:
    //          a0:00
    //  Signature Algorithm: sha1WithRSAEncryption
    //      07:f8:b7:40:37:49:08:c4:13:82:cb:1f:57:e9:00:db:fc:b4:
    //      a5:7e:53:3f:e2:f3:9e:99:1f:52:91:31:96:59:e1:8f:e1:99:
    //      3b:b4:88:78:14:f5:73:27:5d:02:34:bb:05:20:2b:fe:ba:32:
    //s    fe:20:38:cd:8d:2e:dc:31:ea:43
    let csr = r#"
-----BEGIN CERTIFICATE REQUEST-----
MIIBMzCB3gIBADB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEW
MBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEjMCEGA1UEChMaV2lraW1lZGlhIEZvdW5k
YXRpb24sIEluYy4xGDAWBgNVBAMUDyoud2lraXBlZGlhLm9yZzBcMA0GCSqGSIb3
DQEBAQUAA0sAMEgCQQC+ogxM6T9HwhzBufBTxEFKYLhaiNRUw+8+KP8V4FTO9my7
5JklrwSpa4ympAMMpTyK9cY4HIaJOXZ21om85c0vAgMBAAGgADANBgkqhkiG9w0B
AQUFAANBAAf4t0A3SQjEE4LLH1fpANv8tKV+Uz/i856ZH1KRMZZZ4Y/hmTu0iHgU
9XMnXQI0uwUgK/66Mv4gOM2NLtwx6kM=
-----END CERTIFICATE REQUEST-----
"#;

    let mut pem_reader = PemReader::new(csr.as_bytes())?;

    let decoded = CertificationRequest::decode(&mut pem_reader)?;

    println!("decoded: {:?}", decoded);

    Ok(())
}

#[test]
fn rsa_csr_parsing_test() -> der::Result<()> {
    let csr = include_str!("./examples/rsa_csr.pem");

    let mut pem_reader = PemReader::new(csr.as_bytes())?;

    let decoded = CertificationRequest::decode(&mut pem_reader)?;

    println!("decoded: {:?}", decoded);

    Ok(())
}
