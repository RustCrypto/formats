# RustCrypto: Formats [![Project Chat][chat-image]][chat-link] ![MSRV][msrv-image] [![dependency status][deps-image]][deps-link] 

Cryptography-related format encoders/decoders e.g. PKCS, X.509

## Crates

| Name | crates.io | Docs | Description |
|------|-----------|------|--------------|
| `base64ct` | [![crates.io](https://img.shields.io/crates/v/base64ct.svg)](https://crates.io/crates/base64ct) | [![Documentation](https://docs.rs/base64ct/badge.svg)](https://docs.rs/base64ct) | Constant-time encoder and decoder of several Base64 variants |
| `const‑oid` | [![crates.io](https://img.shields.io/crates/v/const-oid.svg)](https://crates.io/crates/const-oid) | [![Documentation](https://docs.rs/const-oid/badge.svg)](https://docs.rs/const-oid) | Const-friendly implementation of the ISO/IEC Object Identifier (OID) standard as defined in [ITU X.660] |
| `der` | [![crates.io](https://img.shields.io/crates/v/der.svg)](https://crates.io/crates/der) | [![Documentation](https://docs.rs/der/badge.svg)](https://docs.rs/der) | Decoder and encoder of the Distinguished Encoding Rules (DER) for Abstract Syntax Notation One (ASN.1) as described in [ITU X.690] |
| `pem‑rfc7468` | [![crates.io](https://img.shields.io/crates/v/pem-rfc7468.svg)](https://crates.io/crates/pem-rfc7468) | [![Documentation](https://docs.rs/pem-rfc7468/badge.svg)](https://docs.rs/pem-rfc7468) | Strict PEM encoding for PKIX/PKCS/CMS objects |
| `pkcs1` | [![crates.io](https://img.shields.io/crates/v/pkcs1.svg)](https://crates.io/crates/pkcs1) | [![Documentation](https://docs.rs/pkcs1/badge.svg)](https://docs.rs/pkcs1) | Implementation of PKCS#1: RSA Cryptography Specifications Version 2.2 ([RFC 8017]) |
| `pkcs5` | [![crates.io](https://img.shields.io/crates/v/pkcs5.svg)](https://crates.io/crates/pkcs5) | [![Documentation](https://docs.rs/pkcs5/badge.svg)](https://docs.rs/pkcs5) | Implementation of PKCS#5: Password-Based Cryptography Specification Version 2.1 ([RFC 8018]) |
| `pkcs8` | [![crates.io](https://img.shields.io/crates/v/pkcs8.svg)](https://crates.io/crates/pkcs8) | [![Documentation](https://docs.rs/pkcs8/badge.svg)](https://docs.rs/pkcs8) | Implementation of PKCS#8(v2): Private-Key Information Syntax Specification ([RFC 5208]) and asymmetric key packages ([RFC 5958]) |
| `spki` | [![crates.io](https://img.shields.io/crates/v/spki.svg)](https://crates.io/crates/spki) | [![Documentation](https://docs.rs/spki/badge.svg)](https://docs.rs/spki) | X.509 Subject Public Key Info ([RFC 5280 Section 4.1]) describing public keys as well as their associated AlgorithmIdentifiers (i.e. OIDs) |
| `x509` | [![crates.io](https://img.shields.io/crates/v/x509.svg)](https://crates.io/crates/x509) | [![Documentation](https://docs.rs/x509/badge.svg)](https://docs.rs/x509) | Implementation of the X.509 Public Key Infrastructure Certificate format as described in [RFC 5280] |

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/300570-formats
[deps-image]: https://deps.rs/repo/github/RustCrypto/formats/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/formats
[msrv-image]: https://img.shields.io/badge/rustc-1.51+-blue.svg

[//]: # (links)

[ITU X.660]: https://www.itu.int/rec/T-REC-X.660
[ITU X.690]: https://www.itu.int/rec/T-REC-X.690
[RFC 5208]: https://datatracker.ietf.org/doc/html/rfc5208
[RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
[RFC 5280]: https://datatracker.ietf.org/doc/html/rfc5280
[RFC 5958]: https://datatracker.ietf.org/doc/html/rfc5958
[RFC 8017]: https://datatracker.ietf.org/doc/html/rfc8017
[RFC 8018]: https://datatracker.ietf.org/doc/html/rfc8018
