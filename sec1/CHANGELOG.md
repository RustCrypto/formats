# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.1 (2021-11-18)
### Added
- `serde` feature ([#248])
- Hexadecimal serialization/deserialization support for `EncodedPoint` ([#248])

[#248]: https://github.com/RustCrypto/formats/pull/248

## 0.2.0 (2021-11-17) [YANKED]
### Added
- `pkcs8` feature ([#229])

### Changed
- Rename `From/ToEcPrivateKey` => `DecodeEcPrivateKey`/`EncodeEcPrivateKey` ([#122])
- Use `der::Document` to impl `EcPrivateKeyDocument` ([#133])
- Rust 2021 edition upgrade; MSRV 1.56 ([#136])
- Bump `der` crate dependency to v0.5 ([#222])

### Removed
- I/O related errors ([#158])

[#122]: https://github.com/RustCrypto/formats/pull/122
[#133]: https://github.com/RustCrypto/formats/pull/133
[#136]: https://github.com/RustCrypto/formats/pull/136
[#158]: https://github.com/RustCrypto/formats/pull/158
[#222]: https://github.com/RustCrypto/formats/pull/222
[#229]: https://github.com/RustCrypto/formats/pull/229

## 0.1.0 (2021-09-22)
- Initial release
