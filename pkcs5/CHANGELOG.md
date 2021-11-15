# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0 (2021-11-15)
### Changed
- Introduce `Error` enum with new error cases ([#26])
- Introduce specialized `Result` type for crate ([#26])
- Rust 2021 edition upgrade; MSRV 1.56 ([#136])
- Bump `der` dependency to v0.5 ([#222])
- Bump `spki` dependency to v0.5 ([#223])

### Removed
- Legacy DES encryption support ([#25])

[#25]: https://github.com/RustCrypto/formats/pull/25
[#26]: https://github.com/RustCrypto/formats/pull/26
[#136]: https://github.com/RustCrypto/formats/pull/136
[#222]: https://github.com/RustCrypto/formats/pull/222
[#223]: https://github.com/RustCrypto/formats/pull/223

## 0.3.2 (2021-09-14)
### Added
- `3des` and `des-insecure` features
- `sha1` feature
- Support for AES-192-CBC

### Changed
- Moved to `formats` repo ([#2])

[#2]: https://github.com/RustCrypto/formats/pull/2

## 0.3.1 (2021-08-30)
### Changed
- Bump `scrypt` dependency to 0.8
- Bump `pbkdf2` dependency to v0.9

## 0.3.0 (2021-06-07)
### Changed
- Bump `der` crate dependency to v0.4
- Bump `spki` crate dependency to v0.4

## 0.2.2 (2021-05-26)
### Added
- `scrypt` support as specified in RFC 7914

## 0.2.1 (2021-04-29)
### Changed
- Bump `aes` to v0.7
- Bump `block-modes` to v0.8
- Bump `hmac` to v0.11
- Bump `pbkdf2` to v0.8

## 0.2.0 (2021-03-22)
### Changed
- Bump `der` to v0.3
- Bump `spki` to v0.3

## 0.1.1 (2021-02-23)
### Added
- Encryption support

## 0.1.0 (2021-02-20)
- Initial release
