# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.7.6 (2021-09-14)
### Added
- `3des` and `des-insecure` features
- `sha1` feature
- Support for AES-192-CBC

### Changed
- Moved to `formats` repo ([#2])

[#2]: https://github.com/RustCrypto/formats/pull/2

## 0.7.5 (2021-07-26)
### Added
- Support for customizing PEM `LineEnding`

### Changed
- Bump `pem-rfc7468` dependency to v0.2

## 0.7.4 (2021-07-25)
### Added
- PKCS#1 support

## 0.7.3 (2021-07-24)
### Changed
- Use `pem-rfc7468` crate

## 0.7.2 (2021-07-20)
### Added
- `Error::ParametersMalformed` variant

## 0.7.1 (2021-07-20)
### Added
- `Error::KeyMalformed` variant

## 0.7.0 (2021-06-07)
### Added
- ASN.1 error improvements

### Changed
- Merge `OneAsymmetricKey` into `PrivateKeyInfo`
- Use scrypt as the default PBES2 KDF
- Return `Result`(s) when encoding 
- Bump `der` to v0.4
- Bump `spki` to v0.4
- Bump `pkcs5` to v0.3

## 0.6.1 (2021-05-24)
### Added
- Support for RFC5958's `OneAsymmetricKey`

### Changed
- Bump `der` to v0.3.5

## 0.6.0 (2021-03-22)
### Changed
- Bump `der` dependency to v0.3
- Bump `spki` dependency to v0.3
- Bump `pkcs5` dependency to v0.2

## 0.5.5 (2021-03-17)
### Changed
- Bump `base64ct` dependency to v1.0

## 0.5.4 (2021-02-24)
### Added
- Encryption helper methods for `FromPrivateKey`/`ToPrivateKey`

## 0.5.3 (2021-02-23)
### Added
- Support for decrypting/encrypting `EncryptedPrivateKeyInfo`
- PEM support for `EncryptedPrivateKeyInfo`
- `Error::Crypto` variant

## 0.5.2 (2021-02-20)
### Changed
- Use `pkcs5` crate

## 0.5.1 (2021-02-18) [YANKED]
### Added
- `pkcs5` feature

### Changed
- Bump `spki` dependency to v0.2.0

## 0.5.0 (2021-02-16) [YANKED]
### Added
- Initial `EncryptedPrivateKeyInfo` support

### Changed
- Extract SPKI-related types into the `spki` crate

## 0.4.1 (2021-02-01)
### Changed
- Bump `basec4ct` dependency to v0.2

## 0.4.0 (2021-01-26)
### Changed
- Bump `der` crate dependency to v0.2
- Use `base64ct` v0.1 for PEM encoding

## 0.3.3 (2020-12-21)
### Changed
- Use `der` crate for decoding/encoding ASN.1 DER

## 0.3.2 (2020-12-16)
### Added
- `AlgorithmIdentifier::parameters_oid` method

## 0.3.1 (2020-12-16)
### Changed
- Bump `const-oid` dependency to v0.4

## 0.3.0 (2020-12-16) [YANKED]
### Added
- `AlgorithmParameters` enum

## 0.2.2 (2020-12-14)
### Fixed
- Decoding/encoding support for Ed25519 keys

## 0.2.1 (2020-12-14)
### Added
- rustdoc improvements

## 0.2.0 (2020-12-14)
### Added
- File writing methods for public/private keys
- Methods for loading `*Document` types from files
- DER encoding support
- PEM encoding support
- `ToPrivateKey`/`ToPublicKey` traits

### Changed
- `Error` enum
- Rename `load_*_file` methods to `read_*_file`

## 0.1.1 (2020-12-06)
### Added
- Helper methods to load keys from the local filesystem

## 0.1.0 (2020-12-05)
- Initial release
