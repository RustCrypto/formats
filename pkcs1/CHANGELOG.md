# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.4 (2021-09-14)
### Changed
- Moved to `formats` repo ([#2])

[#2]: https://github.com/RustCrypto/formats/pull/2

## 0.2.3 (2021-07-26)
### Added
- Support for customizing PEM `LineEnding`

### Changed
- Bump `pem-rfc7468` dependency to v0.2

## 0.2.2 (2021-07-25)
### Fixed
- `Version` encoder

## 0.2.1 (2021-07-25)
### Added
- `Error::Crypto` variant

## 0.2.0 (2021-07-25)
### Added
- `From*`/`To*` traits for `RsaPrivateKey`/`RsaPublicKey`

### Changed
- Use `FromRsa*`/`ToRsa*` traits with `*Document` types

## 0.1.1 (2021-07-24)
### Added
- Re-export `der` crate and `der::UIntBytes`

### Changed
- Replace `Error::{Decode, Encode}` with `Error::Asn1`

## 0.1.0 (2021-07-24) [YANKED]
- Initial release
