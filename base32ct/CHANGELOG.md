# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 (2025-08-20)
### Changed
- Upgrade to 2024 edition; MSRV 1.85 ([#1670])
- Use `core::error::Error` ([#2006])

### Removed
- `std` feature ([#2006])

[#1670]: https://github.com/RustCrypto/formats/pull/1670
[#2006]: https://github.com/RustCrypto/formats/pull/2006

## 0.2.2 (2025-02-23)
### Added
- `const fn` for `encoded_len` ([#1424])

[#1424]: https://github.com/RustCrypto/formats/pull/1424

## 0.2.1 (2024-05-28)
### Added
- Support for Base32 upper unpadded alphabet ([#1406])

### Fixed
- Broken encoding of unpadded base32 ([#1421])

[#1406]: https://github.com/RustCrypto/formats/pull/1406
[#1421]: https://github.com/RustCrypto/formats/pull/1421

## 0.2.0 (2023-02-26)
### Changed
- MSRV 1.60 ([#802])
- Lint improvements ([#824])

[#802]: https://github.com/RustCrypto/formats/pull/802
[#824]: https://github.com/RustCrypto/formats/pull/824

## 0.1.0 (2022-06-12)
- Initial release
