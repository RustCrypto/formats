# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.3.3 (2021-12-28)
### Fixed
- Potential infinite loop in `Decoder::decode` ([#305])

[#305]: https://github.com/RustCrypto/formats/pull/305

## 1.3.2 (2021-12-26) [YANKED]
### Fixed
- `Decoder` unpadding ([#299])
- Edge case when using `Decoder::new_wrapped` ([#300])

[#299]: https://github.com/RustCrypto/formats/pull/299
[#300]: https://github.com/RustCrypto/formats/pull/300

## 1.3.1 (2021-12-20) [YANKED]
### Added
- `Decoder::new_wrapped` with support for line-wrapped Base64 ([#292], [#293], [#294])

[#292]: https://github.com/RustCrypto/formats/pull/292
[#293]: https://github.com/RustCrypto/formats/pull/292
[#294]: https://github.com/RustCrypto/formats/pull/294

## 1.3.0 (2021-12-02) [YANKED]
### Added
- Stateful `Decoder` type ([#266])

[#266]: https://github.com/RustCrypto/formats/pull/266

## 1.2.0 (2021-11-03)
### Changed
- Rust 2021 edition upgrade; MSRV 1.56 ([#136])

### Fixed
- Benchmarks ([#135])

[#135]: https://github.com/RustCrypto/formats/pull/135
[#136]: https://github.com/RustCrypto/formats/pull/136

## 1.1.1 (2021-10-14)
### Changed
- Update `Util::Lookup` paper references ([#32])

[#32]: https://github.com/RustCrypto/formats/pull/32

## 1.1.0 (2021-09-14)
### Changed
- Moved to `formats` repo; MSRV 1.51+ ([#2])

[#2]: https://github.com/RustCrypto/formats/pull/2

## 1.0.1 (2021-08-14)
### Fixed
- Make `Encoding::decode` reject invalid padding

## 1.0.0 (2021-03-17)
### Changed
- Bump MSRV to 1.47+

### Fixed
- MSRV-dependent TODOs in implementation

## 0.2.1 (2021-03-07)
### Fixed
- MSRV docs

## 0.2.0 (2021-02-01)
### Changed
- Refactor with `Encoding` trait
- Internal refactoring

## 0.1.2 (2021-01-31)
### Added
- bcrypt encoding
- `crypt(3)` encoding

### Changed
- Internal refactoring

## 0.1.1 (2021-01-27)
- Minor code improvements

## 0.1.0 (2021-01-26)
- Initial release
