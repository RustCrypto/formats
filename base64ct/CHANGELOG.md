# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
