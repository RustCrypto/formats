# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.1 (2021-09-14)
### Changed
- Moved to `formats` repo ([#2])

[#2]: https://github.com/RustCrypto/formats/pull/2

## 0.4.0 (2021-06-07)
### Added
- `AlgorithmIdentifier::assert_oids`

### Changed
- Bump `der` to v0.4

## 0.3.0 (2021-03-22)
### Changed
- Bump `der` to v0.3

### Removed
- `AlgorithmParameters` enum

## 0.2.1 (2021-02-22)
### Added
- Impl `Choice` for `AlgorithmParameters`

## 0.2.0 (2021-02-18)
### Changed
- Return `Result` from `AlgorithmIdentifier::params_*`

## 0.1.0 (2021-02-16)
- Initial release
