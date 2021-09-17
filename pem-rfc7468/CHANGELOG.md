# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.2 (2021-09-16)
### Changed
- Allow for data before PEM encapsulation boundary ([#40])

[#40]: https://github.com/RustCrypto/formats/pull/40

## 0.2.1 (2021-09-14)
### Added
- `decode_label` ([#22])
- `Error::HeaderDisallowed` ([#13], [#19], [#21])

### Changed
- Moved to `formats` repo ([#2])

[#2]: https://github.com/RustCrypto/formats/pull/2
[#13]: https://github.com/RustCrypto/formats/pull/13
[#19]: https://github.com/RustCrypto/formats/pull/19
[#21]: https://github.com/RustCrypto/formats/pull/21
[#22]: https://github.com/RustCrypto/formats/pull/22

## 0.2.0 (2021-07-26)
### Added
- Support for customizing PEM line endings

## 0.1.1 (2021-07-24)
### Changed
- Increase LF precedence in EOL stripping functions

### Fixed
- Bug in the size calculation for `decode_vec`

## 0.1.0 (2021-07-23)
- Initial release
