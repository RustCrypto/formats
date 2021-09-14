# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.1 (2021-09-13)
### Changed
- Moved to `formats` repo ([#2])

[#2]: https://github.com/RustCrypto/formats/pull/2

## 0.4.0 (2021-06-07)
### Changed
- Update generated code to support the corresponding `der` crate changes

## 0.3.0 (2021-03-21)
### Added
- `choice::Alternative` and duplicate tracking
- Auto-derive `From` impls for variants when deriving `Choice`

## 0.2.2 (2021-02-22)
### Added
- Custom derive support for the `Choice` trait

## 0.2.1 (2021-02-15)
### Added
- Custom derive support for enums

## 0.2.0 (2021-02-02)
### Added
- Support for `PrintableString` and `Utf8String`

## 0.1.0 (2020-12-21)
- Initial release
