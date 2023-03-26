# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.1 (2023-03-26)
### Added
- `FromStr` impls for `RdnSequence` (`Name`), `RelativeDistinguishedName`, and
  `AttributeTypeAndValue` ([#949])

### Changed
- Deprecate `encode_from_string` functions ([#951])

[#949]: https://github.com/RustCrypto/formats/pull/949
[#951]: https://github.com/RustCrypto/formats/pull/951

## 0.2.0 (2023-03-18)
### Added
- Feature-gated `Arbitrary` impl for `Certificate` ([#761])
- Allow request to be serialized to PEM ([#819])
- `Display` impl for `SerialNumber` ([#820])
- `std` feature implies `const-oid/std` ([#874])

### Changed
- Serial numbers are formatted as `PrintableString` ([#794])
- `SerialNumber` is now a specialized object ([#795])
- MSRV 1.65 ([#805])
- Make types owned instead of reference-based ([#806], [#841])
- Bump `der` to v0.7 ([#899])
- Bump `spki` to v0.7 ([#900])

### Fixed
- Handling of negative serial numbers ([#823], [#831])

### Removed
- `alloc` feature: now unconditionally required ([#841])

[#761]: https://github.com/RustCrypto/formats/pull/761
[#794]: https://github.com/RustCrypto/formats/pull/794
[#795]: https://github.com/RustCrypto/formats/pull/795
[#805]: https://github.com/RustCrypto/formats/pull/805
[#806]: https://github.com/RustCrypto/formats/pull/806
[#819]: https://github.com/RustCrypto/formats/pull/819
[#820]: https://github.com/RustCrypto/formats/pull/820
[#823]: https://github.com/RustCrypto/formats/pull/823
[#831]: https://github.com/RustCrypto/formats/pull/831
[#841]: https://github.com/RustCrypto/formats/pull/841
[#874]: https://github.com/RustCrypto/formats/pull/874
[#899]: https://github.com/RustCrypto/formats/pull/899
[#900]: https://github.com/RustCrypto/formats/pull/900

## 0.1.1 (2022-12-10)
### Added
- Support `TeletexString` in `DirectoryString` ([#692])
- Re-export `spki` ([#701])
- `PemLabel` impl for `Certificate` ([#763])
- `ValueOrd` impl for `Version` and other derived types ([#723])

### Fixed
-  `countryName` should always be `PrintableString` ([#760])

[#692]: https://github.com/RustCrypto/formats/pull/692
[#701]: https://github.com/RustCrypto/formats/pull/701
[#723]: https://github.com/RustCrypto/formats/pull/723
[#760]: https://github.com/RustCrypto/formats/pull/760
[#763]: https://github.com/RustCrypto/formats/pull/763

## 0.1.0 (2022-07-23)
- Initial release
