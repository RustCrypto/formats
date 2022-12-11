# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
