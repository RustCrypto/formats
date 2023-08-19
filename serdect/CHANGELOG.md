# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## UNRELEASED
### Changed
- Pin upper version of `serde` to <1.0.172 to work around [serde-rs/serde#2538] ([#1201])

[#1201]: https://github.com/RustCrypto/formats/pull/1201
[serde-rs/serde#2538]: https://github.com/serde-rs/serde/issues/2538

## 0.2.0 (2023-02-26)
### Changed
- MSRV 1.60 ([#802])
- Lint improvements ([#824])
- Bump `base16ct` dependency to v0.2 ([#890])

### Fixed
- TOML test ([#864])

[#802]: https://github.com/RustCrypto/formats/pull/802
[#824]: https://github.com/RustCrypto/formats/pull/824
[#864]: https://github.com/RustCrypto/formats/pull/864
[#890]: https://github.com/RustCrypto/formats/pull/890

## 0.1.0 (2022-03-29)
- Initial release
