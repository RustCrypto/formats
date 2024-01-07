# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- [#1251](https://github.com/RustCrypto/formats/pull/1251): Add `_bytes` suffix to function names in the `DeserializeBytes` trait to avoid collisions with function names in the `Deserialize` trait
- [#1135](https://github.com/RustCrypto/formats/pull/1135): `no_std` support for the derive crate. This requires the `std` feature to be enabled when using derive with `Serialize` and `Deserialize`.

### Removed

- [#1251](https://github.com/RustCrypto/formats/pull/1251): Remove the `tls_deserialize_bytes` function from the `Deserialize` trait
