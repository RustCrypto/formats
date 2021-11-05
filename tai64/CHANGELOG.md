# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 3.1.0 (2019-10-25)
- Add `TryFrom` impls for slices
- Add (optional) `serde` support

## 3.0.0 (2019-08-19)
- Remove `failure`

## 2.0.1 (2019-05-24)
- Test all crates on Rust 1.35.0

## 2.0.0 (2019-05-20)
- `no_std` support
- Cleanups and modernization
  - `to_external` and `from_external` replaced with `From`/`TryFrom`
  - `byteorder` crate replaced with `from_be_bytes` / `to_be_bytes`
  - `Error` type
  - Update `quickcheck` to `0.8`
- Update to Rust 2018 edition

## 1.0.0 (2018-10-03)
- Initial 1.0 release.

## 0.2.3 (2018-04-14)
- Fix CI badge location (for crates.io)

## 0.2.2 (2018-04-08)
- `README.md` formatting fixups for [crates.io](https://crates.io)

## 0.2.1 (2018-04-08)
- Use Apache 2.0 license and clarify contribution guidelines

## 0.2.0 (2018-03-27)
- Chrono support

## 0.1.0 (2018-03-20)
- Initial release
