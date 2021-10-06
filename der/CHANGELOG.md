# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.4 (2021-10-06)
### Removed
- Accidentally checked-in `target/` directory ([#66])

[#66]: https://github.com/RustCrypto/formats/pull/66

## 0.4.3 (2021-09-15)
### Added
- `Tag::unexpected_error` ([#33])

[#33]: https://github.com/RustCrypto/formats/pull/33

## 0.4.2 (2021-09-14)
### Changed
- Moved to `formats` repo ([#2])

### Fixed
- ASN.1 `SET` type now flagged with the constructed bit

[#2]: https://github.com/RustCrypto/formats/pull/2

## 0.4.1 (2021-08-08)
### Fixed
- Encoding `UTCTime` for dates with `20xx` years

## 0.4.0 (2021-06-07)
### Added
- `TagNumber` type
- Const generic integer de/encoders with support for all of Rust's integer
  primitives
- `crypto-bigint` support
- `Tag` number helpers
- `Tag::octet`
- `ErrorKind::Value` helpers
- `SequenceIter`

### Changed
- Bump `const-oid` crate dependency to v0.6
- Make `Tag` structured
- Namespace ASN.1 types in `asn1` module
- Refactor context-specific field decoding
- MSRV 1.51
- Rename `big-uint` crate feature to `bigint`
- Rename `BigUInt` to `UIntBytes`
- Have `Decoder::error()` return an `Error`
  
### Removed
- Deprecated methods replaced by associated constants

## 0.3.5 (2021-05-24)
### Added
- Helper methods for context-specific fields
- `ContextSpecific` field wrapper
- Decoder position tracking for errors during `Any<'a>` decoding

### Fixed
- `From` conversion for `BitString` into `Any`

## 0.3.4 (2021-05-16)
### Changed
- Support `Length` of up to 1 MiB

## 0.3.3 (2021-04-15)
### Added
- `Length` constants

### Changed
- Deprecate `const fn` methods replaced by `Length` constants

## 0.3.2 (2021-04-15)
### Fixed
- Non-critical bug allowing `Length` to exceed the max invariant

## 0.3.1 (2021-04-01) [YANKED]
### Added
- `PartialOrd` + `Ord` impls to all ASN.1 types

## 0.3.0 (2021-03-22) [YANKED]
### Added
- Impl `Decode`/`Encoded`/`Tagged` for `String`
- `Length::one` and `Length::for_tlv`
- `SET OF` support with `SetOf` trait and `SetOfRef`

### Changed
- Rename `Decodable::from_bytes` => `Decodable::from_der`
- Separate `sequence` and `message`
- Rename `ErrorKind::Oid` => `ErrorKind::MalformedOid`
- Auto-derive `From` impls for variants when deriving `Choice`
- Make `Length` use `u32` internally
- Make `Sequence` constructor private
- Bump `const_oid` to v0.5
- Bump `der_derive` to v0.3

### Removed
- Deprecated methods
- `BigUIntSize`

## 0.2.10 (2021-02-28)
### Added
- Impl `From<ObjectIdentifier>` for `Any`

### Changed
- Bump minimum `const-oid` dependency to v0.4.4

## 0.2.9 (2021-02-24)
### Added
- Support for `IA5String`

## 0.2.8 (2021-02-22)
### Added
- `Choice` trait

## 0.2.7 (2021-02-20)
### Added
- Export `Header` publicly
- Make `Encoder::reserve` public

## 0.2.6 (2021-02-19)
### Added
- Make the unit type an encoding of `NULL`

## 0.2.5 (2021-02-18)
### Added
- `ErrorKind::UnknownOid` variant

## 0.2.4 (2021-02-16)
### Added
- `Any::is_null` method

### Changed
- Deprecate `Any::null` method

## 0.2.3 (2021-02-15)
### Added
- Additional `rustdoc` documentation

## 0.2.2 (2021-02-12)
### Added
- Support for `UTCTime` and `GeneralizedTime`

## 0.2.1 (2021-02-02)
### Added
- Support for `PrintableString` and `Utf8String`

## 0.2.0 (2021-01-22)
### Added
- `BigUInt` type
- `i16` support
- `u8` and `u16` support
- Integer decoder helper methods

### Fixed
- Handle leading byte of `BIT STRING`s

## 0.1.0 (2020-12-21)
- Initial release
