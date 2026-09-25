# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 (UNRELEASED)

### Added
- Implement `PemLabel` for `ContentInfo` ([#2353])
- Callbacks in the SignerInfo builder ([#1991])
- decode a `MessageDigest` from an `Attribute` ([#1992])
- `DecodeValue` implementation for `Time` ([#1986])
- types from RFC6031 - Symmetric Key Package Content ([#1952])
- `MessageDigest` as a newtype around `OctetString` ([#1967])
- ECC KeyAgreementRecipientInfo initial support ([#1579])
- PasswordRecipientInfoBuilder for CMS ([#1273])
- Support for `AsyncSigner` ([#1533])
- implementation for `SignedDataBuilder` for `PSS` ([#1531])
- Support for `KEMRecipientInfo` for RFC9629 ([#1485])

### Changes
- MSRV bumped to 1.85, Edition bumped to 2024 ([#1689])
- Implement `core::error::Error` for `cms::builder::Error` ([#1429] & [#2394])
- Bump `zeroize` to `1.8.1` ([#1419])
- Fixup content-type comparison ([#1978])
- Accept a reference in the `From<&Certificate> for SignerIdentifier` ([#1962] & [#1966])
- Propagate std feature to `x509-cert` ([#1990])
- Bump `pem-rfc7468` to `1.0.0` (#[2096])
- Bump `rand` to `0.10` (#[2212])
- Bump `der` to `0.8` (#[2234])
- Bump `digest` to `0.11` (#[2237])
- Bump `cipher` to `0.5` (#[2238])
- Bump `sha2` to `0.11` (#[2273])
- Bump `spki` to `0.8` (#[2277])
- Bump `aes` to `0.9` (#[2281])
- Bump `aes-kw` to `0.3` (#[2282])
- Bump `cbc` to `0.2` (#[2282])
- Bump `ctr` to `0.10` (#[2282])
- Bump `des` to `0.9` (#[2282])
- Bump `sha3` to `0.11` (#[2282])
- Bump `pkcs5` to `0.8` (#[2301])
- Bump `signature` to `3` (#[2326])
- Bump `elliptic-curve` to `0.14.1` (#[2364])
- Bump `ecdsa` to `0.17` (#[2371])
- Bump `p256` to `0.14` (#[2371])
- Bump `x509-cert` to `0.3` (#[2375])

### Removed
- `alloc` feature, `cms` has a hard dependency on `liballoc` ([#1566])
- direct dependency on `std` ([#2395])
- `pem` dependency ([#1565])

[#1273]: https://github.com/RustCrypto/formats/pull/1273
[#1419]: https://github.com/RustCrypto/formats/pull/1419
[#1429]: https://github.com/RustCrypto/formats/pull/1429
[#1485]: https://github.com/RustCrypto/formats/pull/1485
[#1531]: https://github.com/RustCrypto/formats/pull/1531
[#1533]: https://github.com/RustCrypto/formats/pull/1533
[#1565]: https://github.com/RustCrypto/formats/pull/1565
[#1566]: https://github.com/RustCrypto/formats/pull/1566
[#1579]: https://github.com/RustCrypto/formats/pull/1579
[#1689]: https://github.com/RustCrypto/formats/pull/1689
[#1962]: https://github.com/RustCrypto/formats/pull/1962
[#1966]: https://github.com/RustCrypto/formats/pull/1966
[#1967]: https://github.com/RustCrypto/formats/pull/1967
[#1978]: https://github.com/RustCrypto/formats/pull/1978
[#1986]: https://github.com/RustCrypto/formats/pull/1986
[#1990]: https://github.com/RustCrypto/formats/pull/1990
[#1991]: https://github.com/RustCrypto/formats/pull/1991
[#2096]: https://github.com/RustCrypto/formats/pull/2096
[#2212]: https://github.com/RustCrypto/formats/pull/2212
[#2234]: https://github.com/RustCrypto/formats/pull/2234
[#2237]: https://github.com/RustCrypto/formats/pull/2237
[#2238]: https://github.com/RustCrypto/formats/pull/2238
[#2273]: https://github.com/RustCrypto/formats/pull/2273
[#2277]: https://github.com/RustCrypto/formats/pull/2277
[#2281]: https://github.com/RustCrypto/formats/pull/2281
[#2282]: https://github.com/RustCrypto/formats/pull/2282
[#2301]: https://github.com/RustCrypto/formats/pull/2301
[#2326]: https://github.com/RustCrypto/formats/pull/2326
[#2353]: https://github.com/RustCrypto/formats/pull/2353
[#2364]: https://github.com/RustCrypto/formats/pull/2364
[#2371]: https://github.com/RustCrypto/formats/pull/2371
[#2375]: https://github.com/RustCrypto/formats/pull/2375
[#2394]: https://github.com/RustCrypto/formats/pull/2394
[#2395]: https://github.com/RustCrypto/formats/pull/2395

## 0.2.3 (2024-01-08)
### Added
- RFC 5544 `TimeStampedData` implementation ([#1258])

[#1258]: https://github.com/RustCrypto/formats/pull/1258

## 0.2.2 (2023-07-14)
### Added
- `SignedData` builder ([#1051])

### Changed
- Deprecate `pkcs7` in favor of `cms` ([#1062])
- der: add `SetOf(Vec)::insert(_ordered)`; deprecate `add` ([#1067])
- Re-enable all minimal-versions checks ([#1071])

### Fixed
- Don't insert signing time attribute by default ([#1148])
- Fixed encoding of `SubjectKeyIdentifier` ([#1152])

[#1051]: https://github.com/RustCrypto/formats/pull/1051
[#1062]: https://github.com/RustCrypto/formats/pull/1062
[#1067]: https://github.com/RustCrypto/formats/pull/1067
[#1071]: https://github.com/RustCrypto/formats/pull/1071
[#1148]: https://github.com/RustCrypto/formats/pull/1148
[#1152]: https://github.com/RustCrypto/formats/pull/1152

## 0.2.1 (2023-05-04)
### Added
- Convenience functions for converting cert(s) to certs-only `SignedData` message ([#1032])

[#1032]: https://github.com/RustCrypto/formats/pull/1032

## 0.2.0 (2023-03-18)
- Initial RustCrypto release

## 0.1.0 (2019-05-08)
