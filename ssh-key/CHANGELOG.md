# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.1 (2022-04-26)
### Added
- Internal `UnixTime` helper type ([#613])

### Changed
- Bump `pem-rfc7468` dependency to v0.6.0 ([#620])
- Further restrict maximum allowed timestamps ([#621])

[#613]: https://github.com/RustCrypto/formats/pull/613
[#620]: https://github.com/RustCrypto/formats/pull/620
[#621]: https://github.com/RustCrypto/formats/pull/621

## 0.4.0 (2022-04-12)
### Added
- Private key decryption support ([#535], [#539])
- Private key encryption support ([#536], [#546])
- Ed25519 keygen/sign/verify support using `ed25519-dalek` ([#551])
- Private key encryption ([#560])
- Certificate decoder ([#574])
- Certificate encoder ([#578])
- Certificate validation support ([#584])
- FIDO/U2F (`sk-*`) certificate and key support ([#575], [#587], [#590])
- `certificate::Builder` (i.e. SSH CA support) ([#592])
- ECDSA/NIST P-256 keygen/sign/verify support using `p256` crate ([#593])
- RSA keygen/sign/verify support using `rsa` crate ([#583], [#594])
- SHA-512 fingerprint support ([#596])
- `serde` support ([#586], [#597])

### Changed
- Consolidate `KdfAlg` and `KdfOpts` into `Kdf` ([#541])
- Rename `CipherAlg` => `Cipher` ([#544])

### Removed
- `PrivateKey::kdf_alg` ([#542])

[#535]: https://github.com/RustCrypto/formats/pull/535
[#536]: https://github.com/RustCrypto/formats/pull/536
[#539]: https://github.com/RustCrypto/formats/pull/539
[#541]: https://github.com/RustCrypto/formats/pull/541
[#542]: https://github.com/RustCrypto/formats/pull/542
[#544]: https://github.com/RustCrypto/formats/pull/544
[#546]: https://github.com/RustCrypto/formats/pull/546
[#551]: https://github.com/RustCrypto/formats/pull/551
[#560]: https://github.com/RustCrypto/formats/pull/560
[#574]: https://github.com/RustCrypto/formats/pull/574
[#575]: https://github.com/RustCrypto/formats/pull/575
[#578]: https://github.com/RustCrypto/formats/pull/578
[#583]: https://github.com/RustCrypto/formats/pull/583
[#584]: https://github.com/RustCrypto/formats/pull/584
[#586]: https://github.com/RustCrypto/formats/pull/586
[#587]: https://github.com/RustCrypto/formats/pull/587
[#590]: https://github.com/RustCrypto/formats/pull/590
[#592]: https://github.com/RustCrypto/formats/pull/592
[#593]: https://github.com/RustCrypto/formats/pull/593
[#594]: https://github.com/RustCrypto/formats/pull/594
[#596]: https://github.com/RustCrypto/formats/pull/596
[#597]: https://github.com/RustCrypto/formats/pull/597

## 0.3.0 (2022-03-16)
### Added
- `FromStr` impls for key types ([#368])
- `PublicKey` encoder ([#369], [#371], [#372], [#373])
- `AuthorizedKeys` parser ([#452])
- `PrivateKey::public_key` and `From` conversions ([#485])
- `PrivateKey` encoder ([#494])
- Validate private key padding bytes ([#495])
- File I/O methods for `PrivateKey` and `PublicKey` ([#494], [#503])
- SHA-256 fingerprint support ([#513])

### Changed
- Use `pem-rfc7468` for private key PEM parser ([#407])
- Make `PublicKey`/`PrivateKey` fields private ([#498])

[#368]: https://github.com/RustCrypto/formats/pull/368
[#369]: https://github.com/RustCrypto/formats/pull/369
[#371]: https://github.com/RustCrypto/formats/pull/371
[#372]: https://github.com/RustCrypto/formats/pull/372
[#373]: https://github.com/RustCrypto/formats/pull/373
[#407]: https://github.com/RustCrypto/formats/pull/407
[#452]: https://github.com/RustCrypto/formats/pull/452
[#485]: https://github.com/RustCrypto/formats/pull/485
[#494]: https://github.com/RustCrypto/formats/pull/494
[#495]: https://github.com/RustCrypto/formats/pull/495
[#498]: https://github.com/RustCrypto/formats/pull/498
[#503]: https://github.com/RustCrypto/formats/pull/503
[#513]: https://github.com/RustCrypto/formats/pull/513

## 0.2.0 (2021-12-29)
### Added
- OpenSSH private key decoder ([#297], [#301], [#307], [#311])
- `MPInt::as_positive_bytes` ([#312])

### Changed
- `MPInt` validates the correct number of leading zeroes are used ([#312])

[#297]: https://github.com/RustCrypto/formats/pull/297
[#301]: https://github.com/RustCrypto/formats/pull/301
[#307]: https://github.com/RustCrypto/formats/pull/307
[#311]: https://github.com/RustCrypto/formats/pull/311
[#312]: https://github.com/RustCrypto/formats/pull/312

## 0.1.0 (2021-12-02)
- Initial release
