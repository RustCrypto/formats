# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- `EncryptedPrivateKeyInfo::decrypt_3des_cbc`: decrypt `pkcs8ShroudedKeyBag` entries
  encrypted with `pbeWithSHAAnd3-KeyTripleDES-CBC` (OID 1.2.840.113549.1.12.1.3)
- SHA-1 KDF test vectors verified against OpenSSL 3.x `PKCS12KDF` provider
- Cross-vendor interoperability test against a pyca/cryptography-generated fixture
- Bouncy Castle cipher-layer isolation test vector

### Changed
- `Pkcs12KeyType` now derives `Copy`, `Clone`, `Debug`, `PartialEq`, `Eq`
- `derive_key_utf8` returns `Err` for `rounds <= 0` (previously silent wrong output)
- Renamed `PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC` → `PKCS_12_PBE_WITH_SHAAND40_BIT_RC2_CBC`
  to match the naming pattern of all other PBE OID constants (breaking change)

## 0.1.0 (2024-01-04)
- Initial release
