# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.6.0 (2026-03-08)
NOTE: v0.3 - v0.5 skipped to sync version numbers with the `password-hash` crate.

### Added
- `Display` impl for `PasswordHashRef` ([#2114])
- `PasswordHash::push_displayable` ([#2115])
- `PasswordHash::as_password_hash_ref` method ([#2117])
- `Base64::B64` alphabet ([#2152])
- `Base64::Pbkdf2` alphabet ([#2168])

### Changed
- `Error` enum ([#2119])
- Rename `Base64::ShaCrypt` to `Base64::Crypt` replacing old alphabet ([#2134])

### Removed
- `PasswordHashRef` lifetime ([#2116])

[#2114]: https://github.com/RustCrypto/formats/pull/2114
[#2115]: https://github.com/RustCrypto/formats/pull/2115
[#2116]: https://github.com/RustCrypto/formats/pull/2116
[#2117]: https://github.com/RustCrypto/formats/pull/2117
[#2119]: https://github.com/RustCrypto/formats/pull/2119
[#2134]: https://github.com/RustCrypto/formats/pull/2134
[#2152]: https://github.com/RustCrypto/formats/pull/2152
[#2168]: https://github.com/RustCrypto/formats/pull/2168

## 0.2.0 (2025-09-07)
### Added
- `(Try)From` impls for `PasswordHash` <=> `String` ([#2027])
- `(Try)From` impls for `PasswordHashRef` and `&str` ([#2028])
- `PasswordHash::push_str` ([#2029])

### Changed
- Rename `McfHash::push_field_base64` to `McfHash::push_base64` ([#2030])
- Rename `McfHash` => `PasswordHash` ([#2031])
- Rename `McfHashRef` => `PasswordHashRef` ([#2031])
- Make `base64` an optional (on-by-default) feature ([#2032])

[#2027]: https://github.com/RustCrypto/formats/pull/2027
[#2028]: https://github.com/RustCrypto/formats/pull/2028
[#2029]: https://github.com/RustCrypto/formats/pull/2029
[#2030]: https://github.com/RustCrypto/formats/pull/2030
[#2031]: https://github.com/RustCrypto/formats/pull/2031
[#2032]: https://github.com/RustCrypto/formats/pull/2032

## 0.1.0 (2025-07-09)
- Initial release
