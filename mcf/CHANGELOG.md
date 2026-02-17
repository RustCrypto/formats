# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
