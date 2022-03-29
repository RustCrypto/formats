# [RustCrypto]: SSH Key Formats

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

[Documentation][docs-link]

## About

Pure Rust implementation of SSH key file format decoders/encoders as described
in [RFC4251] and [RFC4253] as well as OpenSSH's [PROTOCOL.key] format
specification  and `authorized_keys` files.

## Features

- [x] Constant-time Base64 decoding/encoding using `base64ct`/`pem-rfc7468` crates
- [x] `no_std` support including support for "heapless" (no-`alloc`) targets
- [x] Decoding/encoding OpenSSH-formatted public/private keys
- [x] Private key encryption/decryption (`bcrypt-pbkdf` + `aes256-ctr` only)
- [x] Fingerprint support (SHA-256 only)
- [x] Parsing `authorized_keys` files
- [x] Built-in zeroize support for private keys

#### TODO

- [ ] Key generation support (WIP - see table below)
- [ ] Interop with digital signature crates
  - [x] `ed25519-dalek`
  - [ ] `p256` (ECDSA)
  - [ ] `p384` (ECDSA)
  - [ ] `rsa`
- [ ] OpenSSH certificate support
- [ ] U2F/FIDO2 key support (`sk-*`)
- [ ] Legacy (pre-OpenSSH) SSH key format support
  - [ ] PKCS#1
  - [ ] PKCS#8
  - [ ] [RFC4716] public keys
  - [ ] SEC1

## Supported algorithms

| Name                                 | Decoding | Encoding | `no_std`  | Keygen |
|--------------------------------------|----------|----------|-----------|--------|
| `ecdsa-sha2-nistp256`                | ✅        | ✅        | heapless  | ⛔️     |
| `ecdsa-sha2-nistp384`                | ✅        | ✅        | heapless  | ⛔️     |
| `ecdsa-sha2-nistp521`                | ✅        | ✅        | heapless  | ⛔️     |
| `ssh-dsa`                            | ✅        | ✅        | `alloc` ️ | ⛔      |
| `ssh-ed25519`                        | ✅        | ✅        | heapless  | ✅️     |
| `ssh-rsa`                            | ✅        | ✅        | `alloc`   | ⛔️     |
| `sk-ecdsa-sha2-nistp256@openssh.com` | ⛔        | ⛔        | heapless  | ⛔️     |
| `sk-ssh-ed25519@openssh.com`         | ⛔        | ⛔        | heapless  | ✅️     |

## Minimum Supported Rust Version

This crate requires **Rust 1.57** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor
version bump.

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/ssh-key.svg
[crate-link]: https://crates.io/crates/ssh-key
[docs-image]: https://docs.rs/ssh-key/badge.svg
[docs-link]: https://docs.rs/ssh-key/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.57+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/300570-formats
[build-image]: https://github.com/RustCrypto/formats/actions/workflows/ssh-key.yml/badge.svg
[build-link]: https://github.com/RustCrypto/formats/actions/workflows/ssh-key.yml

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[RFC4251]: https://datatracker.ietf.org/doc/html/rfc4251
[RFC4253]: https://datatracker.ietf.org/doc/html/rfc4253
[RFC4716]: https://datatracker.ietf.org/doc/html/rfc4716
[PROTOCOL.key]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD
