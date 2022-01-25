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
in [RFC4253] and [RFC4716] as well as OpenSSH's [PROTOCOL.key] format specification.

## Features

- [x] Constant-time Base64 decoding using the `base64ct` crate
- [x] `no_std` support including support for "heapless" (no-`alloc`) targets
- [x] Parsing OpenSSH-formatted public and private keys with the following algorithms:
  - [x] DSA (`no_std` + `alloc`)
  - [x] ECDSA (`no_std` "heapless")
  - [x] Ed25519 (`no_std` "heapless")
  - [x] RSA (`no_std` + `alloc`)
- [x] Built-in zeroize support for private keys

#### TODO:

- [ ] Encoder support (currently decode-only)
- [ ] Encrypted private key support
- [ ] Legacy SSH key (pre-OpenSSH) format support
- [ ] Integrations with other RustCrypto crates (e.g. `ecdsa`, `ed25519`, `rsa`)

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
[RFC4253]: https://datatracker.ietf.org/doc/html/rfc4253
[RFC4716]: https://datatracker.ietf.org/doc/html/rfc4716
[PROTOCOL.key]: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
