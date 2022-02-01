# [RustCrypto]: X.501 (Directory Services Types)

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of X.501 Types.

[Documentation][docs-link]

## About X.501

X.501 is a series of standards originally specified in [ISO/IEC 9594] and
subsequently used in numerous standards such as [RFC 2986] and [RFC 5280].
The most common modern use of these types is in X.509 certificates and related
standards.

## Minimum Supported Rust Version

This crate requires **Rust 1.56** at a minimum.

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

[crate-image]: https://img.shields.io/crates/v/x500.svg
[crate-link]: https://crates.io/crates/x500
[docs-image]: https://docs.rs/x500/badge.svg
[docs-link]: https://docs.rs/x500/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/300570-formats
[build-image]: https://github.com/RustCrypto/formats/workflows/x500/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/formats/actions

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[RFC 2986]: https://tools.ietf.org/html/rfc2986
