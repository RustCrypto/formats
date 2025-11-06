# [RustCrypto]: Modular Crypt Format

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the Modular Crypt Format (MCF), which is used to store password hashes.

## About

Modular Crypt Format is the name for a bespoke set of password hash formats associated with the
POSIX [`crypt(3)`] function which take the form `${id}$...`, where `{id}` is a short numeric or
lower case alphanumeric  algorithm identifier optionally containing a hyphen character (`-`),
followed  by `$` as a delimiter, further followed by an algorithm-specific serialization of a
password hash, typically using a variant (often an algorithm-specific variant) of Base64.

This algorithm-specific serialization contains one or more fields `${first}[${second}]...`, where
each field only uses characters in the regexp range `[A-Za-z0-9./+=,\-]`. Usually, these include
a salt and the output of a password hashing function.

Note that MCF has no official specification describing it, and no central registry of identifiers
exists, nor are there more specific rules for the format than outlined above. MCF is more of an
ad hoc idea of how to serialize password hashes rather than a standard.

This crate provides types for working with Modular Crypt Format in as generic a manner as possible.

For more information and history on MCF, see the [PassLib documentation].

### Example (SHA-crypt w\ SHA-512):

```text
$6$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0
```

## Minimum Supported Rust Version (MSRV) Policy

MSRV increases are not considered breaking changes and can happen in patch releases.

The crate MSRV accounts for all supported targets and crate feature combinations, excluding
explicitly unstable features.

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

[crate-image]: https://img.shields.io/crates/v/mcf?logo=rust
[crate-link]: https://crates.io/crates/mcf
[docs-image]: https://docs.rs/mcf/badge.svg
[docs-link]: https://docs.rs/mcf/
[build-image]: https://github.com/RustCrypto/formats/actions/workflows/mcf.yml/badge.svg
[build-link]: https://github.com/RustCrypto/formats/actions/workflows/mcf.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/300570-formats

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[`crypt(3)`]: https://en.wikipedia.org/wiki/Crypt_(C)
[PassLib documentation]: https://passlib.readthedocs.io/en/stable/modular_crypt_format.html
