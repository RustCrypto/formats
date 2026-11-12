# [RustCrypto]: Cryptographic Message Syntax (CMS)

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the Cryptographic Message Syntax (CMS) as described
in [RFC 5652], [RFC 5911], and in [RFC 3274].

[Documentation][docs-link]

## About

Cryptographic Message Syntax (CMS) is an IETF standard for encrypted messages,
and can be used to sign and/or encrypt data.  It uses a certificate-based
architecture for authenticating principals who can exchange encrypted and/or
signed messages.

CMS is based on the syntax of PKCS #7, itself based on the Privacy-Enhanced
Mail (PEM) standard.

It's used in many cryptographic standards, such as S/MIME, PKCS#12 and the
RFC 3161 digital timestamping protocol.

## Certificate profiles

CMS certificate and issuer/serial types accept an `x509_cert::certificate::Profile`
parameter. Containing messages and builders propagate the same profile. The
default remains `Rfc5280`, including its certificate serial-number length check.

```rust
use cms::{content_info::ContentInfo, der::{self, Decode}, signed_data::SignedData};

fn decode_signed_data(bytes: &[u8]) -> der::Result<SignedData> {
    ContentInfo::from_der(bytes)?.content.decode_as()
}
```

For nonconforming inputs, explicitly select a custom profile or
`x509_cert::certificate::Raw`, available through the existing `x509-cert/hazmat`
feature. For example, `content.decode_as::<SignedData<Raw>>()` accepts the
oversized serial numbers used by some SCEP clients. Selecting `Raw` bypasses
X.509 profile checks and time adjustments, but not ASN.1 structural validation.
Decoding does not verify signatures or establish certificate trust.

The generic types can require annotations at previously inferred call sites.
Use `let value: SignedData = ...` or `content.decode_as::<SignedData>()` to select
the default profile explicitly. This is a source-compatibility change; default
validation is unchanged.

## Minimum Supported Rust Version (MSRV) Policy

MSRV increases are not considered breaking changes and can happen in patch releases.

The crate MSRV accounts for all supported targets and crate feature combinations, excluding
explicitly unstable features.

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/cms
[crate-link]: https://crates.io/crates/cms
[docs-image]: https://docs.rs/cms/badge.svg
[docs-link]: https://docs.rs/cms/
[build-image]: https://github.com/RustCrypto/formats/actions/workflows/cms.yml/badge.svg
[build-link]: https://github.com/RustCrypto/formats/actions/workflows/cms.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.87+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/300570-formats

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[RFC 3274]: https://www.rfc-editor.org/info/rfc3274
[RFC 5652]: https://www.rfc-editor.org/info/rfc5652
[RFC 5911]: https://www.rfc-editor.org/info/rfc5652
