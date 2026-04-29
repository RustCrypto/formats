# C2SP x509-limbo fixtures

This directory holds the local integration point for the C2SP `x509-limbo` certificate path-validation corpus.

## Fetching the fixture

`limbo.json` is intentionally ignored by git because it is large. Fetch it with the helper script, which uses the GitHub CLI, resolves the current default-branch commit SHA, checks out that exact commit, copies the fixture, and removes the temporary clone:

```sh
./x509-cert/tests/limbo/fetch.sh
```

Then run the limbo-targeted tests:

```sh
cargo test --package x509-cert -- limbo
```

If `tests/limbo/limbo.json` is absent, the tests print a skip message and return successfully so offline builds are not broken.

## Harness scope

`x509-cert` is a decode-only crate. It does not build chains, validate DNS names, enforce name constraints, check revocation, or apply server/client validation policy. The limbo harness therefore treats the corpus as a DER and extension-decoding corpus, not as a full RFC 5280 validator conformance suite.

For every PEM certificate found in each testcase leaf, intermediate, and trusted-root field, the harness:

- Decodes the PEM payload to DER and parses it with `Certificate::from_der`.
- Re-encodes the parsed certificate and verifies the DER bytes round-trip exactly.
- Re-parses the round-tripped DER to catch unstable encodings.
- Exercises single-certificate extension decoders for `basicConstraints`, `keyUsage`, `extendedKeyUsage`, `subjectAltName`, and `nameConstraints` when present.
- Checks that the parsed validity interval is ordered as `notBefore <= notAfter`.

Expected-success limbo cases must decode all certificates. Expected-failure cases tagged as malformed certificates are expected to fail certificate decoding. Other expected-failure cases are reported as decoded-without-error when the certificates are syntactically valid but the failure requires validation behavior outside this crate.

## Feature gap report

| Limbo feature category | Status | Notes |
| --- | --- | --- |
| `malformed-cert`, malformed ASN.1/DER | EXERCISED | Expected failures should be rejected by PEM/DER or `Certificate::from_der` decoding. |
| `basic-constraints` | EXERCISED | Decodes the extension and observes the `cA` flag when present; no chain role enforcement. |
| `ku`, `key-usage` | EXERCISED | Decodes the extension and records criticality when present; no path-validation semantics. |
| `eku`, `extended-key-usage` | EXERCISED | Decodes the extension and checks presence when present; no server/client policy matching. |
| `san`, `subject-alt-name` | EXERCISED | Decodes general names when present; no peer-name matching. |
| `validity` | EXERCISED | Parses `notBefore`/`notAfter` and checks local ordering; validation-time checks are out of scope. |
| `name-constraints` | PUNTED | Syntax is decoded when present, but subtree enforcement requires chain validation. |
| `path-len`, CA depth, chain building | OUT-OF-SCOPE | Requires path construction and issuer/subject chaining. |
| Trust roots, validation kind, validation policy | OUT-OF-SCOPE | Requires a validator and policy engine. |
| DNS/IP/email peer-name validation | OUT-OF-SCOPE | Requires name matching against the testcase peer name. |
| Signature algorithm/path signature validation | OUT-OF-SCOPE | Requires signature verification across the chain. |
| Revocation, CRL, OCSP | OUT-OF-SCOPE | `x509-cert` parses related structures but does not perform revocation checks. |
| Certificate policies, policy mappings, inhibit-any-policy | OUT-OF-SCOPE | Requires policy-tree processing during path validation. |

The test harness also prints the normalized feature inventory it finds in the local fixture when run with `-- --nocapture` or when an assertion fails.
