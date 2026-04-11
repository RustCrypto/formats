# Test Fixture Files

## Generated fixtures (password: `hunter2`)

All RC2 fixtures contain the same RSA-2048 key and self-signed certificate as the
`test-3des-*.p12` fixtures in this directory.  They differ only in cipher and/or
iteration count.

SHA-256 of the PrivateKeyInfo DER blob (oracle for all RSA decryption tests):
`ccdf40f8d0881c5aa3cb9c563399f5fb590f7615ef7da4d057031bc809c9190d`

This value was independently confirmed with two external tools:
- `openssl pkcs12 -legacy ... -nodes | openssl pkcs8 -nocrypt -topk8 -outform DER | sha256sum`
- `pyca/cryptography` `pkcs12.load_key_and_certificates` + `private_bytes(DER, PKCS8, NoEncryption)`

### RC2-128-CBC fixtures

Generated with:
```bash
openssl genrsa -out key.pem 2048
openssl req -x509 -new -key key.pem -out cert.pem -days 3650 -nodes \
  -subj "/CN=pkcs12-test/O=test/C=US"
openssl pkcs12 -export -legacy \
  -keypbe PBE-SHA1-RC2-128 -certpbe PBE-SHA1-RC2-128 \
  -inkey key.pem -in cert.pem \
  -out test-rc2-128-iter<N>.p12 -passout pass:hunter2 [-iter <N>]
```

| File | Iterations | Key cipher | Cert cipher |
|------|-----------|-----------|------------|
| `test-rc2-128-iter1.p12` | 1 | pbeWithSHAAnd128BitRC2-CBC | pbeWithSHAAnd128BitRC2-CBC |
| `test-rc2-128-iter2048.p12` | 2048 | pbeWithSHAAnd128BitRC2-CBC | pbeWithSHAAnd128BitRC2-CBC |
| `test-rc2-128-iter100000.p12` | 100000 | pbeWithSHAAnd128BitRC2-CBC | pbeWithSHAAnd128BitRC2-CBC |

### RC2-40-CBC fixtures

Generated with:
```bash
openssl pkcs12 -export -legacy \
  -keypbe PBE-SHA1-RC2-40 -certpbe PBE-SHA1-RC2-40 \
  -inkey key.pem -in cert.pem \
  -out test-rc2-40-iter2048.p12 -passout pass:hunter2 -iter 2048
```

| File | Iterations | Key cipher | Cert cipher |
|------|-----------|-----------|------------|
| `test-rc2-40-iter2048.p12` | 2048 | pbeWithSHAAnd40BitRC2-CBC | pbeWithSHAAnd40BitRC2-CBC |

## pyca/cryptography fixture (password: `cryptography`)

`pyca-cert-rc2-key-3des.p12` — from the pyca/cryptography test vectors.
- Certificate bag: pbeWithSHAAnd40BitRC2-CBC, 2048 iterations
- Private key bag: EC (`id-ecPublicKey`), pbeWithSHAAnd3-KeyTripleDES-CBC, 2048 iterations

Current test coverage (`pyca_fixture_parses_and_key_bag_has_3des_oid` in `decrypt_rc2.rs`):
- Verifies the PFX parses correctly (cross-vendor format compatibility)
- Verifies the key bag OID is `pbeWithSHAAnd3-KeyTripleDES-CBC` (not RC2)
- Verifies both RC2 decrypt methods reject the 3DES bag at the OID check

Full key decryption is not yet tested; it requires 3DES decryption support
(planned for a follow-up PR).

SHA-256 of the EC PrivateKeyInfo DER blob (reserved oracle for 3DES PR):
`c5eacb73dd8324007d050afcc807fccd09c1f752634eeafaffc0872b35da4383`

(Confirmed with pyca `private_bytes(DER, PKCS8, NoEncryption)` on the extracted key.)
