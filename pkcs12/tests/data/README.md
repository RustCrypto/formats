# Test Fixture Files

## Generated fixtures (password: `hunter2`)

All three files contain the same RSA-2048 key and self-signed certificate, encrypted
with `pbeWithSHA1And3-KeyTripleDES-CBC`. They differ only in iteration count.

Public key fingerprint (SHA-256 of DER pubkey, oracle for decryption tests):
`adbe3a3bb8f734eed65bb2c841ebce69c3d0fac37722c8d794de5b37399411fd`

Generated with:
```bash
openssl genrsa -out key.pem 2048
openssl req -x509 -new -key key.pem -out cert.pem -days 3650 -nodes -subj "/CN=pkcs12-test/O=test/C=US"
openssl pkcs12 -export -legacy -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES \
  -inkey key.pem -in cert.pem -out test-3des-iter<N>.p12 -passout pass:hunter2 [-iter <N>]
```

| File | Iterations | Cipher |
|------|-----------|--------|
| `test-3des-iter1.p12` | 1 | pbeWithSHA1And3-KeyTripleDES-CBC |
| `test-3des-iter2048.p12` | 2048 | pbeWithSHA1And3-KeyTripleDES-CBC |
| `test-3des-iter100000.p12` | 100000 | pbeWithSHA1And3-KeyTripleDES-CBC |

## pyca/cryptography fixture (password: `cryptography`)

`pyca-cert-rc2-key-3des.p12` — from the pyca/cryptography test vectors.
- Certificate: pbeWithSHA1And40BitRC2-CBC (not tested here)
- Private key: EC (`id-ecPublicKey`), pbeWithSHA1And3-KeyTripleDES-CBC, 2048 iterations

Public key fingerprint (SHA-256 of DER pubkey):
`c5eacb73dd8324007d050afcc807fccd09c1f752634eeafaffc0872b35da4383`
