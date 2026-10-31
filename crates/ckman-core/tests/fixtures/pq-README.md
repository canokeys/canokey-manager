# Post-quantum key fixtures

These are public, disposable test keys generated with OpenSSL 3.5.9.
ML-DSA-65 uses the seed bytes `00..1f`; ML-KEM-768 uses `00..3f`.
They are unrelated to any physical CanoKey.

Generate them with:

```sh
openssl genpkey -algorithm ML-DSA-65 \
  -pkeyopt hexseed:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -outform DER -out mldsa65-openssl.der
openssl genpkey -algorithm ML-KEM-768 \
  -pkeyopt hexseed:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f \
  -outform DER -out mlkem768-openssl.der
openssl pkey -inform DER -in mldsa65-openssl.der \
  -pubout -outform DER -out mldsa65-openssl-pub.der
openssl pkey -inform DER -in mlkem768-openssl.der \
  -pubout -outform DER -out mlkem768-openssl-pub.der
```

The PKCS#8 `privateKey` contains the seed-and-expanded-key SEQUENCE. Tests
also exercise the `[0] IMPLICIT` seed-only choice and reject expanded-only
keys, since the card import API requires a seed. The public-key fixtures
cross-check the OIDs and encoding against libcanokey's SPKI exporter.

Import validation regenerates both the public key and the expanded private
key from the seed using `fips203`/`fips204` and compares them byte-for-byte
with these independent OpenSSL fixtures. Corrupted seed-and-expanded-key
pairs and mismatching PKCS#8 outer public keys are rejected before device
access. Tests cover raw, OCTET STRING, `[0] IMPLICIT`, and SEQUENCE seed
encodings; expanded-only import remains unsupported by the card API.
