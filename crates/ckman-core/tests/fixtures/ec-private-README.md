# EC private-key import fixtures

The five `*-scalar-one-openssl.der` files contain PKCS#8 private keys with
the integer scalar **one**, padded to their curve's fixed width. These are
public test values, never credentials. Each inner SEC1 ECPrivateKey includes
the corresponding uncompressed public point, calculated independently by
OpenSSL 3.5.9.

| File prefix | Curve OID | Scalar width |
| --- | --- | --- |
| p256 | 1.2.840.10045.3.1.7 | 32 |
| p384 | 1.3.132.0.34 | 48 |
| p521 | 1.3.132.0.35 | 66 |
| k256 | 1.3.132.0.10 | 32 |
| sm2 | 1.2.156.10197.1.301 | 32 |

Construction: encode SEC1 version 1, the fixed-width scalar, and the named
curve in explicit `[0]`. Export its public point with `openssl pkey -inform
DER -in scalar.sec1 -pubout -outform DER`. Add that SPKI's BIT STRING as
explicit `[1]` in the SEC1 key, then convert with:

```sh
openssl pkcs8 -topk8 -nocrypt -inform DER -in scalar.sec1 -outform DER -out fixture.der
openssl pkey -inform DER -in fixture.der -check -noout
```

Every fixture passes OpenSSL's key check. Regression cases mutate the scalar
or curve while retaining this independent public point, and test compressed
representations of the same point. Zero scalars were also checked separately
with OpenSSL and rejected on all five curves.
