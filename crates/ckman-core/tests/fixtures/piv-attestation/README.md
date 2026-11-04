# PIV attestation chain fixtures

`generate.py` uses Python cryptography >=45 to generate a deterministic test
chain with PUBLIC TEST P-256 scalars 1 (root), 2 (F9 issuer), 3 (target).
No private-key files are generated or required. Never use these keys in production.
All certificates are valid from 2020-01-01 to 2040-01-01 UTC; tests use
2030-01-01 (Unix 1893456000). The leaf matches CanoKey firmware 3.1.0's
subject and raw extension values: slot 9a, serial 11223344, policies 02 01.

Independent OpenSSL 4.1.0 chain/signature cross-check (from this directory):

```sh
openssl verify -attime 1893456000 -CAfile root.pem -untrusted issuer.pem leaf.pem
```

Expected: `leaf.pem: OK`. These are host-side policy/crypto fixtures, not a
claim that hardware generated the keys. Scripted transport tests separately
check APDU framing with the 3.1.0 profile. Rust tests re-sign modified
certificates using the public test scalars to isolate policy failures from
signature failures. Target SPKI variants are signed by the same P-256 F9
signer; target algorithms do not determine the attestation signature algorithm.
