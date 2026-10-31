# PBKDF2-HMAC-SHA1 encrypted PKCS#8 fixture

`pbkdf2-sha1-openssl.der` wraps the disposable P-256 scalar-one key from
`p256-scalar-one-openssl.der`. The password is `audit`; this is public test
material, not a user credential. OpenSSL 3.5.9 generated it with:

```sh
openssl pkcs8 -topk8 -inform DER -in p256-scalar-one-openssl.der \
  -outform DER -v2 aes-256-cbc -v2prf hmacWithSHA1 -iter 2048 \
  -passout pass:audit -out pbkdf2-sha1-openssl.der
```

PBKDF2's HMAC-SHA1 PRF is the RFC 8018 default, so OpenSSL omits the
optional PRF field. This verifies that importing existing files using that
default succeeds with the correct password and fails with a wrong password.

`pbkdf2-sha1-safe-openssl.p12` holds the same scalar-one key in a plaintext
PKCS#8 key bag inside encrypted SafeContents (without a MAC). Its PBES2
parameters use PBKDF2-HMAC-SHA1, 2048 iterations and AES-256-CBC. Python's
`hashlib.pbkdf2_hmac('sha1', b'audit', salt, 2048, 32)` derived the AES key;
OpenSSL `enc -aes-256-cbc -K KEY -iv IV` encrypted the DER SafeContents.
OpenSSL `pkcs12 -in FILE -passin pass:audit -nodes` independently extracted
the key. This covers decryption of the outer safe as well as PKCS#8 keys.
