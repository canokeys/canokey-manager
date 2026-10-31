# RSA export verification fixture

OpenSSL 3.5.9 generated this disposable RSA-2048 public key and its PKCS#1
v1.5/SHA-256 signature of the exact bytes:

```text
ckman RSA export verification fixture\n
```

The final `\n` denotes a single newline byte. No private key is retained.
The fixture was selected so `signature + modulus` still fits in 256 bytes.
This lets the regression test check the RSA signature range independently
of its encoded length. OpenSSL accepts the original signature and rejects
both a prefixed zero byte and the same-width `signature + modulus` form.

Equivalent fixture generation uses:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem
printf 'ckman RSA export verification fixture\n' > message.txt
openssl pkey -in key.pem -pubout -outform DER -out rsa-export-verify-openssl-pub.der
openssl dgst -sha256 -sign key.pem -out rsa-export-verify-openssl.sig message.txt
```

To verify the checked-in signature:

```sh
openssl pkey -pubin -inform DER -in rsa-export-verify-openssl-pub.der -out public.pem
printf 'ckman RSA export verification fixture\n' > message.txt
openssl dgst -sha256 -verify public.pem -signature rsa-export-verify-openssl.sig message.txt
```
