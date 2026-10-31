# OpenSSL subject fixture

`subject-openssl.der` is the raw X.501 subject Name from a throwaway
certificate generated with OpenSSL 3.5.9:

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key.pem
openssl req -new -x509 -key key.pem -outform DER -out cert.der \
  -subj '/C=SG/O=Example/OU=branch+CN=foo\;bar\,\\tail/emailAddress=alice@example.com/serialNumber=42'
openssl x509 -inform DER -in cert.der -noout -subject -nameopt RFC2253
```

The last command's output, without `subject=`, is `subject-openssl.txt`.
The DER fixture is the sixth field of the version-3 TBSCertificate
(after version, serial number, signature algorithm, issuer and validity).
It contains no key or signature. It cross-checks RDN order, SET sorting,
escaped punctuation and the UTF8String/PrintableString/IA5String types.
