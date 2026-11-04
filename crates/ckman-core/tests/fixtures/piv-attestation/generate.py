"""Regenerate public fixtures using Python cryptography >=45; no private files.

Scalars 1/2/3 are PUBLIC TEST KEYS, never production keys. Deterministic ECDSA.
Cross-check with OpenSSL (see README.md). No hardware or network is used.
"""
from pathlib import Path
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

out = Path(__file__).parent
keys = [ec.derive_private_key(i, ec.SECP256R1()) for i in (1, 2, 3)]
names = [x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]) for name in
         ('Test PIV Root', 'Test PIV F9 Issuer', 'CanoKey PIV Attestation 9a')]
for i, role in enumerate(('root', 'issuer', 'leaf')):
    builder = (x509.CertificateBuilder().subject_name(names[i])
               .issuer_name(names[max(0, i-1)]).public_key(keys[i].public_key())
               .serial_number(i+1)
               .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
               .not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc)))
    if i < 2:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=1-i), critical=True)
        builder = builder.add_extension(x509.KeyUsage(False, False, False, False, False,
                                                      True, True, False, False), critical=True)
    else:
        for oid, data in [('1.3.6.1.4.1.66602.1.1', bytes.fromhex('11223344')),
                          ('1.3.6.1.4.1.66602.1.2', bytes([2, 1]))]:
            builder = builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(oid), data), critical=False)
    certificate = builder.sign(keys[max(0, i-1)], hashes.SHA256(), ecdsa_deterministic=True)
    (out / f'{role}.der').write_bytes(certificate.public_bytes(serialization.Encoding.DER))
    (out / f'{role}.pem').write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
