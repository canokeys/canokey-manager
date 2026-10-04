#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Destructive ckman 4.0.0 functional regression over a dedicated virtual PC/SC reader.

NFC/NDEF, HID/keyboard output, WebUSB and fault recovery are outside this suite.
Test keys are temporary. A failure retains state and an explicit failed report.
"""
import argparse
import base64
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
import pexpect
from smartcard.System import readers

DEFAULT_ADMIN_PIN = '123456'
DEFAULT_PGP_ADMIN_PIN = '12345678'
DEFAULT_MANAGEMENT_KEY = '010203040506070801020304050607080102030405060708'
APDU_CHUNK_BYTES = 128
SW_OK = 0x9000


def tlv(tag, value):
    size = len(value)
    length = bytes([size]) if size < 0x80 else bytes([0x81, size]) if size < 0x100 else b'\x82' + size.to_bytes(2, 'big')
    return tag.to_bytes((tag.bit_length() + 7) // 8, 'big') + length + value


class Card:
    def __init__(self, reader):
        matches = [item for item in readers() if str(item) == reader]
        assert len(matches) == 1, 'select exactly the named virtual reader'
        self.connection = matches[0].createConnection()

    def __enter__(self):
        self.connection.connect()
        return self

    def __exit__(self, *args):
        self.connection.disconnect()

    def command(self, ins, p1=0, p2=0, data=b'', cla=0, expected=SW_OK):
        chunks = [data[i:i + APDU_CHUNK_BYTES] for i in range(0, len(data), APDU_CHUNK_BYTES)] or [b'']
        for index, chunk in enumerate(chunks):
            chain = index != len(chunks) - 1
            apdu = bytes([cla | (0x10 if chain else 0), ins, p1, p2])
            apdu += bytes([len(chunk)]) + chunk if chunk else b''
            response, sw1, sw2 = self.connection.transmit(list(apdu))
            status = sw1 << 8 | sw2
            if chain:
                assert status == SW_OK, hex(status)
        result = bytes(response)
        while status >> 8 == 0x61:
            response, sw1, sw2 = self.connection.transmit([0, 0xC0, 0, 0, 0])
            result += bytes(response)
            status = sw1 << 8 | sw2
        assert status == expected, f'INS {ins:#04x}: {status:#06x}, expected {expected:#06x}'
        return result

    def select(self, aid):
        return self.command(0xA4, 4, data=bytes.fromhex(aid))


class Suite:
    def __init__(self, binary, reader, work):
        self.binary, self.reader, self.work = str(binary), reader, work
        self.cases = []

    def run(self, label, *args, failure=None, input=None):
        result = subprocess.run([self.binary, '--reader', self.reader, *map(str, args)],
                                input=input, capture_output=True, timeout=120)
        output = result.stdout.decode(errors='replace')
        error = result.stderr.decode(errors='replace')
        if failure is None:
            assert result.returncode == 0, f'{label}: {error}'
        else:
            assert result.returncode != 0 and failure.lower() in (output + error).lower(), f'{label}: expected {failure!r}, got {output + error}'
        self.cases.append(label)
        print(f'PASS {label}', flush=True)
        return output

    def prompt(self, label, args, answers):
        child = pexpect.spawn(self.binary, ['--reader', self.reader, *map(str, args)],
                              encoding='utf-8', timeout=60, echo=False)
        try:
            for prompt, answer in answers:
                child.expect_exact(prompt)
                child.sendline(answer)
            child.expect(pexpect.EOF)
            output = child.before
            child.close()
            for _, answer in answers:
                assert answer not in output, f'{label}: secret appeared in output'
            assert child.exitstatus == 0, f'{label}: {output}'
        finally:
            if child.isalive():
                child.terminate(force=True)
        self.cases.append(label)
        print(f'PASS {label}', flush=True)
        return output

    def reset(self, applet):
        self.run(f'{applet} reset', applet, 'reset', '--force', '--admin-pin', DEFAULT_ADMIN_PIN)

    def restart(self):
        if os.environ.get('CANOKEY_TEST_PRIVATE_IFD') == '1':
            with Card(self.reader) as card:
                card.command(0xEE, data=bytes.fromhex('1256abf0'))
        else:
            subprocess.run([os.environ['CANOKEY_DEVICE_RESTART']], check=True, timeout=120,
                           capture_output=True)

    def oath(self):
        self.reset('oath')
        secret = b'12345678901234567890'
        encoded = base64.b32encode(secret).decode()
        for algorithm in ['sha1', 'sha256', 'sha512']:
            name = f'oracle-{algorithm}'
            self.run(f'OATH {algorithm} add', 'oath', 'accounts', 'add', name, encoded,
                     '--algorithm', algorithm, '--digits', '8')
            before = int(time.time()) // 30
            code = self.run(f'OATH {algorithm} independent code', 'oath', 'accounts', 'code', name, '--single').strip()
            after = int(time.time()) // 30
            expected = {self.otp(secret, counter, algorithm, 8) for counter in range(before, after + 1)}
            assert code in expected, (name, code, expected)
        self.run('OATH URI import', 'oath', 'accounts', 'uri',
                 f'otpauth://hotp/CI:counter?secret={encoded}&issuer=CI&counter=0&digits=6')
        assert 'CI:counter' in self.run('OATH account list', 'oath', 'accounts', 'list', '--oath-type', '--period')
        for counter in range(3):
            code = self.run(f'OATH HOTP counter {counter}', 'oath', 'accounts', 'code', 'CI:counter', '--single').strip()
            # CanoKey increments its stored HOTP counter before calculation.
            assert code == self.otp(secret, counter + 1, 'sha1', 6), repr(code)
        self.run('OATH rename', 'oath', 'accounts', 'rename', 'CI:counter', 'CI:renamed', '--force')
        assert 'CI:renamed' in self.run('OATH rename readback', 'oath', 'accounts', 'list')
        self.run('OATH short default', 'oath', 'accounts', 'set-default', 'CI:renamed', '--slot', 'short')
        self.run('OATH long default', 'oath', 'accounts', 'set-default', 'CI:renamed', '--slot', 'long', '--enter')
        self.run('OATH touch-protected add', 'oath', 'accounts', 'add', 'touch-oracle', encoded, '--touch')
        step = int(time.time()) // 30
        actual = self.run('OATH touch-protected calculation', 'oath', 'accounts', 'code', 'touch-oracle', '--single').strip()
        assert actual in {self.otp(secret, count, 'sha1', 6) for count in range(step, int(time.time()) // 30 + 1)}
        self.run('OATH password set', 'oath', 'access', 'change', '--new-password', 'first-test-password')
        self.run('OATH wrong password', 'oath', 'accounts', 'list', '--password', 'wrong-test-password', failure='password')
        self.run('OATH password change', 'oath', 'access', 'change', '--password', 'first-test-password', '--new-password', 'second-test-password')
        self.run('OATH old password revoked', 'oath', 'accounts', 'list', '--password', 'first-test-password', failure='password')
        self.run('OATH password clear', 'oath', 'access', 'change', '--password', 'second-test-password', '--clear')
        self.run('OATH delete', 'oath', 'accounts', 'delete', 'CI:renamed', '--force')
        assert 'CI:renamed' not in self.run('OATH delete readback', 'oath', 'accounts', 'list')
        self.reset('oath')

    @staticmethod
    def otp(secret, counter, algorithm, digits):
        digest = hmac.digest(secret, counter.to_bytes(8, 'big'), algorithm)
        offset = digest[-1] & 0x0F
        number = int.from_bytes(digest[offset:offset + 4], 'big') & 0x7FFFFFFF
        return str(number % (10 ** digits)).zfill(digits)

    def piv(self):
        self.reset('piv')
        management = ['--management-key', DEFAULT_MANAGEMENT_KEY]
        pin = ['--pin', DEFAULT_ADMIN_PIN]
        public_file = self.work / 'piv-public.pem'
        self.run('PIV key generate', 'piv', 'keys', 'generate', '9a', public_file, '-a', 'ecc-p256', *management)
        public = serialization.load_pem_public_key(public_file.read_bytes())
        self.run('PIV certificate generate', 'piv', 'certificates', 'generate', '9a',
                 '--subject', 'CN=Rust ckman test', *management, *pin)
        cert_file = self.work / 'piv-cert.pem'
        self.run('PIV certificate export', 'piv', 'certificates', 'export', '9a', cert_file)
        cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
        public.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        exported = self.work / 'piv-export.pem'
        self.run('PIV public export verified', 'piv', 'keys', 'export', '9a', exported, '--verify', *pin)
        assert serialization.load_pem_public_key(exported.read_bytes()).public_numbers() == public.public_numbers()
        csr_file = self.work / 'piv.csr'
        self.run('PIV CSR request', 'piv', 'certificates', 'request', '9a', public_file, csr_file,
                 '--subject', 'CN=Rust ckman CSR', *pin)
        csr = x509.load_pem_x509_csr(csr_file.read_bytes())
        assert csr.is_signature_valid and csr.public_key().public_numbers() == public.public_numbers()
        self.run('PIV Unicode container name', 'piv', 'objects', 'name', '9a', 'Test \u4e2d\u6587', *management)
        assert 'Test \u4e2d\u6587' in self.run('PIV container name readback', 'piv', 'objects', 'name', '9a')
        self.run('PIV key move', 'piv', 'keys', 'move', '9a', '95', *management)
        self.run('PIV moved source absent', 'piv', 'keys', 'info', '9a', failure='not found')
        self.run('PIV certificate retained after move', 'piv', 'certificates', 'export', '9a', cert_file)
        self.run('PIV certificate delete', 'piv', 'certificates', 'delete', '9a', *management)
        self.run('PIV deleted certificate absent', 'piv', 'certificates', 'export', '9a', cert_file, failure='not found')
        self.run('PIV moved key retained', 'piv', 'keys', 'info', '95')
        self.run('PIV moved key delete', 'piv', 'keys', 'delete', '95', *management)
        self.run('PIV deleted key absent', 'piv', 'keys', 'info', '95', failure='not found')
        for algorithm, key in [('rsa2048', rsa.generate_private_key(public_exponent=65537, key_size=2048)),
                               ('ecc-p384', ec.generate_private_key(ec.SECP384R1())),
                               ('ed25519', ed25519.Ed25519PrivateKey.generate())]:
            private_file = self.work / f'{algorithm}.pem'
            private_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            self.run(f'PIV {algorithm} import', 'piv', 'keys', 'import', '9c', private_file, *management)
            message = b'ckman PIV independent signature'
            message_file, signature_file = self.work / 'message', self.work / 'signature'
            message_file.write_bytes(message)
            self.run(f'PIV {algorithm} sign', 'piv', 'sign', '9c', message_file, signature_file, *pin)
            signature = signature_file.read_bytes()
            if algorithm.startswith('rsa'):
                key.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            elif algorithm.startswith('ecc'):
                key.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))
            else:
                key.public_key().verify(signature, message)
        format_key = ec.generate_private_key(ec.SECP256R1())
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        formats = [
            ('SEC1', format_key, format_key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()), []),
            ('PKCS1', rsa_key, rsa_key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()), []),
            ('encrypted PKCS8', format_key, format_key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b'file-password')),
                ['--password', 'file-password']),
            ('PKCS12', format_key, pkcs12.serialize_key_and_certificates(b'test', format_key, None, None,
                serialization.BestAvailableEncryption(b'file-password')), ['--password', 'file-password']),
        ]
        for name, key, data, password in formats:
            source = self.work / 'format-key'
            source.write_bytes(data)
            self.run(f'PIV {name} import', 'piv', 'keys', 'import', '9c', source, *password, *management)
            self.run(f'PIV {name} public export', 'piv', 'keys', 'export', '9c', exported)
            actual = serialization.load_pem_public_key(exported.read_bytes())
            assert actual.public_numbers() == key.public_key().public_numbers()
        self.run('PIV random', 'piv', 'random', '32', self.work / 'random')
        assert len((self.work / 'random').read_bytes()) == 32
        # Provision a throwaway attestation signer using the firmware F9 slot.
        signer = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test PIV issuer')])
        issuer = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                  .public_key(signer.public_key()).serial_number(2)
                  .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
                  .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
                  .sign(signer, hashes.SHA256()))
        with Card(self.reader) as card:
            card.select('a000000308000010000100')
            metadata = card.command(0xF7, p2=0x9B)
            assert metadata[:2] == b'\x01\x01'
            algorithm = metadata[2]
            challenge = card.command(0x87, algorithm, 0x9B, tlv(0x7C, tlv(0x81, b'')))
            block = algorithms.AES(bytes.fromhex(DEFAULT_MANAGEMENT_KEY)) if algorithm == 0x0A else TripleDES(bytes.fromhex(DEFAULT_MANAGEMENT_KEY))
            assert len(challenge[4:]) == block.block_size // 8
            cipher = Cipher(block, modes.ECB()).encryptor()
            card.command(0x87, algorithm, 0x9B, tlv(0x7C, tlv(0x82, cipher.update(challenge[4:]) + cipher.finalize())))
            card.command(0xFE, 0x11, 0xF9, tlv(0x06, signer.private_numbers().private_value.to_bytes(32, 'big')))
            container = tlv(0x70, issuer.public_bytes(serialization.Encoding.DER)) + tlv(0x71, b'\0') + tlv(0xFE, b'')
            card.command(0xDB, 0x3F, 0xFF, tlv(0x5C, bytes.fromhex('5fff01')) + tlv(0x53, container))
        self.run('PIV attested key generate', 'piv', 'keys', 'generate', '9e', public_file, '-a', 'ecc-p256', *management)
        self.run('PIV attestation export', 'piv', 'keys', 'attest', '9e', cert_file)
        attested = x509.load_pem_x509_certificate(cert_file.read_bytes())
        signer.public_key().verify(attested.signature, attested.tbs_certificate_bytes, ec.ECDSA(attested.signature_hash_algorithm))
        assert attested.public_key().public_numbers() == serialization.load_pem_public_key(public_file.read_bytes()).public_numbers()
        self.run('PIV PIN-protected management key', 'piv', 'access', 'change-management-key',
                 '--new-management-key', '11' * 24, '--protect', '--force', *management, *pin)
        self.prompt('PIV protected management key used',
                    ['piv', 'keys', 'generate', '9d', public_file, '-a', 'ecc-p256'],
                    [('Enter PIN (to unlock the stored management key): ', DEFAULT_ADMIN_PIN)])
        self.reset('piv')

    def openpgp(self):
        self.reset('openpgp')
        admin = ['--admin-pin', DEFAULT_PGP_ADMIN_PIN]
        self.run('OpenPGP PIN change', 'openpgp', 'access', 'change-pin', '--pin', DEFAULT_ADMIN_PIN, '--new-pin', '654321')
        self.run('OpenPGP reset code set', 'openpgp', 'access', 'change-reset-code', '--reset-code', '87654321', *admin)
        self.run('OpenPGP PIN unblock by reset code', 'openpgp', 'access', 'unblock-pin', '--reset-code', '87654321', '--new-pin', DEFAULT_ADMIN_PIN)
        self.run('OpenPGP admin PIN change', 'openpgp', 'access', 'change-admin-pin', *admin, '--new-admin-pin', 'abcdefgh')
        self.run('OpenPGP admin PIN restore', 'openpgp', 'access', 'change-admin-pin', '--admin-pin', 'abcdefgh', '--new-admin-pin', DEFAULT_PGP_ADMIN_PIN)
        self.run('OpenPGP retry configuration', 'openpgp', 'access', 'set-retries', '4', '5', '6', '--force', *admin)
        self.run('OpenPGP retry restoration', 'openpgp', 'access', 'set-retries', '3', '3', '3', '--force', *admin)
        for policy in ['always', 'once']:
            self.run(f'OpenPGP signature policy {policy}', 'openpgp', 'access', 'set-signature-policy', policy, *admin)
        for role, key in [('sig', ed25519.Ed25519PrivateKey.generate()),
                          ('dec', x25519.X25519PrivateKey.generate()),
                          ('aut', ec.generate_private_key(ec.SECP256R1()))]:
            private_file = self.work / f'pgp-{role}.pem'
            private_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            algorithm = {'sig': 'ed25519', 'dec': 'x25519', 'aut': 'ecc-p256'}[role]
            self.run(f'OpenPGP {role} import', 'openpgp', 'keys', 'import', role, private_file,
                     '--algorithm', algorithm, *admin)
            public_file = self.work / f'pgp-{role}-public.pem'
            self.run(f'OpenPGP {role} export', 'openpgp', 'keys', 'export', role, public_file)
            actual = serialization.load_pem_public_key(public_file.read_bytes()).public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            expected = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            assert actual == expected, f'{role} public key: {actual.hex()} != {expected.hex()}'
            with Card(self.reader) as card:
                card.select('d27600012401')
                card.command(0x20, p2=0x81 if role == 'sig' else 0x82, data=DEFAULT_ADMIN_PIN.encode())
                message = b'ckman OpenPGP independent operation'
                if role == 'sig':
                    key.public_key().verify(card.command(0x2A, 0x9E, 0x9A, message), message)
                elif role == 'aut':
                    digest = hashlib.sha256(message).digest()
                    signature = card.command(0x88, data=digest)
                    width = len(signature) // 2
                    signature = utils.encode_dss_signature(int.from_bytes(signature[:width], 'big'), int.from_bytes(signature[width:], 'big'))
                    key.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))
                else:
                    peer = x25519.X25519PrivateKey.generate()
                    point = peer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                    assert card.command(0x2A, 0x80, 0x86, tlv(0xA6, tlv(0x7F49, tlv(0x86, point)))) == peer.exchange(key.public_key())
            self.cases.append(f'OpenPGP {role} independent private operation')
            certificate_file = self.work / 'pgp-certificate.der'
            # A valid padded certificate exercises multi-chunk certificate DOs.
            issuer = ec.generate_private_key(ec.SECP256R1())
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Rust OpenPGP test')])
            value = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                     .public_key(issuer.public_key()).serial_number(1)
                     .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
                     .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
                     .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier('1.3.6.1.4.1.55555.1'),
                                                               bytes(range(256)) * 3), critical=False)
                     .sign(issuer, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
            certificate_file.write_bytes(value)
            self.run(f'OpenPGP {role} certificate import', 'openpgp', 'certificates', 'import', role, certificate_file, *admin)
            exported = self.work / 'pgp-certificate-out.der'
            self.run(f'OpenPGP {role} certificate export', 'openpgp', 'certificates', 'export', role, exported, '--format', 'der')
            assert exported.read_bytes() == value
            self.run(f'OpenPGP {role} certificate delete', 'openpgp', 'certificates', 'delete', role, *admin)
            self.run(f'OpenPGP {role} key generate', 'openpgp', 'keys', 'generate', role,
                     '--algorithm', algorithm, *admin)
            self.run(f'OpenPGP {role} generated export', 'openpgp', 'keys', 'export', role, public_file)
            generated = serialization.load_pem_public_key(public_file.read_bytes())
            with Card(self.reader) as card:
                card.select('d27600012401')
                card.command(0x20, p2=0x81 if role == 'sig' else 0x82, data=DEFAULT_ADMIN_PIN.encode())
                if role == 'sig':
                    generated.verify(card.command(0x2A, 0x9E, 0x9A, message), message)
                elif role == 'aut':
                    signature = card.command(0x88, data=hashlib.sha256(message).digest())
                    generated.verify(utils.encode_dss_signature(int.from_bytes(signature[:32], 'big'),
                        int.from_bytes(signature[32:], 'big')), message, ec.ECDSA(hashes.SHA256()))
                else:
                    peer = x25519.X25519PrivateKey.generate()
                    point = peer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                    assert card.command(0x2A, 0x80, 0x86, tlv(0xA6, tlv(0x7F49, tlv(0x86, point)))) == peer.exchange(generated)
        for policy in ['once', 'always']:
            self.run(f'OpenPGP signature authorization {policy}', 'openpgp', 'access', 'set-signature-policy', policy, *admin)
            with Card(self.reader) as card:
                card.select('d27600012401')
                card.command(0x20, p2=0x81, data=DEFAULT_ADMIN_PIN.encode())
                card.command(0x2A, 0x9E, 0x9A, b'first')
                card.command(0x2A, 0x9E, 0x9A, b'second', expected=SW_OK if policy == 'once' else 0x6982)
        for policy in ['on', 'cached', 'fixed']:
            self.run(f'OpenPGP touch policy {policy}', 'openpgp', 'keys', 'set-touch', 'sig', policy, '--force', *admin)
            with Card(self.reader) as card:
                card.select('d27600012401')
                card.command(0x20, p2=0x81, data=DEFAULT_ADMIN_PIN.encode())
                card.command(0x2A, 0x9E, 0x9A, b'touch-confirmed signature')
        self.run('OpenPGP fixed touch cannot be disabled', 'openpgp', 'keys', 'set-touch', 'sig', 'off',
                 '--force', *admin, failure='condition')
        self.reset('openpgp')

    def fido(self):
        from fido2.ctap2 import Ctap2, ClientPin, PinProtocolV2
        from fido2.pcsc import CtapPcscDevice
        pin = '12345678'
        self.run('FIDO PIN set', 'fido', 'access', 'set-pin', '--new-pin', pin)
        self.run('FIDO PIN change', 'fido', 'access', 'change-pin', '--pin', pin, '--new-pin', '87654321')
        pin = '87654321'
        self.run('FIDO PIN verify', 'fido', 'access', 'verify-pin', '--pin', pin)
        self.run('FIDO PIN minimum length', 'fido', 'access', 'set-min-length', '8', '--pin', pin)
        self.run('FIDO force PIN change', 'fido', 'access', 'force-change', '--pin', pin)
        self.run('FIDO forced PIN blocks token', 'fido', 'credentials', 'list', '--pin', pin, failure='0x37')
        self.run('FIDO forced PIN change clears flag', 'fido', 'access', 'change-pin', '--pin', pin, '--new-pin', 'abcdefgh')
        pin = 'abcdefgh'
        self.run('FIDO always UV enable', 'fido', 'config', 'toggle-always-uv', '--pin', pin)
        self.run('FIDO always UV disable', 'fido', 'config', 'toggle-always-uv', '--pin', pin)
        with CtapPcscDevice(Card(self.reader).connection, self.reader) as device:
            ctap = Ctap2(device)
            client_pin = ClientPin(ctap, PinProtocolV2())
            rp = 'ckman-test.example'
            token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, rp)
            digest = hashlib.sha256(b'ckman resident credential').digest()
            result = ctap.make_credential(digest, {'id': rp},
                {'id': b'ckman-user', 'name': 'before', 'displayName': 'Before'},
                [{'type': 'public-key', 'alg': -7}], options={'rk': True},
                pin_uv_param=client_pin.protocol.authenticate(token, digest), pin_uv_protocol=2)
            credential = result.auth_data.credential_data
        rows = list(csv.DictReader(io.StringIO(self.run('FIDO resident list CSV', 'fido', 'credentials', 'list', '--csv', '--pin', pin))))
        assert len(rows) == 1 and 'before' in str(rows), rows
        identifier = credential.credential_id.hex()
        self.run('FIDO resident update', 'fido', 'credentials', 'update-user', identifier,
                 '--username', 'after', '--display-name', 'After', '--force', '--pin', pin)
        assert 'after' in self.run('FIDO updated user readback', 'fido', 'credentials', 'list', '--csv', '--pin', pin)
        self.run('FIDO resident field clear', 'fido', 'credentials', 'update-user', identifier,
                 '--display-name', '', '--force', '--pin', pin)
        self.run('FIDO resident delete', 'fido', 'credentials', 'delete', identifier, '--force', '--pin', pin)
        assert rp not in self.run('FIDO deleted resident absent', 'fido', 'credentials', 'list', '--csv', '--pin', pin)
        # One 4076-byte CBOR byte string plus its array header and checksum.
        payload = b'\x81\x59\x0f\xec' + bytes(range(256)) * 15 + bytes(range(236))
        assert len(payload) + 16 == 4096
        blob = payload + hashlib.sha256(payload).digest()[:16]
        original, exported = self.work / 'blob', self.work / 'blob-out'
        original.write_bytes(blob)
        self.run('FIDO full largeBlob write', 'fido', 'blobs', 'write', original, '--pin', pin, '--force')
        self.run('FIDO full largeBlob read', 'fido', 'blobs', 'read', exported)
        assert exported.read_bytes() == blob
        empty = b'\x80'
        original.write_bytes(empty + hashlib.sha256(empty).digest()[:16])
        self.run('FIDO largeBlob clear', 'fido', 'blobs', 'write', original, '--pin', pin, '--force')
        self.restart()
        self.run('FIDO reset within power-on window', 'fido', 'reset', '--force')
        self.run('FIDO PIN set after reset', 'fido', 'access', 'set-pin', '--new-pin', pin)
        self.run('FIDO long touch reset enable', 'fido', 'config', 'enable-long-touch-for-reset',
                 '--pin', pin, '--force')
        duration = Path('/tmp/canokey-test-touch-ms')
        saved = duration.read_bytes() if duration.exists() else None
        try:
            duration.write_text('700\n')
            self.restart()
            self.run('FIDO long touch reset', 'fido', 'reset', '--force')
        finally:
            if saved is None:
                duration.unlink(missing_ok=True)
            else:
                duration.write_bytes(saved)
        self.run('FIDO reset restores short-touch setting', 'fido', 'access', 'set-pin', '--new-pin', pin)
        self.restart()
        self.run('FIDO final reset', 'fido', 'reset', '--force')

    def configuration(self):
        self.prompt('Admin PIN prompt change', ['config', 'admin-pin', 'change'],
                    [('Admin PIN: ', DEFAULT_ADMIN_PIN), ('New Admin PIN: ', '654321'), ('Repeat the new Admin PIN: ', '654321')])
        self.prompt('Admin PIN prompt restore', ['config', 'admin-pin', 'change'],
                    [('Admin PIN: ', '654321'), ('New Admin PIN: ', DEFAULT_ADMIN_PIN), ('Repeat the new Admin PIN: ', DEFAULT_ADMIN_PIN)])
        self.run('Admin PIN status', 'config', 'admin-pin', 'status')
        before = self.run('Configuration snapshot', 'config', 'info')
        self.prompt('LED configuration off', ['config', 'led', 'off'], [('Admin PIN: ', DEFAULT_ADMIN_PIN)])
        self.prompt('LED configuration on', ['config', 'led', 'on'], [('Admin PIN: ', DEFAULT_ADMIN_PIN)])
        self.run('Configuration readback', 'config', 'info')
        assert 'Firmware' not in before or '4.0.0' in before
        for slot in ['short', 'long']:
            secret = bytes(range(20))
            self.run(f'PASS {slot} HMAC configure', 'config', 'pass', 'set', slot, 'hmac',
                     '--key', secret.hex(), '--admin-pin', DEFAULT_ADMIN_PIN)
            challenge = bytes(range(32))
            actual = self.run(f'PASS {slot} independent HMAC', 'oath', 'challenge-response',
                              slot, challenge.hex()).strip()
            assert actual.lower() == hmac.digest(secret, challenge, 'sha1').hex(), actual
            self.run(f'PASS {slot} clear', 'config', 'pass', 'set', slot, 'off',
                     '--admin-pin', DEFAULT_ADMIN_PIN)
        original = self.prompt('SM2 configuration read', ['config', 'sm2'], [('Admin PIN: ', DEFAULT_ADMIN_PIN)])
        self.prompt('SM2 configuration set', ['config', 'sm2', 'set', '--curve-id', '9', '--algorithm-id', '-54'],
                    [('Admin PIN: ', DEFAULT_ADMIN_PIN)])
        updated = self.prompt('SM2 configuration readback', ['config', 'sm2'], [('Admin PIN: ', DEFAULT_ADMIN_PIN)])
        assert '9' in updated and '-54' in updated
        assert '9' in original and '-54' in original, 'fresh virtual firmware SM2 defaults changed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--suite', choices=['configuration', 'oath', 'piv', 'openpgp', 'fido', 'all'], default='all')
    args = parser.parse_args()
    if not (os.environ.get('CANOKEY_USBIP') or os.environ.get('CANOKEY_TEST_PRIVATE_IFD') == '1') or os.environ.get('CKMAN_DESTRUCTIVE') != '1':
        parser.error('requires CANOKEY_USBIP and CKMAN_DESTRUCTIVE=1; use a dedicated virtual key')
    if os.environ.get('CANOKEY_FIRMWARE_VERSION') != '4.0.0':
        parser.error('this suite requires mapped Rust firmware 4.0.0')
    reader = os.environ['CANOKEY_PCSC_READER']
    binary = Path(os.environ.get('CKMAN_BIN', 'target/debug/ckman')).resolve()
    transport = 'private Rust PC/SC IFD' if os.environ.get('CANOKEY_TEST_PRIVATE_IFD') == '1' else 'USB/IP CCID PC/SC'
    report = {'firmware': '4.0.0', 'transport': transport, 'passed': False,
              'excluded': ['NFC/NDEF', 'HID/keyboard', 'WebUSB', 'fault recovery']}
    with tempfile.TemporaryDirectory(prefix='ckman-rust-functional-') as directory:
        suite = Suite(binary, reader, Path(directory))
        try:
            for name in ['configuration', 'oath', 'piv', 'openpgp', 'fido']:
                if args.suite in ['all', name]:
                    getattr(suite, name)()
            report['passed'] = True
        except Exception as error:
            report['error'] = str(error)
            raise
        finally:
            report['checks'] = len(suite.cases)
            report['cases'] = suite.cases
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'checks': report['checks']}))


if __name__ == '__main__':
    main()
