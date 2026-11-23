#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only

"""Generate disposable test keys and certificates. Never use these in production."""
import argparse
import datetime as dt
import ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID


def generate(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    def key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    def certificate(cn, public_key, issuer, signing_key, ca=False, start=None, end=None, dns=None):
        builder = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(issuer)
                   .public_key(public_key).serial_number(x509.random_serial_number())
                   .not_valid_before(start or now - dt.timedelta(days=1))
                   .not_valid_after(end or now + dt.timedelta(days=30))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), critical=False)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                  key_encipherment=not ca, data_encipherment=False, key_agreement=False,
                                  key_cert_sign=ca, crl_sign=ca, encipher_only=None, decipher_only=None), critical=True))
        if not ca:
            builder = builder.add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(dns or 'localhost'), x509.DNSName('www.localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1')), x509.IPAddress(ipaddress.ip_address('::1')), x509.RFC822Name('test@localhost'), x509.UniformResourceIdentifier('https://localhost/')]), critical=False)
        return builder.sign(signing_key, hashes.SHA256())
    def save(stem, cert, private_key):
        (directory / (stem + '.pem')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        path = directory / (stem + '.key')
        path.write_bytes(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        path.chmod(0o600)
    ca_key = key()
    ca = certificate('Inspector Test Root', ca_key.public_key(), name('Inspector Test Root'), ca_key, ca=True)
    save('ca', ca, ca_key)
    other_key = key()
    other = certificate('Other Root', other_key.public_key(), name('Other Root'), other_key, ca=True)
    save('other-ca', other, other_key)
    leaf_key = key()
    for stem, kwargs in [('valid', {}), ('expired', {'start': now - dt.timedelta(days=20), 'end': now - dt.timedelta(days=10)}),
                         ('future', {'start': now + dt.timedelta(days=10), 'end': now + dt.timedelta(days=20)}),
                         ('mismatch', {'dns': 'wrong.example'})]:
        save(stem, certificate('localhost', leaf_key.public_key(), ca.subject, ca_key, **kwargs), leaf_key)
    save('self', certificate('localhost', leaf_key.public_key(), name('localhost'), leaf_key), leaf_key)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    save('ec', certificate('localhost', ec_key.public_key(), ca.subject, ca_key), ec_key)
    inter_key = key()
    inter = certificate('Intermediate', inter_key.public_key(), ca.subject, ca_key, ca=True)
    leaf = certificate('localhost', leaf_key.public_key(), inter.subject, inter_key)
    save('missing-intermediate', leaf, leaf_key)
    save('chain', leaf, leaf_key)
    with (directory / 'chain.pem').open('ab') as f:
        f.write(inter.public_bytes(serialization.Encoding.PEM))
    # Root A is trusted locally; the server also sends A cross-signed by B.
    cross_signed_ca = certificate('Inspector Test Root', ca_key.public_key(), other.subject, other_key, ca=True)
    save('cross-signed-chain', leaf, leaf_key)
    with (directory / 'cross-signed-chain.pem').open('ab') as f:
        f.write(inter.public_bytes(serialization.Encoding.PEM))
        f.write(cross_signed_ca.public_bytes(serialization.Encoding.PEM))
    unrelated_key = key()
    unrelated = certificate('Unrelated Root', unrelated_key.public_key(), name('Unrelated Root'), unrelated_key, ca=True)
    save('unrelated-ca', unrelated, unrelated_key)
    return directory

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    generate(parser.parse_args().directory)
