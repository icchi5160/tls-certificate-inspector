#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only

"""Offline, loopback-only TLS and process-level JSON checks."""
import contextlib
import hashlib
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
sys.path.insert(0, str(Path(__file__).parent / 'fixtures'))
from generate import generate
from cryptography import x509
from cryptography.hazmat.primitives import serialization

binary = sys.argv[1]
checks = 0

def run(args, code):
    global checks
    process = subprocess.run([binary, *args, '--json'], capture_output=True, text=True, timeout=8)
    assert process.returncode == code, (args, process.returncode, process.stdout, process.stderr)
    data = json.loads(process.stdout)
    assert bool(process.stderr) == (code != 0), process.stderr
    checks += 1
    return data

@contextlib.contextmanager
def server(directory, stem='valid', version='1.3', mode='tls', family=socket.AF_INET):
    listener = socket.socket(family)
    listener.bind(('::1' if family == socket.AF_INET6 else '127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    errors, names = [], []
    stop = threading.Event()
    if mode == 'tls':
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3 if version == '1.3' else ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(directory / (stem + '.pem')), str(directory / (stem + '.key')))
        ctx.set_servername_callback(lambda sock, name, context: names.append(name))
    def worker():
        try:
            with listener.accept()[0] as client:
                client.settimeout(4)
                if mode == 'stall':
                    stop.wait(4)
                elif mode == 'plain':
                    client.recv(4096)
                    client.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                else:
                    try:
                        with ctx.wrap_socket(client, server_side=True) as tls:
                            try:
                                tls.recv(1)
                            except (OSError, ssl.SSLError):
                                pass
                    except (ssl.SSLError, ConnectionError):
                        pass  # Expected when the inspector rejects a certificate/version.
        except Exception as exc:
            errors.append(exc)
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    try:
        yield port, names
    finally:
        stop.set()
        thread.join(6)
        listener.close()
        assert not thread.is_alive(), 'server thread leaked'
        assert not errors, errors

with tempfile.TemporaryDirectory(prefix='tls-inspector-tests-') as temp:
    directory = generate(temp)
    def arguments(port, ca='ca'):
        return ['localhost', '--port', str(port), '--ca-file', str(directory / (ca + '.pem')), '--timeout', '2']
    for version in ('1.3', '1.2'):
        for stem, bits, algorithm in [('valid', 2048, 'RSA'), ('ec', 256, 'EC'), ('chain', 2048, 'RSA'), ('cross-signed-chain', 2048, 'RSA')]:
            with server(directory, stem, version) as (port, names):
                data = run(arguments(port) + ['--tls', version], 0)
                # A TLS retry can produce another ClientHello and SNI callback.
                assert names and all(name == 'localhost' for name in names), names
                assert data['connection']['tls_version'] == 'TLSv' + version
                assert data['connection']['cipher_suite'] != 'N/A'
                cert = data['certificate']
                assert cert['public_key_bits'] == bits, cert
                assert cert['public_key_algorithm'] == algorithm, cert
                assert {'DNS: localhost', 'IP: 127.0.0.1', 'IP: ::1', 'EMAIL: test@localhost', 'URI: https://localhost/'} <= set(cert['san']), cert
                assert cert['subject'] != 'N/A' and cert['issuer'] != 'N/A'
                assert cert['not_before'] != 'N/A' and cert['not_after'] != 'N/A'
                assert cert['signature_algorithm'] != 'N/A', cert
                parsed = x509.load_pem_x509_certificate((directory / (stem + '.pem')).read_bytes())
                expected = ':'.join(f'{b:02X}' for b in hashlib.sha256(parsed.public_bytes(serialization.Encoding.DER)).digest())
                assert cert['sha256_fingerprint'] == expected
                expected_serial = parsed.serial_number.to_bytes((parsed.serial_number.bit_length() + 7) // 8, 'big')
                assert cert['serial_number'] == ':'.join(f'{b:02X}' for b in expected_serial)
                assert data['verification']['wolfssl_combined'] == 'PASS'
                assert data['verification']['hostname'] == 'PASS'
                assert data['verification']['overall'] == 'PASS'
                assert data['verification']['chain'] == 'NOT_CHECKED'
    for version in ('1.3', '1.2'):
        for stem, ca, categories in [
            ('expired', 'ca', ['EXPIRED_CERTIFICATE']), ('future', 'ca', ['NOT_YET_VALID']),
            ('mismatch', 'ca', ['HOSTNAME_MISMATCH']), ('valid', 'other-ca', ['INVALID_CERTIFICATE_CHAIN', 'UNTRUSTED_CA']),
            ('self', 'ca', ['INVALID_CERTIFICATE_CHAIN', 'UNTRUSTED_CA']),
            ('missing-intermediate', 'ca', ['INVALID_CERTIFICATE_CHAIN']),
            ('cross-signed-chain', 'unrelated-ca', ['INVALID_CERTIFICATE_CHAIN', 'UNTRUSTED_CA'])]:
            with server(directory, stem, version) as (port, _):
                data = run(arguments(port, ca) + ['--tls', version], 3)
                assert data['error']['category'] in categories, data
                assert data['verification']['overall'] == 'FAIL'
                assert data['verification']['hostname'] != 'PASS'
                assert data['verification']['wolfssl_combined'] != 'PASS'
                assert data['connection']['tls_version'] == 'N/A'
                if stem in ('expired', 'future'):
                    assert data['verification']['validity_period'] == 'FAIL'
                if stem == 'mismatch':
                    assert data['verification']['hostname'] == 'FAIL'
    for missing_ca in ('missing', 'malformed.pem'):
        if missing_ca.endswith('.pem'):
            (directory / missing_ca).write_text('not a certificate')
        with server(directory, mode='stall') as (port, _):
            data = run(arguments(port) + ['--ca-file', str(directory / missing_ca)], 4)
            assert data['error']['category'] == 'TLS_ERROR'
            assert data['verification']['wolfssl_combined'] == 'NOT_CHECKED'
    # A leaf used as an explicit trust anchor is an intentional user trust choice.
    with server(directory, 'self') as (port, _):
        assert run(arguments(port, 'self'), 0)['verification']['overall'] == 'PASS'
    for offered, requested in [('1.2', '1.3'), ('1.3', '1.2')]:
        with server(directory, version=offered) as (port, _):
            assert run(arguments(port) + ['--tls', requested], 4)['error']['category'] == 'TLS_ERROR'
    with server(directory, mode='plain') as (port, _):
        assert run(arguments(port), 4)['error']['category'] == 'TLS_ERROR'
    with server(directory, mode='stall') as (port, _):
        start = time.monotonic()
        assert run(arguments(port) + ['--timeout', '1'], 5)['error']['category'] == 'TIMEOUT'
        assert time.monotonic() - start < 3
    with socket.socket() as closed:
        closed.bind(('127.0.0.1', 0))
        closed_port = closed.getsockname()[1]
    assert run(arguments(closed_port), 4)['error']['category'] == 'TCP_ERROR'
    for args in [[], ['localhost', '--port', '65536'], ['localhost', '--unknown'], ['localhost', '--tls', '1.0']]:
        assert run(args, 2)['error']['category'] == 'ARGUMENT_ERROR'
    help_data = run(['--help'], 0)
    assert 'usage' in help_data
    # Verify IPv6 without requiring external DNS or connectivity.
    try:
        probe = socket.socket(socket.AF_INET6)
        probe.bind(('::1', 0))
        probe.close()
        ipv6 = any(a[0] == socket.AF_INET6 for a in socket.getaddrinfo('localhost', 0, type=socket.SOCK_STREAM))
    except OSError:
        ipv6 = False
    if ipv6:
        with server(directory, family=socket.AF_INET6) as (port, _):
            assert run(arguments(port), 0)['verification']['overall'] == 'PASS'
    else:
        print('IPv6 loopback unavailable: IPv6 test skipped')
print(f'{checks} offline process-level checks passed')
