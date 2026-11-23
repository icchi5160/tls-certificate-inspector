<!-- SPDX-License-Identifier: GPL-3.0-only -->

# TLS Certificate Inspector

A small C++17 CLI for inspecting a TLS server's verified X.509 leaf certificate with wolfSSL on Ubuntu Linux. This portfolio project demonstrates TLS/PKI concepts, explicit ownership, bounded network operations, and repeatable failure tests. It uses the system wolfSSL library; it implements neither TLS nor an ASN.1 parser.

## Features

- TLS 1.3 by default; explicit, exact TLS 1.2 selection without fallback.
- IPv4 and IPv6 sockets, DNS hostname verification, SNI, and required peer verification.
- Subject, issuer, serial, validity dates, SANs, RSA/EC key sizes, signature algorithm, and SHA-256 leaf fingerprint.
- Human-readable and JSON reports, including on errors; distinct exit codes.
- A shared deadline for DNS resolution, TCP connection attempts, and TLS handshake.
- Offline tests using disposable local CAs, certificates, and TLS servers.

## Requirements

Ubuntu Linux, a C++17 compiler, CMake >= 3.16, and wolfSSL >= 5.9.4 with TLS 1.2/1.3, SNI, `OPENSSL_EXTRA`, `KEEP_PEER_CERT`, `WOLFSSL_ALT_CERT_CHAINS`, and certificate date validation enabled. Headers must match the linked library. Configuration rejects older versions, missing required features, disabled certificate time checking, and header/runtime version mismatches.

The tested baseline is upstream **wolfSSL 5.9.4**, GCC 13.3, CMake 3.28.3, Python 3.12, and Python cryptography 41.0.7 on Ubuntu 24.04. CI builds the same pinned wolfSSL release. Version 5.9.4 fixes certificate-validation vulnerabilities described in its [release notes](https://github.com/wolfSSL/wolfssl/releases/tag/v5.9.4-stable), including CVE-2026-93302. Keep monitoring upstream security releases and rerun the tests when updating; the minimum version is not a permanent guarantee that all future issues are fixed.

Tests additionally require Python 3 and `cryptography`. Python's standard `ssl` module provides the independent local test server; the application itself links only wolfSSL and standard system libraries. OpenSSL development headers and the OpenSSL CLI are not needed.

```bash
sudo apt-get update
sudo apt-get install -y gcc g++ make cmake curl ca-certificates python3-cryptography
```

## Build Instructions

If a suitable wolfSSL is already installed, the basic build remains:

```bash
cmake -S . -B build
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

Ubuntu 24.04's original wolfSSL 5.6.6 package is too old for this project. To install the tested release without administrator privileges, run the following from the project root:

```bash
bash scripts/install-wolfssl.sh "$PWD/.deps/wolfssl-5.9.4"
cmake -S . -B build -DCMAKE_PREFIX_PATH="$PWD/.deps/wolfssl-5.9.4"
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

The script downloads upstream `v5.9.4-stable`, verifies its pinned SHA-256 checksum, and builds a shared library with the required features. The tag resolves to commit `3c5eead44904df64e6a5a1f4ebdce377d35a849a`; both the version and archive checksum must be reviewed when updating. `.deps/` is ignored by Git. The application build does not download dependencies automatically, and the tests themselves require no internet access.

After changing the required wolfSSL build features, rerun the installation script for the same prefix, then configure and rebuild the application. Rebuilding only `tls-inspector` does not change the external library's feature set.

To build only the application, add `-DBUILD_TESTING=OFF`. For a nonstandard wolfSSL installation, pass `-DCMAKE_PREFIX_PATH=/path/to/prefix`, or set `WOLFSSL_INCLUDE_DIR` and `WOLFSSL_LIBRARY` explicitly. If an existing build cache points at an older installation, configure a fresh build directory or clear the cached paths with `cmake -U 'WOLFSSL_*' -S . -B build -DCMAKE_PREFIX_PATH=/path/to/prefix`. CMake includes the library's generated `wolfssl/options.h`, checks required features with a compile/link probe, and runs a version probe to confirm the loaded library matches the headers. This configuration step requires a native runnable build, not cross-compilation. Install with `cmake --install build --prefix /your/prefix` if desired.

In the development sandbox, the updated wolfSSL library was installed under the ignored project-local `.deps/` directory. Only CMake itself required separately extracted Ubuntu packages because administrator access was unavailable. A prefix-based application build uses CMake's build RPATH to find wolfSSL; if moving or installing the executable, arrange for the runtime loader to find the matching library (for example via a system installation or `LD_LIBRARY_PATH=/path/to/prefix/lib`). The library is not embedded into the executable.

## Usage Examples

```bash
./build/tls-inspector example.com
./build/tls-inspector example.com --port 8443
./build/tls-inspector example.com --tls 1.2
./build/tls-inspector example.com --ca-file ./ca.pem
./build/tls-inspector example.com --json
./build/tls-inspector example.com --all-sans
./build/tls-inspector example.com --timeout 5
./build/tls-inspector --help
```

The default port is 443 and the default timeout is 5 seconds. Timeouts are integral seconds in 1..3600. The host must be an ASCII DNS hostname; supply internationalized domain names as A-labels. A trailing DNS dot is normalized away. IP literal identity verification is not supported; DNS names may resolve to IPv4 or IPv6 addresses. Options may precede the hostname. Repeated valued options use the last value.

Text reports show the first 10 SAN entries by default, followed by the omitted count and a hint when more entries exist. Use `--all-sans` to display the full list. JSON always includes every SAN entry. This only limits presentation; certificate parsing and hostname verification still use the full certificate.

The default CA bundle is `/etc/ssl/certs/ca-certificates.crt`. `--ca-file` replaces it with the specified PEM trust anchors; it does not add to the system trust. A missing/unreadable CA file is fatal. No insecure mode exists.

| Exit code | Meaning |
| --- | --- |
| 0 | Verified TLS session, or help |
| 2 | Invalid arguments |
| 3 | Certificate or hostname validation failed |
| 4 | DNS/TCP failure, TLS failure, or CA configuration failure |
| 5 | Timeout |
| 6 | Other application failure |

`--json` writes one valid JSON object to stdout and diagnostics to stderr. `--help --json` also produces JSON. Failed sessions have `overall: "FAIL"`, unavailable certificate fields, and an `error` object with category, message, and the native wolfSSL error code when available. Text output escapes control bytes to prevent terminal control sequences. JSON escapes control and non-ASCII bytes; non-ASCII certificate text is represented byte-by-byte using `\u00XX`, rather than interpreted as Unicode. SAN strings include their type (`DNS:`, `IP:`, `EMAIL:`, `URI:`).

## Code Formatting

C++ sources and headers use clang-format 18 with the repository's `.clang-format` configuration, adapted from wolfSSL's public implementation: 4-space indentation, an 80-column target, opening function braces on the next line, control-statement braces on the same line, indented switch labels, and one blank line between function definitions. Blank lines also separate `#pragma once`, include groups (project/system/wolfSSL), the include section from the code, type definitions, and other logical blocks. No extra blank lines are placed immediately inside namespace braces. Include order is preserved, including wolfSSL configuration headers before dependent headers. The reference is wolfSSL commit `5f9ab72a4775c4a7ab1a927455178e846f003dc4`: [CONTRIBUTING.md](https://github.com/wolfSSL/wolfssl/blob/5f9ab72a4775c4a7ab1a927455178e846f003dc4/CONTRIBUTING.md), [.editorconfig](https://github.com/wolfSSL/wolfssl/blob/5f9ab72a4775c4a7ab1a927455178e846f003dc4/.editorconfig), and [src/tls.c](https://github.com/wolfSSL/wolfssl/blob/5f9ab72a4775c4a7ab1a927455178e846f003dc4/src/tls.c). This is a local approximation of that style, not an upstream clang-format configuration. C++17 ownership, declaration placement and C++ comments are retained. The formatter is a development tool, not a build dependency. CI checks formatting with the same major version.

```bash
sudo apt-get install -y clang-format-18
clang-format-18 -i include/*.hpp src/*.cpp tests/*.cpp
clang-format-18 --dry-run --Werror include/*.hpp src/*.cpp tests/*.cpp
```

## Architecture

See the [repository structure guide](diagrams/repository-structure.md) (Japanese) for the file layout, folder responsibilities, and locally generated files.

See the [class diagram](diagrams/class-diagram.md) for the main types and their dependencies, including instructions for rendering it.

See the [sequence diagrams](diagrams/sequence-diagram.md) for successful inspection and error handling, including connection setup, certificate verification, output, and resource cleanup.

| Component | Responsibility |
| --- | --- |
| `main.cpp` | Process I/O, exit status, exception boundary, SIGPIPE handling |
| `certificate_inspector.cpp` | CLI validation and orchestration |
| `TcpConnection` | Deadline-bound DNS resolution and nonblocking TCP, socket ownership |
| `TlsClient` | wolfSSL context/session ownership, exact protocol, SNI, hostname verification and handshake |
| `CertificateInfo` | Certificate data; extraction via wolfSSL APIs |
| `ResultFormatter` functions | Text/JSON serialization without another dependency |

Sockets and resolver descriptors use RAII. wolfSSL contexts, sessions, peer certificates, SAN collections, and public keys use `std::unique_ptr` with matching library deleters. Socket ownership is move-only. Declaration order ensures TLS resources are freed before `wolfSSL_Cleanup` and the TCP socket is released on all paths.

Linux `getaddrinfo()` is synchronous and has no portable per-call timeout. This single-threaded CLI runs it in a short-lived forked child, sends up to 16 IPv4/IPv6 addresses over a pipe, and polls that pipe against the same monotonic deadline used by TCP/TLS. The parent terminates and reaps the child on every return path. TCP sockets stay nonblocking; `poll` and `SO_ERROR` complete connections, while wolfSSL `WANT_READ`/`WANT_WRITE` drive the handshake. This avoids detached resolver threads that could outlive the request. The implementation is intended for this single-threaded process, not for embedding into a multithreaded application that calls `fork()` after initializing other libraries.

## TLS Certificate Verification

TLS authenticates the peer and establishes encrypted communication. X.509 certificates bind public keys to identities. The server presents a leaf and usually intermediate certificates; locally trusted CA public keys are the trust anchors. A server-supplied root is not trusted just because it was sent.

With `WOLFSSL_VERIFY_PEER`, wolfSSL verifies signatures and its certificate-chain constraints against the configured trust anchors and checks certificate dates using the system clock. The application sets `wolfSSL_check_domain_name()` before the handshake to require that the presented identity matches the requested hostname according to wolfSSL's matching rules. SNI (`wolfSSL_UseSNI`) separately tells the server which virtual host is requested; sending SNI alone authenticates nothing. No verification callback overrides errors, and failed handshakes never produce a successful-session report. The tool opens no application-data exchange.

The library must enable `WOLFSSL_ALT_CERT_CHAINS` so wolfSSL can validate a path to a locally trusted CA even if the server also presents cross-signed certificates leading toward another root that is not locally trusted. For example, a server may send root A cross-signed by root B while the trust file already contains self-signed root A. A valid path to trusted A is sufficient; the extra path toward B is not required. Signatures, constraints, dates and hostname verification remain enabled. This uses wolfSSL's official chain-validation mechanism and does not trust arbitrary server-supplied roots. See the [wolfSSL build-option documentation](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html).

Version-specific methods (`wolfTLSv1_3_client_method` / `wolfTLSv1_2_client_method`) select exactly the requested protocol. The negotiated version is also checked before reporting success. Both cross-version failure directions are tested.

wolfSSL reports success/failure for combined chain, validity, and trust verification, rather than three independently observed success results. The report therefore uses:

| Field | Interpretation |
| --- | --- |
| `wolfssl_combined` | PASS only after a verified handshake; FAIL for a reported chain/date/trust failure; otherwise NOT_CHECKED |
| `hostname` | PASS after a verified handshake with hostname checking enabled; FAIL on explicit hostname mismatch; otherwise NOT_CHECKED |
| `chain`, `validity_period`, `trust_anchor` | NOT_CHECKED means no separate result is available; a directly classified failure sets the relevant field to FAIL |
| `overall` | PASS only after a verified handshake, requested version check, and peer certificate retrieval |

Here `NOT_CHECKED` on individual fields means **not independently reported**, even when those checks are included in a combined PASS. No independent PASS is invented. On failure, other checks may not have run, and the first error is not an exhaustive diagnosis. For example, `ASN_NO_SIGNER_E` cannot distinguish a missing intermediate from an unknown root, so it is classified as `INVALID_CERTIFICATE_CHAIN`, rather than asserting `UNTRUSTED_CA`. Explicit self-signed errors can be classified as untrusted CA; expiry, future dates and hostname mismatch use their native wolfSSL errors. Other handshake errors remain `TLS_ERROR`, with the native code retained.

An overall PASS is meaningful only with the intended trust anchors, correct hostname and system time, matching headers/library configuration, and a trusted, maintained wolfSSL installation. Loading an attacker-controlled CA file changes who is trusted. A PASS does not prove that the server or its application is benign.

API behavior and ownership were initially checked against the 5.6.6 headers and source, and revalidated with the 5.9.4 headers, implementation and offline tests during the security update:

- [wolfSSL verification and domain checks](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter07.html)
- [wolfSSL setup API](https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html)
- [wolfSSL certificate APIs](https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html)
- [5.6.6 ssl.c: methods, hostname checking, peer-certificate ownership](https://github.com/wolfSSL/wolfssl/blob/v5.6.6-stable/src/ssl.c)
- [5.6.6 x509.c: SAN decoding, names, public keys, certificate metadata](https://github.com/wolfSSL/wolfssl/blob/v5.6.6-stable/src/x509.c)
- [5.6.6 internal.c: verification and hostname matching](https://github.com/wolfSSL/wolfssl/blob/v5.6.6-stable/src/internal.c)
- [5.9.4 source and headers](https://github.com/wolfSSL/wolfssl/tree/v5.9.4-stable)

## Security Considerations

There is no verification bypass, protocol downgrade fallback, custom cryptography, custom chain builder, or custom ASN.1 parser. Certificate metadata extraction does not replace verification. The SHA-256 fingerprint identifies the leaf's DER encoding; it is not a separate trust decision. Missing optional metadata is `N/A` (unknown key sizes are JSON `null`). Unsupported public-key types are left unknown instead of relying on the older EVP adapter's assumption that unknown types are EC.

All keys generated by tests are disposable and remain in temporary directories that are removed after tests. `.gitignore` excludes private keys and build outputs. No production credentials are included. CA files and the local clock are security inputs. Connect only to endpoints you are authorized to inspect.

## License

The original source code, build and test scripts, configuration files, and documentation in this project are licensed under the **GNU General Public License, version 3 only** (`GPL-3.0-only`). You may use, modify, and redistribute them under those terms. See [LICENSE](LICENSE) for the complete license, including its warranty disclaimer. Source files carry SPDX license identifiers.

wolfSSL is an external dependency and retains its own copyright notices and license terms; this project's license does not relicense wolfSSL. The tested upstream release, **5.9.4**, is used under GPLv3; see its [COPYING](https://github.com/wolfSSL/wolfssl/blob/v5.9.4-stable/COPYING) and [LICENSING](https://github.com/wolfSSL/wolfssl/blob/v5.9.4-stable/LICENSING). The installation script preserves both files under the installation prefix's `share/doc/wolfssl/` directory. Check the actual license and any exceptions of each wolfSSL release or distribution used, including when upgrading or using a commercial license; API compatibility alone does not establish license compatibility.

When distributing binaries under the GPL, provide the corresponding source and build instructions as required by the license, including source for dependencies where required, and preserve applicable copyright and license notices. Publishing this application's source alone is not a blanket assurance that every binary distribution meets those requirements.

## Testing

CTest runs two C++ unit-test executables and a Python integration suite. No external websites or DNS services are required. The suite covers:

- Argument defaults/custom values, invalid ports/options/versions/hostnames, help, and exit codes.
- JSON escaping, unavailable data, error mapping, text formatting, and terminal control escaping.
- A deliberately blocked `getaddrinfo` via a test-only linker wrapper: the deadline fires and the resolver child is reaped.
- RSA and EC leaves and complete intermediate chains under TLS 1.2 and 1.3; SNI, negotiated version, SAN, dates, key sizes, serials and independently computed SHA-256 fingerprints.
- Cross-signed chains under both protocols: a path to the locally trusted root succeeds, while an unrelated trust anchor still fails. This reproduces the alternate-path issue locally without depending on a public website.
- Expired, future-dated, mismatched, wrong-CA, self-signed and missing-intermediate certificates, under both protocols.
- Explicitly trusting a self-signed test leaf succeeds; absent that trust it fails.
- Both protocol mismatch directions, missing/malformed CA files, closed TCP port, plaintext server and stalled TLS handshake.
- IPv6 loopback where available (a clear skip is printed if unsupported).

Recreate fixtures manually if needed:

```bash
python3 tests/fixtures/generate.py tests/fixtures/generated
```

Certificates are regenerated relative to the current clock with random test-only keys. Their semantics are reproducible; their exact bytes intentionally differ. Integration tests use fresh temporary directories and dynamically allocated loopback ports.

Run AddressSanitizer and UBSan:

```bash
cmake -S . -B build-sanitize -DCMAKE_PREFIX_PATH="$PWD/.deps/wolfssl-5.9.4" \
  -DENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-sanitize --parallel 2
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
ctest --test-dir build-sanitize --output-on-failure
```

The sanitizer option instruments application and C++ test code and uses non-PIE test binaries for predictable ASan shadow mappings on Linux. The installed wolfSSL shared library and Python runtime are not rebuilt with sanitizers. A GitHub Actions workflow runs normal and sanitizer configurations on Ubuntu 24.04.

## Limitations

- DNS names only for identity verification; IP literal and Unicode hostname input are rejected. Both socket address families remain supported.
- No OCSP/CRL revocation checking, Certificate Transparency policy, AIA intermediate fetching, certificate pinning, or full chain display. A PASS does not assert these checks.
- Verification and identity matching follow the linked wolfSSL build's policies, including any legacy CN fallback and supported algorithms. This tool is not a complete browser/Web PKI policy engine.
- Only the leaf is displayed after a successful handshake. Failed peers' untrusted certificate metadata is not displayed.
- RSA and EC public-key metadata are supported; other key algorithms return N/A/null. Unknown SAN types are marked N/A. No custom decoder is used.
- One shared network deadline and sequential address attempts; no Happy Eyeballs racing. A stalled first address can consume the budget. DNS results are capped at 16 addresses.
- The deadline bounds waiting in DNS/TCP/TLS; filesystem access when loading CAs, local CPU work, process scheduling and resolver cleanup are not hard real-time guarantees.
- Linux-specific `fork`, `pipe2`, socket flags and GNU linker test wrapping; no Windows/macOS portability claim.
- Distinct chain/date/trust success statuses and exhaustive failure reasons are unavailable. JSON's `NOT_CHECKED` semantics are documented above.
