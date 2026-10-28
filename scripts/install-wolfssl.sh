#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only

set -euo pipefail

if [[ $# != 1 || "$1" != /* ]]; then
    echo "Usage: $0 /absolute/installation/prefix" >&2
    exit 2
fi

prefix="$1"
cmake_bin="${CMAKE_COMMAND:-cmake}"
version="5.9.4"
# v5.9.4-stable resolves to commit 3c5eead44904df64e6a5a1f4ebdce377d35a849a.
# Verify the exact archive bytes; a changed upstream tag/archive fails closed.
archive_sha256="7256bfc89b183a75183806c7debfa203443873b0b4a562e1b80d68e01b45ac57"
archive_url="https://codeload.github.com/wolfSSL/wolfssl/tar.gz/refs/tags/v${version}-stable"

for dependency in curl sha256sum tar "$cmake_bin"; do
    command -v "$dependency" >/dev/null || {
        echo "Required tool not found: $dependency" >&2
        exit 1
    }
done

workdir="$(mktemp -d "${TMPDIR:-/tmp}/tls-inspector-wolfssl.XXXXXXXX")"
trap 'rm -rf -- "$workdir"' EXIT
curl --fail --location --silent --show-error --retry 3 \
    "$archive_url" --output "$workdir/source.tar.gz"
printf '%s  %s\n' "$archive_sha256" "$workdir/source.tar.gz" | sha256sum --check
mkdir "$workdir/source"
tar -xzf "$workdir/source.tar.gz" -C "$workdir/source" --strip-components=1

"$cmake_bin" -S "$workdir/source" -B "$workdir/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DBUILD_SHARED_LIBS=ON \
    -DWOLFSSL_OPENSSLEXTRA=yes \
    -DWOLFSSL_TLS13=yes \
    -DWOLFSSL_SNI=yes \
    -DWOLFSSL_EXAMPLES=no \
    -DWOLFSSL_CRYPT_TESTS=no
"$cmake_bin" --build "$workdir/build" --parallel 2
"$cmake_bin" --install "$workdir/build"
install -d "$prefix/share/doc/wolfssl"
install -m 644 "$workdir/source/COPYING" "$workdir/source/LICENSING" \
    "$prefix/share/doc/wolfssl/"
