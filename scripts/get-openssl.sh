#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# get-openssl.sh
#
# Downloads OpenSSL 1.1.1f (vulnerable to CVE-2021-3449, CVE-2021-3450,
# CVE-2022-0778, etc.) and installs it to /opt/vulnerable.
#
# Usage:
#   sudo bash get-openssl.sh
#
# What this produces:
#   /opt/vulnerable/lib/libssl.so.1.1       ← SSL shared library
#   /opt/vulnerable/lib/libcrypto.so.1.1    ← crypto shared library
#   /opt/vulnerable/ssl/                    ← openssl config dir
#   /opt/vulnerable/include/openssl/        ← headers
#
# Key symbols exported by this build:
#   SSL_read, SSL_write, SSL_connect, EVP_EncryptInit, BN_mod_sqrt, etc.
#
# Verify with:
#   nm -D /opt/vulnerable/lib/libssl.so.1.1 | grep -E "SSL_"
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

OPENSSL_VERSION="1.1.1f"
OPENSSL_SHA256="186c6bfe6ecfba7a5b48c47f8a1673d0f3b0e5ba2e25602dd23b629975da3f35"
PREFIX="/opt/vulnerable"
BUILD_DIR="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

echo "── Installing build dependencies ──────────────────────────────"
apt-get update -qq
apt-get install -y -qq --no-install-recommends build-essential wget ca-certificates

echo "── Downloading OpenSSL ${OPENSSL_VERSION} ─────────────────────"
cd "$BUILD_DIR"
wget -q "https://www.openssl.org/source/old/1.1.1/openssl-${OPENSSL_VERSION}.tar.gz" \
	-O "openssl-${OPENSSL_VERSION}.tar.gz"

echo "── Verifying checksum ─────────────────────────────────────────"
echo "${OPENSSL_SHA256}  openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c -

echo "── Extracting ─────────────────────────────────────────────────"
tar xzf "openssl-${OPENSSL_VERSION}.tar.gz"
cd "openssl-${OPENSSL_VERSION}"

echo "── Configuring (prefix=${PREFIX}) ─────────────────────────────"
# shared: build .so files so uprobes can attach
# -g: keep debug symbols for symbol resolution
./config --prefix="$PREFIX" \
         --openssldir="$PREFIX/ssl" \
         -g \
         shared

echo "── Building ───────────────────────────────────────────────────"
make -j"$(nproc)"

echo "── Installing to ${PREFIX} ────────────────────────────────────"
mkdir -p "$PREFIX"
make install

echo "── Verifying installation ─────────────────────────────────────"
echo ""
echo "Shared libraries:"
ls -la "$PREFIX/lib/"libssl.so* "$PREFIX/lib/"libcrypto.so*
echo ""
echo "Key exported symbols (libssl):"
nm -D --defined-only "$PREFIX/lib/libssl.so.1.1" | grep -E " T (SSL_read|SSL_write|SSL_connect|SSL_do_handshake)$" || true
echo ""
echo "Key exported symbols (libcrypto):"
nm -D --defined-only "$PREFIX/lib/libcrypto.so.1.1" | grep -E " T (EVP_EncryptInit|BN_mod_sqrt|X509_verify)$" || true
echo ""
echo "Symbol count (libssl):"
nm -D --defined-only "$PREFIX/lib/libssl.so.1.1" | wc -l
echo "Symbol count (libcrypto):"
nm -D --defined-only "$PREFIX/lib/libcrypto.so.1.1" | wc -l
echo ""
echo "── Done ───────────────────────────────────────────────────────"
echo "Vulnerable OpenSSL ${OPENSSL_VERSION} installed to ${PREFIX}"