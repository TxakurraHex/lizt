#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# get-expat.sh
#
# Downloads expat 2.2.9 (vulnerable to CVE-2022-25235, CVE-2022-25236,
# CVE-2022-25313, etc.) and installs it to /opt/vulnerable.
#
# Usage:
#   sudo bash get-expat.sh
#
# What this produces:
#   /opt/vulnerable/lib/libexpat.so.1.6.9   ← the shared library
#   /opt/vulnerable/lib/libexpat.so.1       ← symlink
#   /opt/vulnerable/lib/libexpat.so         ← symlink
#   /opt/vulnerable/include/expat.h         ← header
#
# Key symbols exported by this build:
#   XML_Parse, XML_ParserCreate, XML_SetElementHandler, storeRawNames, etc.
#
# Verify with:
#   nm -D /opt/vulnerable/lib/libexpat.so.1 | grep -E "XML_"
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

EXPAT_VERSION="2.2.9"
EXPAT_TAG="R_2_2_9"
EXPAT_SHA256="4456e0aa72ecc7e1d4b3368cd545a5eec7f9de5133a8dc37fdb1efa6174c4947"
PREFIX="/opt/vulnerable"
BUILD_DIR="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

echo "── Installing build dependencies ──────────────────────────────"
apt-get update -qq
apt-get install -y -qq --no-install-recommends build-essential wget ca-certificates

echo "── Downloading expat ${EXPAT_VERSION} ─────────────────────────"
cd "$BUILD_DIR"
wget -q "https://github.com/libexpat/libexpat/releases/download/${EXPAT_TAG}/expat-${EXPAT_VERSION}.tar.gz" \
	-O "expat-${EXPAT_VERSION}.tar.gz"

echo "── Verifying checksum ─────────────────────────────────────────"
echo "${EXPAT_SHA256}  expat-${EXPAT_VERSION}.tar.gz" | sha256sum -c -

echo "── Extracting ─────────────────────────────────────────────────"
tar xzf "expat-${EXPAT_VERSION}.tar.gz"
cd "expat-${EXPAT_VERSION}"

echo "── Configuring (prefix=${PREFIX}) ─────────────────────────────"
CFLAGS="-O2 -g -fPIC" ./configure --prefix="$PREFIX"

echo "── Building ───────────────────────────────────────────────────"
make -j"$(nproc)"

echo "── Installing to ${PREFIX} ────────────────────────────────────"
mkdir -p "$PREFIX"
make install

echo "── Verifying installation ─────────────────────────────────────"
echo ""
echo "Shared library:"
ls -la "$PREFIX/lib/"libexpat.so*
echo ""
echo "Key exported symbols:"
nm -D --defined-only "$PREFIX/lib/libexpat.so.1" | grep -E " T (XML_Parse|XML_ParserCreate|XML_SetElementHandler|XML_GetBuffer)$" || true
echo ""
echo "Symbol count:"
nm -D --defined-only "$PREFIX/lib/libexpat.so.1" | wc -l
echo ""
echo "── Done ───────────────────────────────────────────────────────"
echo "Vulnerable expat ${EXPAT_VERSION} installed to ${PREFIX}"