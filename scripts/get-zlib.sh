#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# install_vulnerable_zlib.sh
#
# Downloads zlib 1.2.11 (vulnerable to CVE-2022-37434) and installs it
# to /opt/vulnerable so the Lizt eval fixtures can resolve symbols
# against it without interfering with the system's patched copy.
#
# Usage:
#   sudo bash install_vulnerable_zlib.sh
#
# What this produces:
#   /opt/vulnerable/lib/libz.so.1.2.11   ← the shared library
#   /opt/vulnerable/lib/libz.so.1        ← symlink
#   /opt/vulnerable/lib/libz.so          ← symlink
#   /opt/vulnerable/include/zlib.h       ← header (for reference)
#   /opt/vulnerable/include/zconf.h
#
# Key symbols exported by this build:
#   inflate, inflateGetHeader, inflateInit2_, deflate, compress, etc.
#
# Verify with:
#   nm -D /opt/vulnerable/lib/libz.so.1 | grep -E "inflate|deflate"
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

ZLIB_VERSION="1.2.11"
ZLIB_SHA256="c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1"
PREFIX="/opt/vulnerable"
BUILD_DIR="$(mktemp -d)"

cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

echo "── Installing build dependencies ──────────────────────────────"
apt-get update -qq
apt-get install -y -qq --no-install-recommends build-essential wget ca-certificates

echo "── Downloading zlib ${ZLIB_VERSION} ───────────────────────────"
cd "$BUILD_DIR"
wget -q "https://zlib.net/fossils/zlib-${ZLIB_VERSION}.tar.gz" \
	-O "zlib-${ZLIB_VERSION}.tar.gz"

echo "── Verifying checksum ─────────────────────────────────────────"
echo "${ZLIB_SHA256}  zlib-${ZLIB_VERSION}.tar.gz" | sha256sum -c -

echo "── Extracting ─────────────────────────────────────────────────"
tar xzf "zlib-${ZLIB_VERSION}.tar.gz"
cd "zlib-${ZLIB_VERSION}"

echo "── Configuring (prefix=${PREFIX}) ─────────────────────────────"
# Build position-independent shared library.
# CFLAGS: -g keeps debug symbols so `nm` (without -D) can resolve
# internal/static functions like storeRawNames in other libraries
# built the same way. For zlib specifically, all interesting symbols
# are already exported, but -g is good practice for eval builds.
CFLAGS="-O2 -g -fPIC" ./configure --prefix="$PREFIX"

echo "── Building ───────────────────────────────────────────────────"
make -j"$(nproc)"

echo "── Installing to ${PREFIX} ────────────────────────────────────"
mkdir -p "$PREFIX"
make install

echo "── Verifying installation ─────────────────────────────────────"
echo ""
echo "Shared library:"
ls -la "$PREFIX/lib/"libz.so*
echo ""
echo "Key exported symbols:"
nm -D --defined-only "$PREFIX/lib/libz.so.1" | grep -E " T (inflate|inflateGetHeader|deflate|compress|uncompress)$" || true
echo ""
echo "Symbol count:"
nm -D --defined-only "$PREFIX/lib/libz.so.1" | wc -l
echo ""
echo "── Done ───────────────────────────────────────────────────────"
echo "Vulnerable zlib ${ZLIB_VERSION} installed to ${PREFIX}"
echo ""
echo "Next steps:"
echo "  1. Add 'zlib' to static_library_files() in resolved_symbol.rs"
echo "  2. Add the zlib fixture to io/inventory/src/fixtures.rs"
echo "  3. Add 'zlib' to the eval CLI match arm in pipeline/src/lib.rs"
echo "  4. Run: cargo run -p cli -- eval --fixture zlib"
