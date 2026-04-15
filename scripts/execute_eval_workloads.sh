#!/usr/bin/env bash
# ─
# eval_workload.sh — Lizt evaluation workload runner
#
# Compiles and runs three small C programs that exercise the specific
# vulnerable functions for each target CVE. Each program links against
# the source-compiled libraries in /opt/vulnerable/.
#
# The purpose is NOT to trigger the vulnerability — it's to call the
# function normally so Lizt's eBPF uprobe fires and records the call.
#
# Prerequisites:
#   - Libraries built in /opt/vulnerable/ (see scripts/get-*.sh)
#   - build-essential installed (gcc, make)
#
# Usage:
#   sudo bash eval_workload.sh          # build + run all three
#   sudo bash eval_workload.sh build    # build only
#   sudo bash eval_workload.sh run      # run only (assumes already built)
# ─
set -euo pipefail

VULN_PREFIX="/opt/vulnerable"
WORKLOAD_DIR="/opt/vulnerable/eval_workloads"
ACTION="${1:-all}"

mkdir -p "$WORKLOAD_DIR"

#  Build ─

build_workloads() {
	echo " Compiling workloads "

	# zlib
	gcc -o "$WORKLOAD_DIR/workload_zlib" \
		"$WORKLOAD_DIR/workload_zlib.c" \
		-I"$VULN_PREFIX/include" \
		-L"$VULN_PREFIX/lib" \
		-lz \
		-Wl,-rpath,"$VULN_PREFIX/lib"
	echo "  Built: workload_zlib"

	# OpenSSL
	gcc -o "$WORKLOAD_DIR/workload_openssl" \
		"$WORKLOAD_DIR/workload_openssl.c" \
		-I"$VULN_PREFIX/include" \
		-L"$VULN_PREFIX/lib" \
		-lssl -lcrypto \
		-Wl,-rpath,"$VULN_PREFIX/lib" \
		-lpthread -ldl
	echo "  Built: workload_openssl"

	# libexpat
	gcc -o "$WORKLOAD_DIR/workload_expat" \
		"$WORKLOAD_DIR/workload_expat.c" \
		-I"$VULN_PREFIX/include" \
		-L"$VULN_PREFIX/lib" \
		-lexpat \
		-Wl,-rpath,"$VULN_PREFIX/lib"
	echo "  Built: workload_expat"

	echo ""
	echo " Verifying linkage "
	for bin in workload_zlib workload_openssl workload_expat; do
		echo "  $bin:"
		ldd "$WORKLOAD_DIR/$bin" | grep "$VULN_PREFIX" || echo "    WARNING: not linked to $VULN_PREFIX"
	done
}

#  Run ─

run_workloads() {
	echo ""
	echo "============================================================"
	echo "  Running eval workloads"
	echo "  Lizt's eBPF monitor should be running to capture probes"
	echo "============================================================"
	echo ""

	for bin in workload_zlib workload_openssl workload_expat; do
		echo " $bin "
		"$WORKLOAD_DIR/$bin"
		echo ""
	done

	echo "============================================================"
	echo "  All workloads complete."
	echo "  Check the Lizt dashboard — symbol_called should now be"
	echo "  true for the probed functions."
	echo "============================================================"
}

#  Main

case "$ACTION" in
build)
	build_workloads
	;;
run)
	run_workloads
	;;
all | *)
	build_workloads
	run_workloads
	;;
esac
