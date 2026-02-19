#!/usr/bin/env python3
"""
CVE Pipeline - Main Orchestrator
Maps system inventory to CPEs and fetches associated CVEs.

Usage:
    python pipeline.py [--api-key KEY] [--output results.json] [--min-score 7.0]
                       [--include-hardware] [--include-modules] [--include-pip]
                       [--dry-run] [--limit N]
"""

import argparse
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path

from inventory import collect_inventory, InventoryItem
from nvd_client import NVDClient, CpeMatch, CveResult


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

# Items that commonly produce too many false positives or noise
SKIP_PRODUCTS = {
    # Very generic package names unlikely to map to interesting CVEs
    "base-files", "base-passwd", "debianutils", "sensible-utils",
    "adduser", "login", "passwd",
}

# Well-known vendor normalizations (product_name -> (vendor, product))
KNOWN_MAPPINGS = {
    "openssl":      ("openssl", "openssl"),
    "openssh":      ("openbsd", "openssh"),
    "openssh-server": ("openbsd", "openssh"),
    "openssh-client": ("openbsd", "openssh"),
    "curl":         ("haxx", "curl"),
    "libcurl":      ("haxx", "curl"),
    "nginx":        ("nginx", "nginx"),
    "apache2":      ("apache", "http_server"),
    "httpd":        ("apache", "http_server"),
    "postgresql":   ("postgresql", "postgresql"),
    "mysql":        ("mysql", "mysql"),
    "sqlite3":      ("sqlite", "sqlite"),
    "libsqlite3":   ("sqlite", "sqlite"),
    "python3":      ("python", "python"),
    "python":       ("python", "python"),
    "pip":          ("pypa", "pip"),
    "git":          ("git-scm", "git"),
    "bash":         ("gnu", "bash"),
    "vim":          ("vim", "vim"),
    "zsh":          ("zsh", "zsh"),
    "sudo":         ("sudo_project", "sudo"),
    "glibc":        ("gnu", "glibc"),
    "libc6":        ("gnu", "glibc"),
    "linux-image":  ("linux", "linux_kernel"),
    "rsync":        ("samba", "rsync"),
    "tar":          ("gnu", "tar"),
    "wget":         ("gnu", "wget"),
    "zip":          ("info-zip", "zip"),
    "unzip":        ("info-zip", "unzip"),
    "expat":        ("libexpat_project", "libexpat"),
    "libexpat1":    ("libexpat_project", "libexpat"),
    "zlib":         ("zlib", "zlib"),
    "zlib1g":       ("zlib", "zlib"),
    "libssl":       ("openssl", "openssl"),
    "libpng":       ("libpng", "libpng"),
    "libtiff":      ("libtiff", "libtiff"),
    "libjpeg":      ("ijg", "libjpeg"),
    "libxml2":      ("xmlsoft", "libxml2"),
    "libxslt":      ("xmlsoft", "libxslt"),
    "dbus":         ("freedesktop", "dbus"),
    "systemd":      ("systemd_project", "systemd"),
    "perl":         ("perl", "perl"),
    "ruby":         ("ruby-lang", "ruby"),
    "nodejs":       ("nodejs", "node.js"),
    "node":         ("nodejs", "node.js"),
    "npm":          ("npmjs", "npm"),
    "java":         ("oracle", "jdk"),
    "openjdk":      ("openjdk", "openjdk"),
    "php":          ("php", "php"),
    "ffmpeg":       ("ffmpeg", "ffmpeg"),
    "imagemagick":  ("imagemagick", "imagemagick"),
}


def normalize_inventory_item(item: InventoryItem) -> InventoryItem:
    """Apply known vendor/product mappings and clean up item."""
    product_lower = item.product.lower().replace("-", "_")

    # Check known mappings
    for key, (vendor, product) in KNOWN_MAPPINGS.items():
        if product_lower == key.replace("-", "_") or product_lower.startswith(key.replace("-", "_") + "_"):
            item.vendor = vendor
            item.product = product
            item.cpe_guess = item.to_cpe_string()
            return item

    # Clean up version strings
    if item.version:
        # Remove common suffixes like +b1, .dfsg, -ubuntu, etc.
        import re
        item.version = re.sub(r'[+~].*$', '', item.version)
        item.version = re.sub(r'-\d+$', '', item.version)

    item.cpe_guess = item.to_cpe_string()
    return item


def build_cpe_search_string(item: InventoryItem) -> str:
    """Build a CPE match string for searching (partial, version-agnostic)."""
    v = item.vendor.lower().replace(" ", "_").replace("-", "_") if item.vendor else "*"
    p = item.product.lower().replace(" ", "_").replace("-", "_")
    return f"cpe:2.3:{item.part}:{v}:{p}:"


def run_pipeline(
    api_key: str = None,
    output_file: str = "cve_results.json",
    min_score: float = 0.0,
    include_hardware: bool = False,
    include_modules: bool = False,
    include_pip: bool = True,
    dry_run: bool = False,
    limit: int = None,
    skip_cve_lookup: bool = False,
    sources_filter: list = None,
):
    print("=" * 60)
    print("  CVE Pipeline")
    print("=" * 60)

    # Step 1: Collect inventory
    inventory = collect_inventory(
        include_packages=True,
        include_kernel_modules=include_modules,
        include_hardware=include_hardware,
        include_pip=include_pip,
        include_brew=True,
        include_driver_versions=False,
    )

    # Filter by source if requested
    if sources_filter:
        inventory = [i for i in inventory if i.source in sources_filter]

    # Normalize
    inventory = [normalize_inventory_item(i) for i in inventory]

    # Skip noise
    inventory = [i for i in inventory if i.product not in SKIP_PRODUCTS]

    # Apply limit
    if limit:
        inventory = inventory[:limit]

    print(f"\n[+] Processing {len(inventory)} items after filtering\n")

    if dry_run:
        print("[DRY RUN] Inventory (no CVE lookup):")
        for item in inventory:
            print(f"  {item.source:12s} | {item.product:30s} | {item.version:20s} | {item.cpe_guess}")
        return

    if skip_cve_lookup:
        out = [asdict(i) for i in inventory]
        Path(output_file).write_text(json.dumps(out, indent=2))
        print(f"[+] Inventory written to {output_file}")
        return

    # Step 2: Query NVD
    client = NVDClient(api_key=api_key)
    results = []
    total = len(inventory)

    for idx, item in enumerate(inventory):
        print(f"[{idx+1}/{total}] {item.product} {item.version} ({item.source})")

        # Try to find matching CPE(s)
        search_str = build_cpe_search_string(item)
        matched_cpes = client.search_cpe_by_name(search_str, limit=3)

        if not matched_cpes:
            # Fallback: keyword search
            matched_cpes = client.search_cpe(item.product, limit=3)

        if not matched_cpes:
            print(f"  [-] No CPE found")
            results.append({
                "item": asdict(item),
                "matched_cpes": [],
                "cves": [],
                "status": "no_cpe_found",
            })
            continue

        # Filter to non-deprecated
        active_cpes = [c for c in matched_cpes if not c.deprecated] or matched_cpes
        best_cpe = active_cpes[0]
        print(f"  [~] CPE: {best_cpe.cpe_name} ({best_cpe.title})")

        # Step 3: Fetch CVEs for this CPE
        cves = client.get_cves_for_cpe(best_cpe.cpe_name, limit=20)

        # Filter by minimum score
        cves = [c for c in cves if c.cvss_score >= min_score]

        if cves:
            sev_counts = {}
            for c in cves:
                sev_counts[c.severity] = sev_counts.get(c.severity, 0) + 1
            print(f"  [!] {len(cves)} CVEs found: {sev_counts}")
        else:
            print(f"  [✓] No CVEs above score threshold")

        results.append({
            "item": asdict(item),
            "matched_cpes": [{"cpe_name": c.cpe_name, "title": c.title} for c in active_cpes],
            "cves": [asdict(c) for c in cves],
            "status": "ok",
        })

    # Step 4: Write results
    summary = {
        "total_items": total,
        "items_with_cves": sum(1 for r in results if r["cves"]),
        "total_cves": sum(len(r["cves"]) for r in results),
        "critical": sum(1 for r in results for c in r["cves"] if c["severity"] == "CRITICAL"),
        "high": sum(1 for r in results for c in r["cves"] if c["severity"] == "HIGH"),
        "medium": sum(1 for r in results for c in r["cves"] if c["severity"] == "MEDIUM"),
        "low": sum(1 for r in results for c in r["cves"] if c["severity"] == "LOW"),
    }

    output = {
        "summary": summary,
        "results": results,
    }

    Path(output_file).write_text(json.dumps(output, indent=2))

    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Items scanned:       {summary['total_items']}")
    print(f"  Items with CVEs:     {summary['items_with_cves']}")
    print(f"  Total CVEs:          {summary['total_cves']}")
    print(f"  Critical:            {summary['critical']}")
    print(f"  High:                {summary['high']}")
    print(f"  Medium:              {summary['medium']}")
    print(f"  Low:                 {summary['low']}")
    print(f"\n  Results written to:  {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Map system inventory to CVEs via NVD API")
    parser.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"), help="NVD API key (or set NVD_API_KEY env var)")
    parser.add_argument("--output", default="cve_results.json", help="Output JSON file")
    parser.add_argument("--min-score", type=float, default=0.0, help="Minimum CVSS score to include (e.g. 7.0 for high+)")
    parser.add_argument("--include-hardware", action="store_true", help="Include PCI/USB hardware devices")
    parser.add_argument("--include-modules", action="store_true", help="Include kernel modules (lsmod)")
    parser.add_argument("--include-pip", action="store_true", default=True, help="Include pip packages")
    parser.add_argument("--dry-run", action="store_true", help="Collect inventory only, no CVE lookup")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of inventory items to process")
    parser.add_argument("--skip-cve-lookup", action="store_true", help="Write inventory JSON only")
    parser.add_argument("--sources", nargs="+", help="Filter by source (dpkg, rpm, pip, brew, lsmod, etc.)")

    args = parser.parse_args()

    run_pipeline(
        api_key=args.api_key,
        output_file=args.output,
        min_score=args.min_score,
        include_hardware=args.include_hardware,
        include_modules=args.include_modules,
        include_pip=args.include_pip,
        dry_run=args.dry_run,
        limit=args.limit,
        skip_cve_lookup=args.skip_cve_lookup,
        sources_filter=args.sources,
    )


if __name__ == "__main__":
    main()
