#!/usr/bin/env python3
"""
System Inventory Collector
Gathers OS, kernel, packages, drivers, and hardware info
to build a software inventory for CVE mapping.
"""

import subprocess
import platform
import json
import re
import os
import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class InventoryItem:
    vendor: str
    product: str
    version: str
    part: str = "a"  # a=application, o=os, h=hardware
    source: str = ""
    cpe_guess: str = ""

    def to_cpe_string(self) -> str:
        v = self.vendor.lower().replace(" ", "_").replace("-", "_")
        p = self.product.lower().replace(" ", "_").replace("-", "_")
        ver = self.version.lower().replace(" ", "_")
        return f"cpe:2.3:{self.part}:{v}:{p}:{ver}:*:*:*:*:*:*:*"


def run(cmd: str, shell=True) -> str:
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# OS & Kernel
# ---------------------------------------------------------------------------

def collect_os_info() -> list[InventoryItem]:
    items = []

    # Platform basics
    system = platform.system()
    release = platform.release()
    version = platform.version()

    if system == "Linux":
        # Try /etc/os-release for distro info
        os_release = {}
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line:
                        k, v = line.split("=", 1)
                        os_release[k] = v.strip('"')
        except FileNotFoundError:
            pass

        distro_id = os_release.get("ID", "linux")
        distro_version = os_release.get("VERSION_ID", release)
        distro_name = os_release.get("NAME", "Linux")

        items.append(InventoryItem(
            vendor=distro_id,
            product=distro_id + "_linux",
            version=distro_version,
            part="o",
            source="os-release",
        ))

        # Kernel
        kernel_version = platform.release()
        items.append(InventoryItem(
            vendor="linux",
            product="linux_kernel",
            version=kernel_version.split("-")[0],  # strip distro suffix
            part="o",
            source="uname",
        ))

    elif system == "Darwin":
        mac_ver = platform.mac_ver()[0]
        items.append(InventoryItem(
            vendor="apple",
            product="macos",
            version=mac_ver,
            part="o",
            source="platform",
        ))

    elif system == "Windows":
        win_ver = platform.version()
        items.append(InventoryItem(
            vendor="microsoft",
            product="windows",
            version=win_ver,
            part="o",
            source="platform",
        ))

    return items


# ---------------------------------------------------------------------------
# Kernel Modules
# ---------------------------------------------------------------------------

def collect_kernel_modules() -> list[InventoryItem]:
    items = []
    if platform.system() != "Linux":
        return items

    lsmod = run("lsmod")
    if not lsmod:
        return items

    lines = lsmod.strip().split("\n")[1:]  # skip header
    for line in lines:
        parts = line.split()
        if parts:
            mod_name = parts[0]
            items.append(InventoryItem(
                vendor="linux",
                product=mod_name,
                version="kernel_module",
                part="a",
                source="lsmod",
            ))

    return items


# ---------------------------------------------------------------------------
# Installed Packages
# ---------------------------------------------------------------------------

def collect_dpkg_packages() -> list[InventoryItem]:
    items = []
    out = run("dpkg-query -W -f='${Package}\\t${Version}\\t${Maintainer}\\n' 2>/dev/null")
    if not out:
        return items

    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            pkg = parts[0].strip()
            ver = parts[1].strip()
            # Strip epoch and distro suffix from version
            ver = re.sub(r'^\d+:', '', ver)
            ver = re.split(r'[~+-]', ver)[0]
            items.append(InventoryItem(
                vendor="",  # will be inferred or left blank
                product=pkg,
                version=ver,
                part="a",
                source="dpkg",
            ))

    return items


def collect_rpm_packages() -> list[InventoryItem]:
    items = []
    out = run("rpm -qa --queryformat '%{NAME}\\t%{VERSION}\\t%{VENDOR}\\n' 2>/dev/null")
    if not out:
        return items

    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            pkg = parts[0].strip()
            ver = parts[1].strip()
            vendor = parts[2].strip() if len(parts) > 2 else ""
            items.append(InventoryItem(
                vendor=vendor.lower().split()[0] if vendor else "",
                product=pkg,
                version=ver,
                part="a",
                source="rpm",
            ))

    return items


def collect_pip_packages() -> list[InventoryItem]:
    items = []
    out = run(f"{sys.executable} -m pip list --format=json 2>/dev/null")
    if not out:
        return items

    try:
        pkgs = json.loads(out)
        for pkg in pkgs:
            items.append(InventoryItem(
                vendor="",
                product=pkg["name"].lower().replace("-", "_"),
                version=pkg["version"],
                part="a",
                source="pip",
            ))
    except json.JSONDecodeError:
        pass

    return items


def collect_brew_packages() -> list[InventoryItem]:
    items = []
    out = run("brew list --versions 2>/dev/null")
    if not out:
        return items

    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            items.append(InventoryItem(
                vendor="",
                product=parts[0],
                version=parts[-1],
                part="a",
                source="brew",
            ))

    return items


# ---------------------------------------------------------------------------
# Hardware / Drivers
# ---------------------------------------------------------------------------

def collect_pci_devices() -> list[InventoryItem]:
    items = []
    out = run("lspci -mm 2>/dev/null")
    if not out:
        return items

    for line in out.splitlines():
        # Format: slot "class" "vendor" "device" "subsys_vendor" "subsys_device"
        parts = re.findall(r'"([^"]*)"', line)
        if len(parts) >= 3:
            vendor = parts[1].strip()
            device = parts[2].strip()
            items.append(InventoryItem(
                vendor=vendor.lower().split()[0] if vendor else "unknown",
                product=device.lower().replace(" ", "_")[:40],
                version="-",
                part="h",
                source="lspci",
            ))

    return items


def collect_usb_devices() -> list[InventoryItem]:
    items = []
    out = run("lsusb 2>/dev/null")
    if not out:
        return items

    for line in out.splitlines():
        # Bus 001 Device 002: ID 8087:0024 Intel Corp. Integrated Rate Matching Hub
        m = re.search(r'ID \w+:\w+ (.+)', line)
        if m:
            desc = m.group(1).strip()
            parts = desc.split(None, 1)
            vendor = parts[0].lower() if parts else "unknown"
            product = parts[1].lower().replace(" ", "_")[:40] if len(parts) > 1 else "unknown"
            items.append(InventoryItem(
                vendor=vendor,
                product=product,
                version="-",
                part="h",
                source="lsusb",
            ))

    return items


def collect_cpu_info() -> list[InventoryItem]:
    items = []
    out = run("lscpu 2>/dev/null")
    if not out:
        return items

    vendor = ""
    model = ""
    for line in out.splitlines():
        if line.startswith("Vendor ID:"):
            vendor = line.split(":", 1)[1].strip().lower()
        elif line.startswith("Model name:"):
            model = line.split(":", 1)[1].strip()

    if model:
        # Try to extract a clean version
        ver_match = re.search(r'([\d\-\.]+GHz)', model)
        ver = ver_match.group(1) if ver_match else "-"
        product = re.sub(r'\s+', '_', model.split("@")[0].strip().lower())[:50]
        items.append(InventoryItem(
            vendor=vendor or "intel",
            product=product,
            version=ver,
            part="h",
            source="lscpu",
        ))

    return items


# ---------------------------------------------------------------------------
# Loaded drivers via modinfo
# ---------------------------------------------------------------------------

def collect_driver_versions() -> list[InventoryItem]:
    """For loaded kernel modules, try to get version via modinfo."""
    items = []
    if platform.system() != "Linux":
        return items

    lsmod_out = run("lsmod")
    if not lsmod_out:
        return items

    mods = [line.split()[0] for line in lsmod_out.splitlines()[1:] if line]
    # Only check a subset to avoid taking forever
    for mod in mods[:50]:
        info = run(f"modinfo {mod} 2>/dev/null")
        version = ""
        description = ""
        for line in info.splitlines():
            if line.startswith("version:"):
                version = line.split(":", 1)[1].strip()
            elif line.startswith("description:"):
                description = line.split(":", 1)[1].strip()
        if version:
            items.append(InventoryItem(
                vendor="linux",
                product=mod,
                version=version,
                part="a",
                source="modinfo",
            ))

    return items


# ---------------------------------------------------------------------------
# Main collector
# ---------------------------------------------------------------------------

def collect_inventory(
    include_packages=True,
    include_kernel_modules=False,
    include_hardware=False,
    include_pip=True,
    include_brew=True,
    include_driver_versions=False,
) -> list[InventoryItem]:
    inventory = []

    print("[*] Collecting OS and kernel info...")
    inventory += collect_os_info()

    if include_packages:
        print("[*] Collecting installed packages (dpkg)...")
        inventory += collect_dpkg_packages()
        print("[*] Collecting installed packages (rpm)...")
        inventory += collect_rpm_packages()

    if include_pip:
        print("[*] Collecting Python packages (pip)...")
        inventory += collect_pip_packages()

    if include_brew:
        print("[*] Collecting Homebrew packages...")
        inventory += collect_brew_packages()

    if include_kernel_modules:
        print("[*] Collecting kernel modules (lsmod)...")
        inventory += collect_kernel_modules()

    if include_hardware:
        print("[*] Collecting PCI devices (lspci)...")
        inventory += collect_pci_devices()
        print("[*] Collecting USB devices (lsusb)...")
        inventory += collect_usb_devices()
        print("[*] Collecting CPU info (lscpu)...")
        inventory += collect_cpu_info()

    if include_driver_versions:
        print("[*] Collecting driver versions (modinfo)... (this may take a moment)")
        inventory += collect_driver_versions()

    # Deduplicate by product+version
    seen = set()
    deduped = []
    for item in inventory:
        key = (item.product, item.version, item.source)
        if key not in seen:
            seen.add(key)
            item.cpe_guess = item.to_cpe_string()
            deduped.append(item)

    print(f"[+] Collected {len(deduped)} inventory items")
    return deduped


if __name__ == "__main__":
    inv = collect_inventory(include_kernel_modules=True, include_hardware=True)
    print(json.dumps([asdict(i) for i in inv], indent=2))
