# CVE Pipeline

Maps your system software inventory to CVEs via the NVD API.

## Files

```
inventory.py      - System collector (packages, OS, kernel, hardware, drivers)
nvd_client.py     - NVD API client (CPE search + CVE lookup)
pipeline.py       - Main orchestrator
report_viewer.html - Browser-based report viewer (drag & drop JSON)
```

## Quick Start

```bash
# Basic scan (OS + dpkg/rpm packages + pip)
python pipeline.py

# Recommended: get a free NVD API key first (50x faster)
# https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY=your-key-here
python pipeline.py

# High severity only
python pipeline.py --min-score 7.0

# See your inventory without doing CVE lookups (fast)
python pipeline.py --dry-run

# Include kernel modules and hardware devices
python pipeline.py --include-hardware --include-modules

# Only scan pip packages
python pipeline.py --sources pip

# Scan first 20 packages (good for testing)
python pipeline.py --limit 20 --min-score 4.0
```

## System Information Sources

### What each collector gathers

| Source | CLI Tool | What it finds |
|--------|----------|---------------|
| `os-release` | `/etc/os-release` | Distro name and version |
| `uname` | `platform.release()` | Kernel version |
| `dpkg` | `dpkg-query` | Debian/Ubuntu installed packages |
| `rpm` | `rpm -qa` | RHEL/Fedora/SUSE packages |
| `pip` | `pip list` | Python packages |
| `brew` | `brew list` | macOS Homebrew packages |
| `lsmod` | `lsmod` | Loaded kernel modules |
| `modinfo` | `modinfo <mod>` | Kernel module versions |
| `lspci` | `lspci -mm` | PCI devices (GPUs, NICs, etc.) |
| `lsusb` | `lsusb` | USB devices (modems, etc.) |
| `lscpu` | `lscpu` | CPU model and vendor |

### Other useful utilities you can add

```bash
# Firmware versions
dmidecode -t bios
dmidecode -t system

# Network interfaces and drivers
ethtool -i eth0        # driver name + version for a NIC
ip link show

# Block devices and their drivers
lsblk -o NAME,TYPE,ROTA,MODEL
udevadm info /dev/sda

# SCSI/storage
lsscsi

# Installed firmware packages (Debian)
dpkg -l | grep firmware

# Sierra Wireless / modem info
mmcli -m 0             # ModemManager
qmicli -d /dev/cdc-wdm0 --dms-get-revision

# OpenWRT package list
opkg list-installed

# Snap packages
snap list

# Flatpak
flatpak list --columns=application,version

# Node.js packages (global)
npm list -g --depth=0 --json

# Ruby gems
gem list --local

# Java (jar manifest scraping)
find / -name "*.jar" -exec unzip -p {} META-INF/MANIFEST.MF \; 2>/dev/null
```

## How CPE Matching Works

1. **Inventory collection** — gather product name + version from system tools
2. **Normalization** — map common package names to NVD vendor/product names
   (e.g., `openssl` → `cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*`)
3. **CPE search** — query NVD CPE API with `cpeMatchString` (prefix match)
4. **Fallback** — if no CPE found, try keyword search
5. **CVE lookup** — for the best matched CPE, fetch associated CVEs

## Tips

- **False positives** are common — many package names don't map cleanly to NVD vendor names
- **False negatives** happen too — some vulnerable packages have unusual CPE names
- The `KNOWN_MAPPINGS` dict in `pipeline.py` is where you tune vendor name normalization
- Running `--dry-run` first lets you see which CPE strings will be guessed before burning API quota
- Without an API key, a full system scan can take 20-30 minutes due to rate limiting

## Output Format

```json
{
  "summary": {
    "total_items": 150,
    "items_with_cves": 12,
    "total_cves": 47,
    "critical": 2,
    "high": 8,
    "medium": 28,
    "low": 9
  },
  "results": [
    {
      "item": {
        "vendor": "openssl",
        "product": "openssl",
        "version": "3.0.2",
        "part": "a",
        "source": "dpkg",
        "cpe_guess": "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"
      },
      "matched_cpes": [
        {
          "cpe_name": "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*",
          "title": "OpenSSL 3.0.2"
        }
      ],
      "cves": [
        {
          "cve_id": "CVE-2022-0778",
          "description": "...",
          "severity": "HIGH",
          "cvss_score": 7.5,
          "published": "2022-03-15T17:15:00.000",
          "references": ["https://..."]
        }
      ]
    }
  ]
}
```

Open `report_viewer.html` in a browser and drag your `cve_results.json` onto it to explore results.
