# LIZT

A reachability-aware vulnerability analysis tool for Linux systems. LIZT collects a software inventory, maps it to CPE
entries, queries the NVD API for CVEs, extracts vulnerable function symbols from CVE data, and (planned) monitors
process runtime behavior via eBPF to determine which vulnerabilities are actually reachable.

## How It Works

```
System inventory  →  CPE matching  →  CVE lookup  →  Symbol extraction  →  (planned) eBPF runtime scan
```

1. **Inventory** — collects installed packages and OS info from dpkg, pip, Ubuntu OS release data, and the Linux kernel
   version
2. **CPE matching** — normalizes package names to CPE 2.3 format and validates them against the NVD CPE dictionary
3. **CVE lookup** — queries the NVD CVE API using confirmed CPE names to find applicable vulnerabilities
4. **Symbol extraction** — parses CVE descriptions, GitHub commit diffs, and GitHub issue/PR bodies to identify
   vulnerable function symbols
5. **Ranking** — scores findings using CVSS score, KEV listing status, and (planned) runtime call confirmation

## Prerequisites

- Rust toolchain (edition 2024 / rustup stable)
- PostgreSQL

## Setup

### 1. Configure environment variables

```bash
export DATABASE_URL="postgres://user:password@localhost/lizt"
export API_KEY="your-nvd-api-key"       # Optional — enables 50 req/30s vs 5 req/30s
```

For the `reset` subcommand only:

```bash
export ADMINDB_URL="postgres://admin:password@localhost/postgres"
export DATABASE_NAME="lizt"
```

### 2. Build

```bash
cargo build --release
```

### 3. Run

```bash
cargo run -p lizt_cli -- scan
```

The database schema is applied automatically on first connection.

## CLI Subcommands

| Subcommand              | Description                                                      |
|-------------------------|------------------------------------------------------------------|
| `scan`                  | Run the full pipeline: inventory → CPE → CVE → symbol extraction |
| `inventory`             | Collect and display the current system software inventory        |
| `symbols --cve-id <ID>` | Extract vulnerable symbols for a specific CVE                    |
| `rank`                  | Generate or update vulnerability rankings                        |
| `reset --confirm`       | Drop and recreate the database, then re-run migrations           |
| `configure`             | Update tool configuration                                        |

## Symbol Extraction

Symbols are extracted from three sources, each assigned a confidence level:

| Source             | Method                                                                          | Confidence    |
|--------------------|---------------------------------------------------------------------------------|---------------|
| CVE description    | Function definitions (`foo()`), keyword phrases ("vulnerable function `foo`")   | Medium / Low  |
| GitHub commit diff | Changed function signatures (C, Python, Java), function calls in modified lines | High / Medium |
| GitHub issue / PR  | Description and title text, same regex patterns as CVE description              | Medium / Low  |

## Inventory Sources

| Source         | Data collected                                  |
|----------------|-------------------------------------------------|
| `dpkg`         | Debian/Ubuntu installed packages (`dpkg-query`) |
| `pip`          | Python packages (`pip list`)                    |
| `ubuntu`       | OS name and version (`/etc/os-release`)         |
| `linux_kernel` | Kernel version (`uname -r`)                     |

## NVD API Rate Limits

Requests are automatically throttled to stay within NVD limits:

- **Without API key**: 5 requests per 30 seconds
- **With `API_KEY`**: 50 requests per 30 seconds

Get a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key.

## Limitations

- Inventory collection requires a Debian/Ubuntu system (dpkg source) or pip
- Symbol detection accuracy depends on CVE data quality — not all vulnerable symbols are explicitly mentioned
- GitHub scraping only works on public repositories
- Symbol pattern matching targets C/C++, Python, and Java; other languages may produce false positives or misses

## License

MIT License

## Disclaimer

This tool is intended for security research and defensive use. Always verify findings before acting on them.
