# LIZT

A reachability-aware vulnerability analysis tool for Linux systems. LIZT collects a software
inventory, maps it to CPE entries, queries the NVD API for CVEs, extracts vulnerable function
symbols from CVE data, and monitors process runtime behavior via eBPF to determine which
vulnerabilities are actually reachable.

## How It Works

```
System inventory → CPE matching → CVE lookup → Symbol extraction → eBPF runtime monitoring
```

1. **Inventory** — collects installed packages and OS info from dpkg, pip, Ubuntu OS release
   data, and the Linux kernel version
2. **CPE matching** — normalizes package names to CPE 2.3 format and validates them against
   the NVD CPE dictionary
3. **CVE lookup** — queries the NVD CVE API using confirmed CPE names to find applicable
   vulnerabilities
4. **Symbol extraction** — parses CVE descriptions, GitHub commit diffs, GitHub issue/PR
   bodies, and OSV database patch commits to identify vulnerable function symbols
5. **Ranking** — scores findings using CVSS score, KEV listing status, and runtime call
   confirmation
6. **eBPF runtime monitoring** — attaches kernel and userspace probes to vulnerable symbols
   identified in step 4, recording which processes actually call them at runtime

## Repository Structure

```
lizt/
  Cargo.toml              # Scanner workspace
  scanner/                # Scanner-only crates
    lizt_cli/             # CLI binary (scan, inventory, symbols, rank, reset, configure)
    lizt_inventory/       # System inventory collection
    lizt_rest/            # NVD, GitHub, and OSV HTTP client
    lizt_symbols/         # Vulnerable symbol extraction
  common/                 # Shared crates (used by both scanner and monitor)
    lizt_core/            # Domain models (Symbol, Cve, CpeEntry, FindingRecord, etc.)
    lizt_db/              # PostgreSQL database layer
  monitor/                # Monitor workspace (Linux only)
    Cargo.toml
    crates/
      lizt_ebpf/          # Userspace eBPF loader and observer (daemon binary)
      lizt_ebpf_programs/ # Kernel-side BPF programs (compiled to bpfel-unknown-none)
```

The scanner and monitor are separate Cargo workspaces. The scanner builds on macOS and Linux;
the monitor is Linux-only due to its use of Linux kernel interfaces.

## Prerequisites

### Scanner

- Rust toolchain (edition 2024, stable)
- PostgreSQL

### Monitor (additional requirements)

- Linux kernel 5.8+ (required for BPF ring buffers)
- Nightly Rust toolchain (`rustup toolchain install nightly`)
- `rust-src` component (`rustup component add rust-src --toolchain nightly`)
- `bpf-linker` (`cargo install bpf-linker`)
- Root or `CAP_BPF + CAP_PERFMON` capabilities at runtime

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

### 2. Build the scanner

```bash
cargo build --release
```

### 3. Build the monitor (Linux only)

```bash
cd monitor
cargo build --release -p lizt_ebpf
```

The build compiles the BPF kernel programs (targeting `bpfel-unknown-none`) and embeds the
resulting bytecode directly into the `lizt_ebpf` binary. No separate BPF object file is
deployed.

### 4. Run the scanner

```bash
cargo run -p lizt_cli -- scan
```

The database schema is applied automatically on first connection.

### 5. Run the monitor (Linux only, requires prior scan)

```bash
sudo -E ./monitor/target/release/lizt_ebpf
```

`-E` preserves environment variables (`DATABASE_URL` etc.). Alternatively, grant the binary
specific capabilities instead of running as root:

```bash
sudo setcap cap_bpf,cap_perfmon+eip ./monitor/target/release/lizt_ebpf
./monitor/target/release/lizt_ebpf
```

## CLI Subcommands (Scanner)

| Subcommand              | Description                                                       |
|-------------------------|-------------------------------------------------------------------|
| `scan`                  | Run the full pipeline: inventory → CPE → CVE → symbol extraction |
| `inventory`             | Collect and display the current system software inventory         |
| `symbols --cve-id <ID>` | Extract vulnerable symbols for a specific CVE                     |
| `rank`                  | Generate or update vulnerability rankings                         |
| `reset --confirm`       | Drop and recreate the database, then re-run migrations            |
| `configure`             | Update tool configuration                                         |

## eBPF Monitor

The monitor is a long-running daemon that reads vulnerable symbols from the database and
attaches eBPF probes to observe whether they are called at runtime.

### Architecture

The monitor is split into two crates:

- **`lizt_ebpf_programs`** — the kernel-side BPF programs, written in Rust using
  [aya-ebpf](https://aya-rs.dev) and compiled to the `bpfel-unknown-none` target. Contains a
  single probe handler (`try_probe`) shared by both kprobe and uprobe program types.

- **`lizt_ebpf`** — the userspace daemon, also written in Rust using
  [aya](https://aya-rs.dev). Reads symbols from the database, loads and attaches probes, and
  consumes events from the kernel via a ring buffer.

### Probe loading

For each vulnerable symbol in the database, the monitor:

1. Determines the probe type by checking `/proc/kallsyms` — if the symbol name appears there
   it is a kernel symbol and gets a **kprobe**; otherwise it gets a **uprobe** targeting the
   relevant userspace binary.
2. Loads a fresh instance of the BPF program object, stamping the symbol's database ID
   (`cve_symbol_id`) into a global variable (`CVE_SYMBOL_ID`) before the program is loaded
   into the kernel. This is necessary because a single BPF program attached to multiple
   functions cannot determine which function triggered it — using a separate program instance
   per symbol avoids this ambiguity.
3. Attaches the program to the symbol via `KProbe::attach` or `UProbe::attach`.
4. Extracts the ring buffer map (`EVENTS`) from the loaded program instance.

### Event collection

Each loaded BPF program instance has its own 256 KiB ring buffer. When a monitored symbol is
called, the kernel-side probe writes an event containing:

- `pid` — process ID of the calling process
- `tgid` — thread group ID
- `comm` — process name (up to 16 bytes, null-terminated)
- `cve_symbol_id` — the database ID of the symbol, copied from the `CVE_SYMBOL_ID` global

The userspace daemon spawns one async Tokio task per probe. Each task wraps the ring buffer's
file descriptor in a `tokio::io::unix::AsyncFd` to receive kernel readiness notifications
without busy-polling. When the kernel signals that events are available, the task drains the
ring buffer and inserts each event into the `symbol_observations` table:

```sql
INSERT INTO symbol_observations (cve_symbol_id, pid, process_name)
VALUES ($1, $2, $3)
```

### Ranking integration

The `symbol_called` field in the `findings` table and the `compute_rank_score` SQL function
use observation data to boost the rank score of vulnerabilities whose symbols have actually
been called at runtime, prioritizing actionable findings.

## Symbol Extraction

Symbols are extracted from four sources, each assigned a confidence level:

| Source             | Method                                                                          | Confidence    |
|--------------------|---------------------------------------------------------------------------------|---------------|
| CVE description    | Function definitions (`foo()`), keyword phrases ("vulnerable function `foo`")   | Medium / Low  |
| GitHub commit diff | Changed function signatures (C, Python, Java), function calls in modified lines | High / Medium |
| GitHub issue / PR  | Description and title text, same regex patterns as CVE description              | Medium / Low  |
| OSV database       | Patch commits from structured fix events; OSV details text                      | High / Medium |

NVD reference tags are used to prioritise `Patch`-tagged refs during scraping and skip
refs tagged only with `Press/Media Coverage` or `Exploit`, reducing wasted rate limit budget.

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
- Symbol detection accuracy depends on CVE data quality — not all vulnerable symbols are
  explicitly mentioned in CVE records
- GitHub scraping only works on public repositories
- Symbol pattern matching targets C/C++, Python, and Java; other languages may produce false
  positives or misses
- Uprobe attachment requires knowing the binary path; symbols not found in `/proc/kallsyms`
  currently fall back to a default path (`/usr/bin/unknown`)
- The monitor requires Linux kernel 5.8+ for BPF ring buffer support

## License

MIT License

## Disclaimer

This tool is intended for security research and defensive use. Always verify findings before
acting on them.
