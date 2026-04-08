<p align="center">
  <img src="icons/lizt-lockup-transparent.svg" alt="lizt" width="320">
</p>

A reachability-aware vulnerability analysis tool for Linux systems. LIZT collects a software
inventory, maps it to CPE entries, queries the NVD API for CVEs, extracts vulnerable function
symbols from CVE data, and monitors process runtime behavior via eBPF to determine which
vulnerabilities are actually reachable.

### Why "lizt"?

*Liztor* is the Basque word for "wasp"; a tip of the hat to Georgia Tech's Yellow Jacket.
It also sounds a lot like "list", which is what this tool does: lists your vulnerabilities,
stings the ones that matter, and ignores the rest.

## How It Works

```
System inventory → CPE matching → CVE lookup → Symbol extraction → Symbol validation → eBPF runtime monitoring
```

1. **Inventory** — collects installed packages and OS info from dpkg, pip, Ubuntu OS release
   data, and the Linux kernel version
2. **CPE matching** — normalizes package names to CPE 2.3 format and validates them against
   the NVD CPE dictionary
3. **CVE lookup** — queries the NVD CVE API using confirmed CPE names to find applicable
   vulnerabilities
4. **Symbol extraction** — parses CVE descriptions, GitHub commit diffs, GitHub issue/PR
   bodies, and OSV database patch commits to identify vulnerable function symbols
5. **Symbol validation** — resolves extracted symbols against the live system: checks
   `/proc/kallsyms` for kernel symbols (kprobe candidates) and scans installed library files
   via dpkg, pip, and static paths for userspace symbols (uprobe candidates). Only symbols
   confirmed present on the system are marked `validated=TRUE` and persisted with their
   `binary_path` and `probe_type`.
6. **Ranking** — scores findings using CVSS score, KEV listing status, and runtime call
   confirmation
7. **eBPF runtime monitoring** — attaches kernel and userspace probes to validated symbols,
   recording which processes actually call them at runtime

## Repository Structure

```
lizt/
  Cargo.toml              # Workspace root
  .cargo/config.toml      # Defines `cargo xtask` alias
  xtask/                  # Install/uninstall tasks for all binaries
  scanner/
    cli/                  # CLI binary: lizt-cli (scan, inventory, symbols, rank, reset, configure)
    web/                  # Web dashboard + eBPF monitor binary: lizt (Axum, port 8080)
  io/
    inventory/            # System inventory collection
    nvd/                  # NVD, GitHub, and OSV HTTP client
    symbols/              # Vulnerable symbol extraction
  pipeline/               # Scan pipeline orchestration (inventory → CPE → CVE → symbols → validate → persist)
  core/                   # Shared crates
    common/               # Domain models (Symbol, Cve, CpeEntry, FindingRecord, ResolvedSymbol, etc.)
    db/                   # PostgreSQL database layer
  conf/                   # Shared config templates (log4rs, env)
  monitor/                # eBPF monitor library (loader + observer)
    ebpf_programs/        # Kernel-side BPF programs (compiled to bpfel-unknown-none)
```

The monitor is built into the `lizt` web binary and runs as a background task alongside the
web server. A single systemd service handles both. Linux kernel 5.8+ is required for BPF
ring buffer support.

## Prerequisites

### Scanner

- Rust toolchain (edition 2024, stable)
- PostgreSQL

### eBPF monitor (additional requirements)

- Linux kernel 5.8+ (required for BPF ring buffers)
- Nightly Rust toolchain (`rustup toolchain install nightly`)
- `rust-src` component (`rustup component add rust-src --toolchain nightly`)
- `CAP_BPF + CAP_PERFMON + CAP_SYS_RESOURCE` capabilities at runtime (or root)

## Setup

### 1. Configure environment variables

```bash
export DATABASE_URL="postgres://user:password@localhost/lizt"
export NVD_API_KEY="your-nvd-api-key"       # Optional — enables 50 req/30s vs 5 req/30s
```

For the `reset` subcommand only:

```bash
export ADMINDB_URL="postgres://admin:password@localhost/postgres"
export DATABASE_NAME="lizt"
```

### 2. Build

```bash
cargo build --release           # builds lizt, lizt-cli, and xtask
```

The build compiles the BPF kernel programs (targeting `bpfel-unknown-none`) via a `build.rs`
script and embeds the resulting bytecode directly into the `lizt` binary. No separate BPF
object file is deployed.

### 3. Run the scanner

```bash
cargo run -p cli -- scan
```

The database schema is applied automatically on first connection. Running `cargo run -p cli`
without a subcommand opens an interactive TUI menu where you can select and run any command
without remembering subcommand names.

### 5. Install (optional — for running as system services)

The `xtask` binary installs binaries, config files, and systemd units. Build first with
`cargo build --release`, then run with `sudo -E` to preserve environment variables:

```bash
sudo -E ./target/release/xtask install    # /usr/bin/lizt + /usr/bin/lizt-cli + nginx + systemd
```

To uninstall:

```bash
sudo -E ./target/release/xtask uninstall
```

Each install creates `/etc/lizt/env` from the template if it does not already exist — edit it
to set `DATABASE_URL` and `NVD_API_KEY` before starting any service. Credentials are loaded
via `EnvironmentFile=/etc/lizt/env` and never appear in the unit file or source tree.

The systemd service grants `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_RESOURCE` via ambient
capabilities so the eBPF monitor can attach probes without running as root.

### 6. Run ad-hoc (requires prior scan for eBPF probes)

```bash
sudo -E ./target/release/lizt
```

`-E` preserves environment variables (`DATABASE_URL` etc.). Alternatively, grant the binary
specific capabilities instead of running as root:

```bash
sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+eip ./target/release/lizt
./target/release/lizt
```

## CLI Subcommands (Scanner)

Running `lizt-cli` without a subcommand opens an interactive TUI menu (powered by
[inquire](https://github.com/mikaelmello/inquire)) that loops through a Select prompt until
you choose Quit. Each menu entry maps directly to one of the subcommands below.

| Subcommand              | Description                                                       |
|-------------------------|-------------------------------------------------------------------|
| `scan`                  | Run the full pipeline: inventory → CPE → CVE → symbol extraction |
| `inventory`             | Collect and display the current system software inventory         |
| `symbols --cve-id <ID>` | Extract vulnerable symbols for a specific CVE                     |
| `rank`                  | Generate or update vulnerability rankings                         |
| `reset --confirm`       | Drop and recreate the database, then re-run migrations            |
| `configure`             | Interactively set NVD_API_KEY and GITHUB_TOKEN; saves to `~/.lizt_config` |

### Configuration file

`configure` and the TUI menu persist API keys to `~/.lizt_config` in `KEY=VALUE` format. This
file is loaded at startup so credentials survive across shell sessions without requiring
`.bashrc`/`.zshrc` exports.

## eBPF Monitor

The eBPF monitor runs as a background task inside the `lizt` web binary. It reads vulnerable
symbols from the database, attaches eBPF probes, and observes whether they are called at
runtime. Probes are automatically reloaded whenever a scan completes.

### Architecture

The monitor is split into two crates:

- **`ebpf_programs`** (`monitor/ebpf_programs/`) — the kernel-side BPF programs, written in
  Rust using [aya-ebpf](https://aya-rs.dev) and compiled to the `bpfel-unknown-none` target.
  Contains a single probe handler (`try_probe`) shared by both kprobe and uprobe program types.

- **`monitor`** (`monitor/`) — the userspace library, written in Rust using
  [aya](https://aya-rs.dev). Reads symbols from the database, loads and attaches probes, and
  consumes events from the kernel via a ring buffer. Spawned as a background Tokio task by
  the web binary.

### Probe loading

The monitor only loads symbols that have been validated by the scanner pipeline
(`validated = TRUE` in the database). Each such symbol already carries a resolved
`probe_type` (`kprobe` or `uprobe`) and, for uprobe symbols, the `binary_path` of the
library that exports it — both set during the scan's symbol validation stage.

For each validated symbol, the monitor:

1. Reads `probe_type` and `binary_path` directly from the database row — no runtime
   `/proc/kallsyms` lookup is needed.
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

The monitor spawns one async Tokio task per probe. Each task wraps the ring buffer's
file descriptor in a `tokio::io::unix::AsyncFd` to receive kernel readiness notifications
without busy-polling. When the kernel signals that events are available, the task drains the
ring buffer and upserts each event into the `symbol_observations` table, incrementing
`call_count` on repeat hits from the same process rather than inserting duplicate rows:

```sql
INSERT INTO symbol_observations (cve_symbol_id, pid, process_name)
VALUES ($1, $2, $3)
ON CONFLICT (cve_symbol_id, pid)
DO UPDATE SET
    call_count   = symbol_observations.call_count + 1,
    observed_at  = NOW(),
    process_name = EXCLUDED.process_name
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
- **With `NVD_API_KEY`**: 50 requests per 30 seconds
- **OSV**: 25 requests per 30 seconds (no key required)

All REST methods use bounded retry loops with a maximum of `MAX_RETRIES` attempts; failed
requests after exhaustion are logged and skipped rather than retrying indefinitely.

Get a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key.

## Limitations

- Inventory collection requires a Debian/Ubuntu system (dpkg source) or pip
- Symbol detection accuracy depends on CVE data quality — not all vulnerable symbols are
  explicitly mentioned in CVE records
- GitHub scraping only works on public repositories
- Symbol pattern matching targets C/C++, Python, and Java; other languages may produce false
  positives or misses
- Symbols not confirmed on the local system during the validation stage are skipped — the
  monitor only probes symbols with `validated = TRUE` in the database
- The monitor requires Linux kernel 5.8+ for BPF ring buffer support

## License

MIT License

## Disclaimer

This tool is intended for security research and defensive use. Always verify findings before
acting on them.
