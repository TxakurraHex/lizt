Gen# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LIZT is a security tool for vulnerability detection. It collects a system software inventory (OS, packages, Python
libraries), maps software to CPE (Common Platform Enumeration) entries, queries the NVD API for CVEs, extracts
vulnerable symbols from CVE data, and (planned) uses eBPF to monitor runtime behavior against known vulnerable symbols.

## Build Commands

```bash
cargo build                    # Build all scanner
cargo build --release          # Release build
cargo run -p lizt_cli          # Run the CLI
cargo test                     # Run all tests
cargo test -p lizt_core        # Run tests for a specific crate
cargo check                    # Check compilation without building
cargo fmt                      # Format code
cargo clippy                   # Lint
```

## Rust Crates Architecture

All crates use Rust edition 2024 with resolver = "2".

- **lizt-core**: Shared domain models. All other crates depend on this for common types.
    - `cve`: `Cve`, `CvssInfo`, `CpeMatch`
    - `inventory_item`: `InventoryItem`, `CpeEntry`, `CpePart`, `InventorySource`, `Confidence`
    - `github_issue`: `GitHubIssue`
    - `symbol`: `Symbol`, `SymbolType`

- **lizt-inventory**: System inventory collection. Implements sources for dpkg, pip, Ubuntu OS info, and Linux kernel.
    - `inventory`: `Source` trait and `Inventory` struct that aggregates sources
    - `runner`: `run(cmd)` shell command helper used by all sources
    - `sources/`: `dpkg_inv_source`, `pip_inv_source`, `ubuntu_inv_source`, `linux_kernel_inv_source`

- **lizt-rest**: NVD and GitHub HTTP client with rate limiting.
    - `rest`: `LiztRestClient` — methods for CPE lookup, CVE lookup (by CPE name or CVE ID), GitHub commit diffs, and
      GitHub issues
    - `rate_limiter`: `RateLimiter` enforcing NVD API rate limits (with/without API key)
    - `nvd/`: Serde response types for NVD CPE, CVE, and GitHub API responses

- **lizt-symbols**: Extracts vulnerable function symbols from CVE data.
    - `symbol_extractor`: `CveSymbolExtractor` and `Scraper` trait
    - `scrapers/`: `DescriptionScraper` (regex over CVE description text), `GithubScraper` (commit diffs and issue
      bodies)

- **lizt-db**: PostgreSQL database layer using `sqlx`.
    - `lib`: `connect()` and `reset()` — connect, run migrations, or drop/recreate the database
    - `rows/`: Row types mapping domain models to DB columns (`cve_rows`, `inventory_item_rows`, `symbol_rows`)
    - `findings`, `packages`, `scans`, `symbols`: stub modules — not yet implemented

- **lizt-cli**: Binary entry point. Subcommands: `scan`, `reset`, `inventory`, `symbols`, `rank`, `configure`.

## Key Patterns

- **Source trait** (`lizt-inventory/src/inventory.rs`): Inventory sources implement `Source` with `name() -> &str` and
  `collect() -> Vec<InventoryItem>` methods.
- **Runner utility** (`lizt-inventory/src/runner.rs`): `run(cmd)` executes shell commands via `sh -c` and returns stdout
  as `Option<String>`.
- **Scraper trait** (`lizt-symbols/src/symbol_extractor.rs`): Symbol scrapers implement `Scraper` with `name() -> &str`
  and `scrape(cve: &Cve) -> Vec<Symbol>` methods.
- **Tests are inline**: Use `#[cfg(test)]` modules colocated with source files.

## Database

PostgreSQL schema managed by `sqlx` migrations in `migrations/`:

- `000_initial_schema.sql` — core tables: `scans`, `inventory`, `inventory_events`, `cves`, `cve_events`, `cve_cpes`,
  `cpe_matches`, `cve_symbols`, `symbol_observations`, `findings`, `kev`, `sync_state`
- `002_symbol_activity_view.sql` — `symbol_activity` materialized view over `symbol_observations`
- `003_compute_rank_score.sql` — `compute_rank_score(cvss, kev, called)` SQL function

Migrations are run automatically on `connect()` in `lizt-db`.

## Environment Variables

| Variable        | Required         | Description                                                        |
|-----------------|------------------|--------------------------------------------------------------------|
| `DATABASE_URL`  | Yes              | PostgreSQL connection string for the app database                  |
| `ADMINDB_URL`   | For `reset` only | Admin connection used to drop/recreate the database                |
| `DATABASE_NAME` | For `reset` only | Name of the database to drop and recreate                          |
| `API_KEY`       | No               | NVD API key — enables higher rate limits (50 req/30s vs 5 req/30s) |
